// Package store keeps the authenticated-IP records for the auth-server.
//
// Records are held in memory and persisted to a single JSON file (no database).
// Every record carries a TTL; expired records are purged and never exported.
package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/misaka-cpu/nft-auth-whitelist/internal/atomicfile"
	"github.com/misaka-cpu/nft-auth-whitelist/internal/signer"
)

// Store is a concurrency-safe TTL set of entries keyed by CIDR.
type Store struct {
	mu         sync.Mutex
	path       string
	maxEntries int
	entries    map[string]*signer.Entry
}

type persisted struct {
	Entries []signer.Entry `json:"entries"`
}

// New creates a store backed by <dataDir>/entries.json, loading any existing
// state.
func New(dataDir string, maxEntries int) (*Store, error) {
	if maxEntries <= 0 {
		maxEntries = 200
	}
	s := &Store{
		path:       filepath.Join(dataDir, "entries.json"),
		maxEntries: maxEntries,
		entries:    make(map[string]*signer.Entry),
	}
	if dataDir != "" {
		if err := os.MkdirAll(dataDir, 0o700); err != nil {
			return nil, err
		}
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) load() error {
	b, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var p persisted
	if err := json.Unmarshal(b, &p); err != nil {
		return err
	}
	for i := range p.Entries {
		e := p.Entries[i]
		s.entries[e.CIDR] = &e
	}
	return nil
}

// RecordResult reports what Record did.
type RecordResult struct {
	Entry   signer.Entry
	IsNew   bool
	Evicted []string // CIDRs removed due to max_entries pressure
}

// Record adds or refreshes the entry for cidr/ip. On refresh it bumps
// LastSeenAt, HitCount and ExpiresAt. It then enforces max_entries (expired
// first, then least-recently-seen) and persists, so a refreshed expires_at
// survives a restart.
func (s *Store) Record(cidr, ip, source string, now time.Time, ttl time.Duration) (RecordResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now = now.UTC().Truncate(time.Second)
	exp := now.Add(ttl).Truncate(time.Second)

	var res RecordResult
	if e, ok := s.entries[cidr]; ok {
		e.LastSeenAt = now
		e.ExpiresAt = exp
		e.HitCount++
		res.Entry = *e
		res.IsNew = false
	} else {
		e := &signer.Entry{
			IP:         ip,
			CIDR:       cidr,
			Source:     source,
			CreatedAt:  now,
			ExpiresAt:  exp,
			LastSeenAt: now,
			HitCount:   1,
		}
		s.entries[cidr] = e
		res.Entry = *e
		res.IsNew = true
	}

	res.Evicted = s.enforceLimitLocked(now)
	if err := s.persistLocked(); err != nil {
		return res, err
	}
	return res, nil
}

func (s *Store) enforceLimitLocked(now time.Time) []string {
	var evicted []string
	// First drop expired entries.
	for k, e := range s.entries {
		if !e.ExpiresAt.After(now) {
			delete(s.entries, k)
			evicted = append(evicted, k)
		}
	}
	// Then, if still over the limit, drop least-recently-seen.
	if len(s.entries) <= s.maxEntries {
		return evicted
	}
	type kv struct {
		key  string
		seen time.Time
	}
	list := make([]kv, 0, len(s.entries))
	for k, e := range s.entries {
		list = append(list, kv{k, e.LastSeenAt})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].seen.Before(list[j].seen) })
	for i := 0; len(s.entries) > s.maxEntries && i < len(list); i++ {
		delete(s.entries, list[i].key)
		evicted = append(evicted, list[i].key)
	}
	return evicted
}

// Purge removes expired entries and returns their CIDRs. It persists if anything
// changed.
func (s *Store) Purge(now time.Time) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	now = now.UTC()
	var removed []string
	for k, e := range s.entries {
		if !e.ExpiresAt.After(now) {
			delete(s.entries, k)
			removed = append(removed, k)
		}
	}
	if len(removed) > 0 {
		_ = s.persistLocked()
	}
	return removed
}

// Snapshot returns the non-expired entries sorted by CIDR (stable ordering for
// signing).
func (s *Store) Snapshot(now time.Time) []signer.Entry {
	s.mu.Lock()
	defer s.mu.Unlock()
	now = now.UTC()
	out := make([]signer.Entry, 0, len(s.entries))
	for _, e := range s.entries {
		if e.ExpiresAt.After(now) {
			out = append(out, *e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CIDR < out[j].CIDR })
	return out
}

// Count returns the number of stored entries (including not-yet-purged expired).
func (s *Store) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}

// BuildEnvelope produces a signed envelope of the current non-expired entries.
// envelopeTTL is how long the signed document is considered fresh.
func (s *Store) BuildEnvelope(now time.Time, envelopeTTL time.Duration, secret []byte) (*signer.Envelope, error) {
	now = now.UTC().Truncate(time.Second)
	env := &signer.Envelope{
		Version:   1,
		IssuedAt:  now,
		ExpiresAt: now.Add(envelopeTTL).Truncate(time.Second),
		Entries:   s.Snapshot(now),
	}
	if err := signer.Sign(env, secret); err != nil {
		return nil, err
	}
	return env, nil
}

func (s *Store) persistLocked() error {
	if s.path == "" {
		return nil
	}
	list := make([]signer.Entry, 0, len(s.entries))
	for _, e := range s.entries {
		list = append(list, *e)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].CIDR < list[j].CIDR })
	b, err := json.MarshalIndent(persisted{Entries: list}, "", "  ")
	if err != nil {
		return err
	}
	return atomicfile.Write(s.path, b, 0o600)
}
