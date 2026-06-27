package store

import (
	"testing"
	"time"
)

func TestRecordAddAndRefresh(t *testing.T) {
	s, err := New(t.TempDir(), 10)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	res, err := s.Record("1.2.3.4/32", "1.2.3.4", "web_auth", now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsNew || res.Entry.HitCount != 1 {
		t.Fatalf("first record should be new with hit_count 1, got %+v", res)
	}

	later := now.Add(time.Minute)
	res2, err := s.Record("1.2.3.4/32", "1.2.3.4", "web_auth", later, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if res2.IsNew || res2.Entry.HitCount != 2 {
		t.Fatalf("second record should refresh with hit_count 2, got %+v", res2)
	}
	if !res2.Entry.ExpiresAt.After(res.Entry.ExpiresAt) {
		t.Fatal("refresh should extend expires_at")
	}
}

func TestTTLExpiryPurge(t *testing.T) {
	s, err := New(t.TempDir(), 10)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if _, err := s.Record("1.2.3.4/32", "1.2.3.4", "web_auth", now, time.Second); err != nil {
		t.Fatal(err)
	}
	// Snapshot before expiry.
	if got := s.Snapshot(now); len(got) != 1 {
		t.Fatalf("want 1 entry before expiry, got %d", len(got))
	}
	// After expiry, snapshot excludes it.
	future := now.Add(2 * time.Second)
	if got := s.Snapshot(future); len(got) != 0 {
		t.Fatalf("expired entry must not appear in snapshot, got %d", len(got))
	}
	removed := s.Purge(future)
	if len(removed) != 1 {
		t.Fatalf("purge should remove 1 expired entry, got %d", len(removed))
	}
	if s.Count() != 0 {
		t.Fatalf("store should be empty after purge, got %d", s.Count())
	}
}

func TestMaxEntriesEviction(t *testing.T) {
	s, err := New(t.TempDir(), 2)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Now()
	// Three distinct, non-expired entries; oldest-seen should be evicted.
	s.Record("1.1.1.1/32", "1.1.1.1", "web_auth", base, time.Hour)
	s.Record("2.2.2.2/32", "2.2.2.2", "web_auth", base.Add(time.Minute), time.Hour)
	s.Record("3.3.3.3/32", "3.3.3.3", "web_auth", base.Add(2*time.Minute), time.Hour)

	if s.Count() != 2 {
		t.Fatalf("max_entries=2 must cap stored entries, got %d", s.Count())
	}
	snap := s.Snapshot(base.Add(3 * time.Minute))
	for _, e := range snap {
		if e.CIDR == "1.1.1.1/32" {
			t.Fatal("least-recently-seen entry should have been evicted")
		}
	}
}

func TestExpiredEvictedBeforeLRU(t *testing.T) {
	s, err := New(t.TempDir(), 2)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Now()
	s.Record("1.1.1.1/32", "1.1.1.1", "web_auth", base, time.Second) // will expire
	s.Record("2.2.2.2/32", "2.2.2.2", "web_auth", base, time.Hour)
	// Add a third after the first expires; expired one is removed, no LRU needed.
	s.Record("3.3.3.3/32", "3.3.3.3", "web_auth", base.Add(2*time.Second), time.Hour)
	if s.Count() != 2 {
		t.Fatalf("want 2 after expiring one, got %d", s.Count())
	}
}

func TestBuildEnvelopeSignedAndSorted(t *testing.T) {
	s, err := New(t.TempDir(), 10)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	s.Record("9.9.9.9/32", "9.9.9.9", "web_auth", now, time.Hour)
	s.Record("1.1.1.1/32", "1.1.1.1", "web_auth", now, time.Hour)
	env, err := s.BuildEnvelope(now, 5*time.Minute, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if env.Version != 1 || env.Signature == "" {
		t.Fatal("envelope missing version/signature")
	}
	if len(env.Entries) != 2 || env.Entries[0].CIDR != "1.1.1.1/32" {
		t.Fatalf("entries must be sorted by cidr, got %+v", env.Entries)
	}
}

func TestPersistReload(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir, 10)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	s.Record("1.2.3.4/32", "1.2.3.4", "web_auth", now, time.Hour)

	s2, err := New(dir, 10)
	if err != nil {
		t.Fatal(err)
	}
	if s2.Count() != 1 {
		t.Fatalf("reloaded store should have 1 entry, got %d", s2.Count())
	}
}

func TestRecordRefreshPersistsExpiresAt(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir, 10)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 6, 25, 12, 0, 0, 0, time.UTC)
	if _, err := s.Record("1.2.3.4/32", "1.2.3.4", "web_auth", now, time.Hour); err != nil {
		t.Fatal(err)
	}

	// Re-auth before expiry: the refresh must extend AND persist expires_at.
	later := now.Add(30 * time.Minute)
	res, err := s.Record("1.2.3.4/32", "1.2.3.4", "web_auth", later, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	// A restart (reload from disk) must keep the refreshed expires_at, not the
	// original one.
	reloaded, err := New(dir, 10)
	if err != nil {
		t.Fatal(err)
	}
	snap := reloaded.Snapshot(later)
	if len(snap) != 1 {
		t.Fatalf("want 1 entry after reload, got %d", len(snap))
	}
	if !snap[0].ExpiresAt.Equal(res.Entry.ExpiresAt) {
		t.Fatalf("reloaded expires_at = %s, want refreshed %s", snap[0].ExpiresAt, res.Entry.ExpiresAt)
	}
	if snap[0].HitCount != 2 {
		t.Fatalf("reloaded hit_count = %d, want 2", snap[0].HitCount)
	}
}

func TestRecordRefreshPersistsExpiredEntryRevival(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir, 10)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 6, 25, 12, 0, 0, 0, time.UTC)
	if _, err := s.Record("1.2.3.4/32", "1.2.3.4", "web_auth", now, time.Second); err != nil {
		t.Fatal(err)
	}
	later := now.Add(2 * time.Second)
	if _, err := s.Record("1.2.3.4/32", "1.2.3.4", "web_auth", later, time.Hour); err != nil {
		t.Fatal(err)
	}

	reloaded, err := New(dir, 10)
	if err != nil {
		t.Fatal(err)
	}
	if got := reloaded.Snapshot(later); len(got) != 1 {
		t.Fatalf("revived entry must be persisted, got %d entries after reload", len(got))
	}
}
