// Package pipeline holds the shared "verify a signed allow.json envelope and
// export allow.txt + state json" core used by both the puller (source=http/file)
// and the receiver (stdin over an SSH forced command).
//
// It deliberately contains NO transport logic and NO nft logic: callers acquire
// the envelope however they like, and apply the nft guard (if any) themselves.
// The contract is fail-safe: VerifyAndFilter writes nothing, and WriteOutputs
// writes atomically, so a verification or write failure never clobbers the last
// good allow.txt.
package pipeline

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/misaka-cpu/nft-auth-whitelist/internal/audit"
	"github.com/misaka-cpu/nft-auth-whitelist/internal/ipx"
	"github.com/misaka-cpu/nft-auth-whitelist/internal/signer"
)

// Params is the validation + export configuration shared by puller and receiver.
type Params struct {
	HMACSecret      string
	MaxEntries      int
	AllowIPv4       bool
	AllowIPv6       bool
	OutputAllowTxt  string
	OutputStateJSON string
	// SourceLabel is a NON-SECRET description of where the envelope came from
	// (e.g. "file:/path", a redacted URL, or "stdin"). It is safe for the state
	// file and audit log.
	SourceLabel string
	// RejectAction is the audit action used when an envelope is rejected for
	// exceeding MaxEntries (e.g. audit.ActionPullFail or audit.ActionReceiveFail),
	// so the record reads naturally for each caller.
	RejectAction string
}

// Result is the outcome of a successful VerifyAndFilter.
type Result struct {
	Kept  []signer.Entry
	CIDRs []string
}

// State is written to output_state_json after a successful export.
type State struct {
	PulledAt  string         `json:"pulled_at"`
	SourceURL string         `json:"source_url"`
	Count     int            `json:"count"`
	Entries   []signer.Entry `json:"entries"`
}

// VerifyAndFilter verifies the HMAC signature, rejects an oversized envelope
// (MaxEntries), and filters out expired entries and invalid/disallowed-family
// CIDRs. On any failure it returns an error and writes nothing, so the caller
// keeps the previous output. It logs signature.ok/signature.fail and, on an
// oversized envelope, p.RejectAction.
func VerifyAndFilter(env *signer.Envelope, p Params, al *audit.Logger, now time.Time) (*Result, error) {
	// Verify signature first; only trust the contents after this passes.
	if !signer.Verify(env, []byte(p.HMACSecret)) {
		al.Log(audit.ActionSignatureFail, audit.ResultError, map[string]interface{}{"reason": "hmac mismatch"})
		return nil, fmt.Errorf("signature verification failed; keeping previous output")
	}
	al.Log(audit.ActionSignatureOK, audit.ResultOK, nil)

	if env.Version != 1 {
		al.Log(p.RejectAction, audit.ResultError, map[string]interface{}{"reason": "unsupported envelope version"})
		return nil, fmt.Errorf("unsupported envelope version %d", env.Version)
	}
	if env.ExpiresAt.IsZero() {
		al.Log(p.RejectAction, audit.ResultError, map[string]interface{}{"reason": "missing envelope expiry"})
		return nil, fmt.Errorf("envelope expires_at is required")
	}
	if !env.ExpiresAt.After(now) {
		al.Log(p.RejectAction, audit.ResultError, map[string]interface{}{"reason": "envelope expired"})
		return nil, fmt.Errorf("envelope expired at %s", env.ExpiresAt.UTC().Format(time.RFC3339))
	}

	// max_entries guard: reject (do not truncate) an oversized envelope so a
	// misbehaving producer cannot blow up the local allowlist.
	if len(env.Entries) > p.MaxEntries {
		al.Log(p.RejectAction, audit.ResultWarn, map[string]interface{}{
			"reason":      "envelope exceeds max_entries",
			"got":         len(env.Entries),
			"max_entries": p.MaxEntries,
		})
		return nil, fmt.Errorf("envelope has %d entries > max_entries %d; rejecting", len(env.Entries), p.MaxEntries)
	}

	// Filter: drop expired and invalid/unallowed CIDRs.
	var kept []signer.Entry
	var cidrs []string
	for _, e := range env.Entries {
		if !e.ExpiresAt.After(now) {
			continue // expired
		}
		canon, ok := ipx.CanonicalCIDR(e.CIDR, p.AllowIPv4, p.AllowIPv6)
		if !ok {
			continue // invalid or disallowed family
		}
		e.CIDR = canon
		kept = append(kept, e)
		cidrs = append(cidrs, canon)
	}
	sort.Strings(cidrs)
	cidrs = dedup(cidrs)
	return &Result{Kept: kept, CIDRs: cidrs}, nil
}

// WriteOutputs atomically writes allow.txt and (when OutputStateJSON is set) the
// state json, then logs output.write.success. On any write error it logs
// output.write.fail and returns the error without leaving partial output.
func WriteOutputs(now time.Time, res *Result, p Params, al *audit.Logger) error {
	txt := strings.Join(res.CIDRs, "\n")
	if len(res.CIDRs) > 0 {
		txt += "\n"
	}
	if err := AtomicWrite(p.OutputAllowTxt, []byte(txt), 0o600); err != nil {
		al.Log(audit.ActionOutputWriteFail, audit.ResultError, map[string]interface{}{"reason": err.Error()})
		return err
	}
	if p.OutputStateJSON != "" {
		state := State{
			PulledAt:  now.UTC().Format(time.RFC3339),
			SourceURL: p.SourceLabel,
			Count:     len(res.Kept),
			Entries:   res.Kept,
		}
		b, err := json.MarshalIndent(state, "", "  ")
		if err != nil {
			al.Log(audit.ActionOutputWriteFail, audit.ResultError, map[string]interface{}{"reason": err.Error()})
			return err
		}
		if err := AtomicWrite(p.OutputStateJSON, b, 0o600); err != nil {
			al.Log(audit.ActionOutputWriteFail, audit.ResultError, map[string]interface{}{"reason": err.Error()})
			return err
		}
	}
	al.Log(audit.ActionOutputWriteOK, audit.ResultOK, map[string]interface{}{"entries": len(res.CIDRs), "path": p.OutputAllowTxt})
	return nil
}

func dedup(sorted []string) []string {
	if len(sorted) == 0 {
		return sorted
	}
	out := sorted[:1]
	for _, s := range sorted[1:] {
		if s != out[len(out)-1] {
			out = append(out, s)
		}
	}
	return out
}

// AtomicWrite writes via a temp file + rename in the destination directory, so a
// reader never observes a half-written or empty file in place of the old one.
func AtomicWrite(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, perm); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
