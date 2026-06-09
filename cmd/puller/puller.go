package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/misaka-cpu/nft-auth-whitelist/internal/audit"
	"github.com/misaka-cpu/nft-auth-whitelist/internal/config"
	"github.com/misaka-cpu/nft-auth-whitelist/internal/ipx"
	"github.com/misaka-cpu/nft-auth-whitelist/internal/nftguard"
	"github.com/misaka-cpu/nft-auth-whitelist/internal/signer"
)

// runOptions captures the command-line behaviour flags.
type runOptions struct {
	DryRun bool
	Apply  bool
}

// puller holds dependencies for one or more pull cycles.
type puller struct {
	cfg    *config.PullerConfig
	audit  *audit.Logger
	client *http.Client
	now    func() time.Time
	stdout io.Writer
}

func newPuller(cfg *config.PullerConfig, al *audit.Logger) *puller {
	return &puller{
		cfg:    cfg,
		audit:  al,
		client: &http.Client{Timeout: 15 * time.Second},
		now:    time.Now,
		stdout: os.Stdout,
	}
}

// pulledState is written to output_state_json after a successful pull.
type pulledState struct {
	PulledAt  string         `json:"pulled_at"`
	SourceURL string         `json:"source_url"`
	Count     int            `json:"count"`
	Entries   []signer.Entry `json:"entries"`
}

// fetchEnvelope acquires the signed envelope from the configured source. All
// later steps (verify / TTL / family / output) are shared regardless of source.
func (p *puller) fetchEnvelope() (*signer.Envelope, error) {
	if p.cfg.Source == "file" {
		return p.readEnvelopeFile()
	}
	return p.fetchEnvelopeHTTP()
}

// readEnvelopeFile reads and decodes a signed envelope delivered to a local
// file (e.g. pushed in over SSH/scp). It makes no network request and ignores
// server_url / pull_token / require_https. A missing or malformed file is an
// error; the caller keeps the previous allow.txt intact on any error.
func (p *puller) readEnvelopeFile() (*signer.Envelope, error) {
	if p.cfg.InputAllowJSON == "" {
		return nil, fmt.Errorf("source=file requires input_allow_json")
	}
	b, err := os.ReadFile(p.cfg.InputAllowJSON)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", p.cfg.InputAllowJSON, err)
	}
	var env signer.Envelope
	if err := json.Unmarshal(b, &env); err != nil {
		return nil, fmt.Errorf("decode envelope: %w", err)
	}
	return &env, nil
}

// fetchEnvelopeHTTP retrieves and decodes the signed envelope over HTTP(S). It
// never logs the token (it travels in the Authorization header, not the URL).
func (p *puller) fetchEnvelopeHTTP() (*signer.Envelope, error) {
	req, err := http.NewRequest(http.MethodGet, p.cfg.ServerURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+p.cfg.PullToken)
	req.Header.Set("Accept", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned status %d", resp.StatusCode)
	}
	var env signer.Envelope
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, fmt.Errorf("decode envelope: %w", err)
	}
	return &env, nil
}

// runOnce performs a single pull/verify/filter/output cycle. On any failure it
// returns an error WITHOUT modifying the existing output files, so the last
// good allow.txt is preserved.
func (p *puller) runOnce(opts runOptions) error {
	now := p.now()

	// 1. Enforce HTTPS before doing anything. Not applicable to the file source,
	// which makes no network request.
	if p.cfg.Source != "file" && p.cfg.RequireHTTPS && !strings.HasPrefix(strings.ToLower(p.cfg.ServerURL), "https://") {
		err := fmt.Errorf("require_https is enabled but server_url is not https://")
		p.audit.Log(audit.ActionPullFail, audit.ResultError, map[string]interface{}{"reason": err.Error(), "source": p.sourceLabel()})
		return err
	}

	// 2. Fetch (over HTTP(S) or from the local file).
	env, err := p.fetchEnvelope()
	if err != nil {
		// Keep previous output intact.
		p.audit.Log(audit.ActionPullFail, audit.ResultWarn, map[string]interface{}{"reason": err.Error(), "source": p.sourceLabel()})
		return err
	}
	p.audit.Log(audit.ActionPullSuccess, audit.ResultOK, map[string]interface{}{"entries": len(env.Entries)})

	// 3. Verify signature.
	if !signer.Verify(env, []byte(p.cfg.HMACSecret)) {
		p.audit.Log(audit.ActionSignatureFail, audit.ResultError, map[string]interface{}{"reason": "hmac mismatch"})
		return fmt.Errorf("signature verification failed; keeping previous output")
	}
	p.audit.Log(audit.ActionSignatureOK, audit.ResultOK, nil)

	// 4. max_entries guard: reject (do not truncate) an oversized envelope so a
	// misbehaving server cannot blow up the local allowlist.
	if len(env.Entries) > p.cfg.MaxEntries {
		p.audit.Log(audit.ActionPullFail, audit.ResultWarn, map[string]interface{}{
			"reason":      "envelope exceeds max_entries",
			"got":         len(env.Entries),
			"max_entries": p.cfg.MaxEntries,
		})
		return fmt.Errorf("envelope has %d entries > max_entries %d; rejecting", len(env.Entries), p.cfg.MaxEntries)
	}

	// 5. Filter: drop expired and invalid/unallowed CIDRs.
	var kept []signer.Entry
	var cidrs []string
	for _, e := range env.Entries {
		if !e.ExpiresAt.After(now) {
			continue // expired
		}
		canon, ok := ipx.CanonicalCIDR(e.CIDR, p.cfg.AllowIPv4, p.cfg.AllowIPv6)
		if !ok {
			continue // invalid or disallowed family
		}
		e.CIDR = canon
		kept = append(kept, e)
		cidrs = append(cidrs, canon)
	}
	sort.Strings(cidrs)
	cidrs = dedup(cidrs)

	// 6. dry-run: print, do not write or apply.
	if opts.DryRun {
		fmt.Fprintf(p.stdout, "# dry-run: %d valid entries (no files written)\n", len(cidrs))
		fmt.Fprintln(p.stdout, "# allow.txt would contain:")
		for _, c := range cidrs {
			fmt.Fprintln(p.stdout, c)
		}
		fmt.Fprintln(p.stdout, "\n# nft guard script (dry-run, not applied):")
		fmt.Fprintln(p.stdout, p.buildNFTScript(cidrs))
		p.audit.Log(audit.ActionNFTDryRun, audit.ResultOK, map[string]interface{}{"entries": len(cidrs)})
		return nil
	}

	// 7. Write allow.txt and state json atomically.
	if err := p.writeOutputs(now, kept, cidrs); err != nil {
		p.audit.Log(audit.ActionOutputWriteFail, audit.ResultError, map[string]interface{}{"reason": err.Error()})
		return err
	}
	p.audit.Log(audit.ActionOutputWriteOK, audit.ResultOK, map[string]interface{}{"entries": len(cidrs), "path": p.cfg.OutputAllowTxt})

	// 8. Optional nft apply: gated on (mode=nft OR nft.enabled) AND --apply.
	if opts.Apply {
		if p.applyAllowed() {
			script := p.buildNFTScript(cidrs)
			if err := nftguard.Apply(script); err != nil {
				p.audit.Log(audit.ActionNFTApplyFail, audit.ResultError, map[string]interface{}{"reason": err.Error()})
				return err
			}
			p.audit.Log(audit.ActionNFTApplySuccess, audit.ResultOK, map[string]interface{}{"entries": len(cidrs)})
		} else {
			// --apply was passed but the guard is not enabled in config: stay in
			// export mode and warn loudly rather than silently applying.
			p.audit.Log(audit.ActionNFTApplyFail, audit.ResultWarn, map[string]interface{}{
				"reason": "--apply ignored: nft guard not enabled (set mode=nft or nft.enabled=true)",
			})
			fmt.Fprintln(p.stdout, "WARN: --apply ignored because nft guard is not enabled in config (mode=nft or nft.enabled=true required)")
		}
	}
	return nil
}

func (p *puller) applyAllowed() bool {
	return p.cfg.Mode == "nft" || p.cfg.NFT.Enabled
}

func (p *puller) buildNFTScript(cidrs []string) string {
	var v4, v6 []string
	for _, c := range cidrs {
		switch ipx.FamilyOfCIDR(c) {
		case "ipv4":
			v4 = append(v4, c)
		case "ipv6":
			v6 = append(v6, c)
		}
	}
	return nftguard.GenerateScript(nftguard.Config{
		Table:             p.cfg.NFT.Table,
		Allow4:            v4,
		Allow6:            v6,
		ProtectedTCPPorts: p.cfg.NFT.ProtectedTCPPorts,
		ProtectedUDPPorts: p.cfg.NFT.ProtectedUDPPorts,
	})
}

func (p *puller) writeOutputs(now time.Time, kept []signer.Entry, cidrs []string) error {
	txt := strings.Join(cidrs, "\n")
	if len(cidrs) > 0 {
		txt += "\n"
	}
	if err := atomicWrite(p.cfg.OutputAllowTxt, []byte(txt), 0o644); err != nil {
		return err
	}
	if p.cfg.OutputStateJSON != "" {
		state := pulledState{
			PulledAt:  now.UTC().Format(time.RFC3339),
			SourceURL: p.sourceLabel(),
			Count:     len(kept),
			Entries:   kept,
		}
		b, err := json.MarshalIndent(state, "", "  ")
		if err != nil {
			return err
		}
		if err := atomicWrite(p.cfg.OutputStateJSON, b, 0o644); err != nil {
			return err
		}
	}
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

// sourceLabel is a non-secret description of where the envelope came from, safe
// to put in the audit log and state file.
func (p *puller) sourceLabel() string {
	if p.cfg.Source == "file" {
		return "file:" + p.cfg.InputAllowJSON
	}
	return redactURL(p.cfg.ServerURL)
}

// redactURL strips any query string so a token accidentally placed in the URL
// never reaches the audit log. (Tokens are normally sent as a header.)
func redactURL(raw string) string {
	if i := strings.IndexByte(raw, '?'); i >= 0 {
		return raw[:i] + "?<redacted>"
	}
	return raw
}

// atomicWrite writes via a temp file + rename in the destination directory.
func atomicWrite(path string, data []byte, perm os.FileMode) error {
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
