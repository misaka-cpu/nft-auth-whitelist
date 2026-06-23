package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/misaka-cpu/nft-auth-whitelist/internal/audit"
	"github.com/misaka-cpu/nft-auth-whitelist/internal/config"
	"github.com/misaka-cpu/nft-auth-whitelist/internal/ipx"
	"github.com/misaka-cpu/nft-auth-whitelist/internal/nftguard"
	"github.com/misaka-cpu/nft-auth-whitelist/internal/pipeline"
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

// pulledState is the state JSON shape; the implementation lives in pipeline so
// the puller and receiver stay byte-compatible.
type pulledState = pipeline.State

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

	// 3-5. Verify signature, enforce max_entries, filter expired/invalid CIDRs.
	res, err := pipeline.VerifyAndFilter(env, p.pipelineParams(), p.audit, now)
	if err != nil {
		return err
	}
	cidrs := res.CIDRs

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
	if err := pipeline.WriteOutputs(now, res, p.pipelineParams(), p.audit); err != nil {
		return err
	}

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
		Allow4:            v4,
		Allow6:            v6,
		ProtectedTCPPorts: p.cfg.NFT.ProtectedTCPPorts,
		ProtectedUDPPorts: p.cfg.NFT.ProtectedUDPPorts,
	})
}

// pipelineParams builds the shared validation/export parameters from the puller
// config, labelling the audit reject action as a pull failure.
func (p *puller) pipelineParams() pipeline.Params {
	return pipeline.Params{
		HMACSecret:      p.cfg.HMACSecret,
		MaxEntries:      p.cfg.MaxEntries,
		AllowIPv4:       p.cfg.AllowIPv4,
		AllowIPv6:       p.cfg.AllowIPv6,
		OutputAllowTxt:  p.cfg.OutputAllowTxt,
		OutputStateJSON: p.cfg.OutputStateJSON,
		SourceLabel:     p.sourceLabel(),
		RejectAction:    audit.ActionPullFail,
	}
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
