package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/misaka-cpu/nft-auth-whitelist/internal/audit"
	"github.com/misaka-cpu/nft-auth-whitelist/internal/config"
	"github.com/misaka-cpu/nft-auth-whitelist/internal/pipeline"
	"github.com/misaka-cpu/nft-auth-whitelist/internal/signer"
)

// receiver holds dependencies for one receive operation.
type receiver struct {
	cfg    *config.ReceiveConfig
	audit  *audit.Logger
	now    func() time.Time
	stdout io.Writer
}

func newReceiver(cfg *config.ReceiveConfig, al *audit.Logger) *receiver {
	return &receiver{cfg: cfg, audit: al, now: time.Now, stdout: os.Stdout}
}

// run reads a signed allow.json from stdin, verifies it, then writes the inbox
// copy, the state json, and the operative allow.txt — in that order, with
// allow.txt LAST. Success means the new allow.txt was applied; on ANY failure
// run returns an error and the live allow.txt is left unchanged (no new
// allowlist is applied). The inbox/state records may be a step ahead of
// allow.txt after a late failure — they are debug records, not operative. It
// never echoes the input or secrets.
func (r *receiver) run(stdin io.Reader) error {
	now := r.now()

	// 1-2. Read stdin under a hard size cap.
	data, err := readLimited(stdin, r.cfg.InputMaxBytes)
	if err != nil {
		r.audit.Log(audit.ActionReceiveFail, audit.ResultError, map[string]interface{}{"reason": err.Error()})
		return err
	}
	if len(data) == 0 {
		err := fmt.Errorf("empty input")
		r.audit.Log(audit.ActionReceiveFail, audit.ResultError, map[string]interface{}{"reason": err.Error()})
		return err
	}

	// 3. Parse JSON (never log the raw body).
	var env signer.Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		r.audit.Log(audit.ActionReceiveFail, audit.ResultError, map[string]interface{}{"reason": "invalid json"})
		return fmt.Errorf("decode envelope: %w", err)
	}

	// 4-9. Verify signature, enforce max_entries, filter expired/invalid CIDRs.
	params := r.pipelineParams()
	res, err := pipeline.VerifyAndFilter(&env, params, r.audit, now)
	if err != nil {
		return err
	}

	// 10. Persist the inbox copy first (a debug record), then export via
	// WriteOutputs, which writes the state json and the operative allow.txt LAST.
	// allow.txt is thus the final write: a failure in any earlier step leaves the
	// live allow.txt unchanged (the command fails and applies no new allowlist).
	// All writes are atomic. The inbox/state records may be one step ahead of
	// allow.txt after a failure; they are records, not operative.
	if err := pipeline.AtomicWrite(r.cfg.InboxAllowJSON, data, 0o600); err != nil {
		r.audit.Log(audit.ActionOutputWriteFail, audit.ResultError, map[string]interface{}{"reason": err.Error()})
		return err
	}
	if err := pipeline.WriteOutputs(now, res, params, r.audit); err != nil {
		return err
	}

	r.audit.Log(audit.ActionReceiveSuccess, audit.ResultOK, map[string]interface{}{"entries": len(res.CIDRs)})
	fmt.Fprintf(r.stdout, "ok entries=%d output=%s\n", len(res.CIDRs), r.cfg.OutputAllowTxt)
	return nil
}

// pipelineParams builds the shared validation/export parameters; the audit
// reject action reads as a receive failure.
func (r *receiver) pipelineParams() pipeline.Params {
	return pipeline.Params{
		HMACSecret:      r.cfg.HMACSecret,
		MaxEntries:      r.cfg.MaxEntries,
		AllowIPv4:       r.cfg.AllowIPv4,
		AllowIPv6:       r.cfg.AllowIPv6,
		OutputAllowTxt:  r.cfg.OutputAllowTxt,
		OutputStateJSON: r.cfg.OutputStateJSON,
		SourceLabel:     "stdin",
		RejectAction:    audit.ActionReceiveFail,
	}
}

// readLimited reads up to max bytes from r. Reading more than max is an error so
// a peer cannot stream an unbounded body into memory.
func readLimited(r io.Reader, max int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("input exceeds input_max_bytes (%d)", max)
	}
	return data, nil
}
