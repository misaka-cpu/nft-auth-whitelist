package main

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/misaka-cpu/nft-auth-whitelist/internal/audit"
	"github.com/misaka-cpu/nft-auth-whitelist/internal/config"
	"github.com/misaka-cpu/nft-auth-whitelist/internal/sshpush"
)

// pushRequestBudget keeps synchronous SSH push safely below the auth-server
// HTTP WriteTimeout (15s), while preserving per-target push results on the
// success page.
const pushRequestBudget = 12 * time.Second

// doPush builds a freshly signed allow.json (identical signing to /allow.json)
// and pushes it to configured targets over SSH within a bounded request budget.
func (s *server) doPush(now time.Time) []sshpush.Result {
	return s.doPushWithBudget(now, pushRequestBudget)
}

// doPushWithBudget returns per-target results and NEVER returns an error: a
// push problem must not break the authentication flow.
func (s *server) doPushWithBudget(now time.Time, budget time.Duration) []sshpush.Result {
	// Reuse the exact same envelope-building + signing path as /allow.json so the
	// receiver verifies it with the same hmac_secret.
	env, err := s.store.BuildEnvelope(now, envelopeTTL, []byte(s.cfg.HMACSecret))
	if err != nil {
		s.audit.Log(audit.ActionPushFail, audit.ResultError, map[string]interface{}{"reason": "build envelope failed"})
		return []sshpush.Result{{Name: "(envelope)", Reason: "internal error building envelope"}}
	}
	payload, err := json.Marshal(env)
	if err != nil {
		s.audit.Log(audit.ActionPushFail, audit.ResultError, map[string]interface{}{"reason": "marshal envelope failed"})
		return []sshpush.Result{{Name: "(envelope)", Reason: "internal error marshalling envelope"}}
	}

	entries := len(env.Entries)
	targetTimeout := time.Duration(s.cfg.Push.TimeoutSeconds) * time.Second
	deadline := time.Now().Add(budget)

	results := make([]sshpush.Result, 0, len(s.cfg.Push.Targets))
	for _, tc := range s.cfg.Push.Targets {
		t := sshpush.Target{
			Name:                  tc.Name,
			User:                  tc.User,
			Host:                  tc.Host,
			Port:                  tc.Port,
			IdentityFile:          tc.IdentityFile,
			StrictHostKeyChecking: tc.StrictHostKey(),
			KnownHostsFile:        tc.KnownHostsFile,
		}

		remaining := time.Until(deadline)
		if remaining <= 0 {
			r := sshpush.Result{
				Name:       t.Name,
				Host:       t.Host,
				Port:       t.Port,
				OK:         false,
				ExitStatus: -1,
				Reason:     "push budget exhausted",
			}
			s.audit.Log(audit.ActionPushFail, audit.ResultWarn, map[string]interface{}{
				"target": t.Name, "host": t.Host, "port": t.Port,
				"duration_ms": r.DurationMs, "reason": r.Reason, "exit_status": r.ExitStatus,
			})
			results = append(results, r)
			continue
		}
		timeout := targetTimeout
		if remaining < timeout {
			timeout = remaining
		}

		s.audit.Log(audit.ActionPushStart, audit.ResultOK, map[string]interface{}{
			"target": t.Name, "host": t.Host, "port": t.Port,
		})

		r := s.pusher.Push(context.Background(), t, payload, timeout)
		// Defensive: scrub any secret value that could conceivably appear in the
		// captured output before it reaches audit log or page.
		r.Stdout = s.redactSecrets(r.Stdout)
		r.Reason = s.redactSecrets(r.Reason)

		if r.OK {
			s.audit.Log(audit.ActionPushSuccess, audit.ResultOK, map[string]interface{}{
				"target": t.Name, "host": t.Host, "port": t.Port,
				"duration_ms": r.DurationMs, "stdout": r.Stdout, "entries": entries,
			})
		} else {
			s.audit.Log(audit.ActionPushFail, audit.ResultWarn, map[string]interface{}{
				"target": t.Name, "host": t.Host, "port": t.Port,
				"duration_ms": r.DurationMs, "reason": r.Reason, "exit_status": r.ExitStatus,
			})
		}
		results = append(results, r)
	}
	return results
}

// redactSecrets replaces any configured secret value with a placeholder, so a
// secret can never leak into the audit log or the success page even if a remote
// echoed it back.
func (s *server) redactSecrets(in string) string {
	if in == "" {
		return in
	}
	for _, secret := range secretValues(s.cfg) {
		if secret != "" {
			in = strings.ReplaceAll(in, secret, "<redacted>")
		}
	}
	return in
}

func secretValues(c *config.ServerConfig) []string {
	return []string{c.HMACSecret, c.PullToken, c.Password}
}

// purgeAndSync removes expired entries and, when push is enabled and the purge
// actually removed something, proactively pushes the (now smaller) allowlist to
// the receivers so expired IPs stop being allowed there. It is called from the
// background purge ticker — off the auth request path — so it may push
// synchronously without affecting any HTTP response. It returns the purged CIDRs.
func (s *server) purgeAndSync(now time.Time) []string {
	removed := s.store.Purge(now)
	for _, cidr := range removed {
		s.audit.Log(audit.ActionEntryExpire, audit.ResultOK, map[string]interface{}{"cidr": cidr})
	}
	if len(removed) > 0 && s.cfg.Push.Enabled {
		s.doPush(now)
	}
	return removed
}

// reconcileSync purges expired entries and then pushes the current allowlist
// unconditionally, so a receiver that missed an earlier push (network blip,
// receiver downtime) converges back to the server state within one interval.
// It runs on its own background ticker, off the auth request path.
func (s *server) reconcileSync(now time.Time) {
	for _, cidr := range s.store.Purge(now) {
		s.audit.Log(audit.ActionEntryExpire, audit.ResultOK, map[string]interface{}{"cidr": cidr})
	}
	if !s.cfg.Push.Enabled {
		return
	}
	s.audit.Log(audit.ActionPushReconcile, audit.ResultOK, map[string]interface{}{
		"entries": s.store.Count(),
	})
	s.doPush(now)
}
