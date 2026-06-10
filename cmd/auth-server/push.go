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

// doPush builds a freshly signed allow.json (identical signing to /allow.json)
// and pushes it to every configured target over SSH, synchronously, one at a
// time, each with its own timeout. It returns the per-target results and NEVER
// returns an error: a push problem must not break the authentication flow.
func (s *server) doPush(now time.Time) []sshpush.Result {
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
	timeout := time.Duration(s.cfg.Push.TimeoutSeconds) * time.Second

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
