package main

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"

	"github.com/misaka-cpu/nft-auth-whitelist/internal/audit"
	"github.com/misaka-cpu/nft-auth-whitelist/internal/auth"
)

// handleAllowJSON serves the signed envelope. Requires a bearer pull_token.
func (s *server) handleAllowJSON(w http.ResponseWriter, r *http.Request) {
	peer := clientHost(r)
	if !auth.CheckBearer(r, s.cfg.PullToken) {
		s.audit.Log(audit.ActionPullFail, audit.ResultWarn, map[string]interface{}{"peer": peer, "endpoint": "/allow.json"})
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	env, err := s.store.BuildEnvelope(s.now(), envelopeTTL, []byte(s.cfg.HMACSecret))
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	b, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.audit.Log(audit.ActionPullSuccess, audit.ResultOK, map[string]interface{}{"peer": peer, "endpoint": "/allow.json", "entries": len(env.Entries)})
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_, _ = w.Write(b)
}

// handleAllowTxt serves a plain CIDR-per-line list. Requires a bearer
// pull_token. The puller prefers /allow.json because that is signed.
func (s *server) handleAllowTxt(w http.ResponseWriter, r *http.Request) {
	peer := clientHost(r)
	if !auth.CheckBearer(r, s.cfg.PullToken) {
		s.audit.Log(audit.ActionPullFail, audit.ResultWarn, map[string]interface{}{"peer": peer, "endpoint": "/allow.txt"})
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	snap := s.store.Snapshot(s.now())
	lines := make([]string, 0, len(snap))
	for _, e := range snap {
		lines = append(lines, e.CIDR)
	}
	sort.Strings(lines)
	s.audit.Log(audit.ActionPullSuccess, audit.ResultOK, map[string]interface{}{"peer": peer, "endpoint": "/allow.txt", "entries": len(lines)})
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(strings.Join(lines, "\n")))
	if len(lines) > 0 {
		_, _ = w.Write([]byte("\n"))
	}
}
