package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/misaka-cpu/nft-auth-whitelist/internal/config"
)

// writeFakeSSH writes an executable stand-in for the ssh binary.
func writeFakeSSH(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "fake-ssh.sh")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// pushServer builds a server with push enabled to a single target served by the
// given fake ssh script.
func pushServer(t *testing.T, fakeSSH string) (*server, *bytes.Buffer) {
	t.Helper()
	srv, buf := testServer(t, func(c *config.ServerConfig) {
		c.Push = config.PushConfig{
			Enabled:        true,
			TimeoutSeconds: 5,
			Targets: []config.PushTarget{{
				Name:         "test-vps",
				User:         "nftauth",
				Host:         "203.0.113.10",
				Port:         2222,
				IdentityFile: "/root/.ssh/nft_auth_push_test",
			}},
		}
	})
	srv.pusher.SSHPath = fakeSSH
	return srv, buf
}

func authSuccess(t *testing.T, srv *server) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "1.2.3.4:1111"
	r.SetBasicAuth("admin", "secret")
	srv.Handler().ServeHTTP(rec, r)
	return rec
}

func TestAuthSuccessTriggersPushWhenEnabled(t *testing.T) {
	fake := writeFakeSSH(t, `cat >/dev/null; echo "ok entries=1 output=/var/lib/nft-auth-whitelist/allow.txt"; exit 0`)
	srv, audit := pushServer(t, fake)

	rec := authSuccess(t, srv)
	if rec.Code != http.StatusOK {
		t.Fatalf("auth must still succeed, got %d", rec.Code)
	}
	if srv.store.Count() != 1 {
		t.Fatal("entry must be recorded")
	}
	a := audit.String()
	if !strings.Contains(a, "push.start") || !strings.Contains(a, "push.success") {
		t.Fatalf("audit must contain push.start and push.success, got %s", a)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Push results") || !strings.Contains(body, "test-vps: ok") {
		t.Fatalf("page must show push result, got %s", body)
	}
}

func TestPushDisabledDoesNotPush(t *testing.T) {
	srv, audit := testServer(t, nil) // push disabled (default)
	rec := authSuccess(t, srv)
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d", rec.Code)
	}
	if strings.Contains(audit.String(), "push.start") {
		t.Fatal("push must not run when disabled")
	}
	if strings.Contains(rec.Body.String(), "Push results") {
		t.Fatal("page must not show push section when disabled")
	}
}

func TestPushFailureDoesNotBreakAuth(t *testing.T) {
	fake := writeFakeSSH(t, `cat >/dev/null; echo "connection refused" 1>&2; exit 255`)
	srv, audit := pushServer(t, fake)

	rec := authSuccess(t, srv)
	if rec.Code != http.StatusOK {
		t.Fatalf("push failure must not fail auth; got %d", rec.Code)
	}
	if srv.store.Count() != 1 {
		t.Fatal("entry must still be recorded on push failure")
	}
	if !strings.Contains(audit.String(), "push.fail") {
		t.Fatal("audit must record push.fail")
	}
	if !strings.Contains(rec.Body.String(), "test-vps: failed") {
		t.Fatalf("page must show push failed, got %s", rec.Body.String())
	}
}

func TestPushNeverLeaksSecrets(t *testing.T) {
	// Fake ssh echoes back the configured password to stdout: redaction must
	// strip it before it reaches the audit log or the page.
	fake := writeFakeSSH(t, `cat >/dev/null; echo "leak secret pw and hmac-secret here"; exit 0`)
	srv, audit := pushServer(t, fake)

	rec := authSuccess(t, srv)
	for _, secret := range []string{"secret", "pull-tok", "hmac-secret"} {
		if strings.Contains(audit.String(), secret) {
			t.Fatalf("audit must not contain secret %q", secret)
		}
		if strings.Contains(rec.Body.String(), secret) {
			t.Fatalf("page must not contain secret %q", secret)
		}
	}
}
