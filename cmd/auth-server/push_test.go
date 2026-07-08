package main

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
	r := httptest.NewRequest(http.MethodPost, "/", nil)
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

func TestPushStopsWhenRequestBudgetIsExhausted(t *testing.T) {
	countFile := filepath.Join(t.TempDir(), "push-count")
	fake := writeFakeSSH(t, fmt.Sprintf(`printf x >> %q
while :; do :; done`, countFile))
	srv, _ := pushServer(t, fake)
	srv.cfg.Push.TimeoutSeconds = 1
	srv.cfg.Push.Targets = []config.PushTarget{
		{
			Name:         "slow-1",
			User:         "nftauth",
			Host:         "203.0.113.10",
			Port:         2222,
			IdentityFile: "/root/.ssh/nft_auth_push_test",
		},
		{
			Name:         "slow-2",
			User:         "nftauth",
			Host:         "203.0.113.11",
			Port:         2222,
			IdentityFile: "/root/.ssh/nft_auth_push_test",
		},
	}

	start := time.Now()
	results := srv.doPushWithBudget(time.Now(), 100*time.Millisecond)
	elapsed := time.Since(start)

	if elapsed > 750*time.Millisecond {
		t.Fatalf("push exceeded request budget by too much: %s", elapsed)
	}
	if len(results) != 2 {
		t.Fatalf("got %d results, want 2", len(results))
	}
	if results[0].OK || !strings.Contains(results[0].Reason, "timeout after") {
		t.Fatalf("first target should time out within the total budget, got %+v", results[0])
	}
	if results[1].OK || results[1].Reason != "push budget exhausted" {
		t.Fatalf("second target should be skipped after budget exhaustion, got %+v", results[1])
	}
	b, err := os.ReadFile(countFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "x" {
		t.Fatalf("fake ssh should run once, ran %d times", len(b))
	}
}

func TestPurgeSyncPushesAfterExpiry(t *testing.T) {
	fake := writeFakeSSH(t, `cat >/dev/null; echo "ok entries=0 output=/var/lib/nft-auth-whitelist/allow.txt"; exit 0`)
	srv, audit := pushServer(t, fake)

	// Seed an entry with a short TTL directly in the store.
	base := time.Date(2026, 6, 25, 12, 0, 0, 0, time.UTC)
	if _, err := srv.store.Record("9.9.9.9/32", "9.9.9.9", "web_auth", base, time.Second); err != nil {
		t.Fatal(err)
	}

	// A background purge well after expiry must drop it AND push the smaller list.
	removed := srv.purgeAndSync(base.Add(time.Hour))
	if len(removed) != 1 || removed[0] != "9.9.9.9/32" {
		t.Fatalf("purge should remove the expired entry, got %v", removed)
	}
	a := audit.String()
	if !strings.Contains(a, "entry.expire") {
		t.Fatalf("audit must record entry.expire, got %s", a)
	}
	if !strings.Contains(a, "push.start") || !strings.Contains(a, "push.success") {
		t.Fatalf("a purge that removed entries must trigger a push, got %s", a)
	}
}

func TestReconcileSyncPushesWithoutExpiry(t *testing.T) {
	fake := writeFakeSSH(t, `cat >/dev/null; echo "ok entries=1 output=/var/lib/nft-auth-whitelist/allow.txt"; exit 0`)
	srv, audit := pushServer(t, fake)

	// A live, unexpired entry: purge removes nothing, reconcile must still push.
	now := time.Now()
	if _, err := srv.store.Record("1.2.3.4/32", "1.2.3.4", "web_auth", now, time.Hour); err != nil {
		t.Fatal(err)
	}
	srv.reconcileSync(now.Add(time.Minute))

	a := audit.String()
	if !strings.Contains(a, "push.reconcile") {
		t.Fatalf("audit must record push.reconcile, got %s", a)
	}
	if !strings.Contains(a, "push.start") || !strings.Contains(a, "push.success") {
		t.Fatalf("reconcile must push even when nothing expired, got %s", a)
	}
}

func TestReconcileSyncAlsoPurgesExpired(t *testing.T) {
	fake := writeFakeSSH(t, `cat >/dev/null; echo ok; exit 0`)
	srv, audit := pushServer(t, fake)

	base := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	if _, err := srv.store.Record("9.9.9.9/32", "9.9.9.9", "web_auth", base, time.Second); err != nil {
		t.Fatal(err)
	}
	srv.reconcileSync(base.Add(time.Hour))

	a := audit.String()
	if !strings.Contains(a, "entry.expire") {
		t.Fatalf("reconcile must purge expired entries first, got %s", a)
	}
	if !strings.Contains(a, "push.start") {
		t.Fatalf("reconcile must push after purging, got %s", a)
	}
}

func TestReconcileSyncNoPushWhenPushDisabled(t *testing.T) {
	srv, audit := testServer(t, nil) // push disabled (default)
	srv.reconcileSync(time.Now())
	if strings.Contains(audit.String(), "push.") {
		t.Fatalf("reconcile must not push when push is disabled, got %s", audit.String())
	}
}

func TestPurgeSyncNoPushWhenNothingExpired(t *testing.T) {
	fake := writeFakeSSH(t, `cat >/dev/null; echo ok; exit 0`)
	srv, audit := pushServer(t, fake)

	now := time.Now()
	if _, err := srv.store.Record("1.2.3.4/32", "1.2.3.4", "web_auth", now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if removed := srv.purgeAndSync(now.Add(time.Minute)); len(removed) != 0 {
		t.Fatalf("nothing should be purged, got %v", removed)
	}
	if strings.Contains(audit.String(), "push.start") {
		t.Fatal("a purge that removed nothing must not push")
	}
}
