package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/misaka-cpu/nft-auth-whitelist/internal/config"
)

// freezeServer builds a server whose freeze file lives in a temp dir, plus the
// path of that (not yet created) freeze file.
func freezeServer(t *testing.T) (*server, string) {
	t.Helper()
	freeze := filepath.Join(t.TempDir(), "freeze")
	srv, _ := testServer(t, func(c *config.ServerConfig) {
		c.FreezeFile = freeze
	})
	return srv, freeze
}

func TestFreezeFileBlocksAuthenticatedWrites(t *testing.T) {
	srv, freeze := freezeServer(t)
	if err := os.WriteFile(freeze, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	rec := authSuccess(t, srv)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("frozen POST must return 503, got %d", rec.Code)
	}
	if srv.store.Count() != 0 {
		t.Fatal("frozen server must not record any entry")
	}
}

func TestFreezeFileBlocksAuthForm(t *testing.T) {
	srv, freeze := freezeServer(t)
	if err := os.WriteFile(freeze, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "1.2.3.4:1111"
	r.SetBasicAuth("admin", "secret")
	srv.Handler().ServeHTTP(rec, r)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("frozen GET must return 503, got %d", rec.Code)
	}
}

func TestFreezeIsAuditedAndNotVisibleWithoutAuth(t *testing.T) {
	srv, freeze := freezeServer(t)
	if err := os.WriteFile(freeze, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	// Without credentials the response stays 401: freeze state must not be
	// observable by unauthenticated scanners.
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.RemoteAddr = "1.2.3.4:1111"
	srv.Handler().ServeHTTP(rec, r)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated request must stay 401 while frozen, got %d", rec.Code)
	}

	rec2 := authSuccess(t, srv)
	if rec2.Code != http.StatusServiceUnavailable {
		t.Fatalf("got %d", rec2.Code)
	}
}

func TestRemovingFreezeFileResumesWithoutRestart(t *testing.T) {
	srv, freeze := freezeServer(t)
	if err := os.WriteFile(freeze, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if rec := authSuccess(t, srv); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("got %d while frozen", rec.Code)
	}

	if err := os.Remove(freeze); err != nil {
		t.Fatal(err)
	}
	rec := authSuccess(t, srv)
	if rec.Code != http.StatusOK {
		t.Fatalf("unfrozen POST must succeed, got %d", rec.Code)
	}
	if srv.store.Count() != 1 {
		t.Fatal("entry must be recorded after unfreeze")
	}
}

func TestFreezeAuditAction(t *testing.T) {
	freeze := filepath.Join(t.TempDir(), "freeze")
	srv, buf := testServer(t, func(c *config.ServerConfig) {
		c.FreezeFile = freeze
	})
	if err := os.WriteFile(freeze, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	authSuccess(t, srv)
	if !strings.Contains(buf.String(), "auth.frozen") {
		t.Fatalf("audit must record auth.frozen, got %s", buf.String())
	}
}
