package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/misaka-cpu/nft-auth-whitelist/internal/audit"
	"github.com/misaka-cpu/nft-auth-whitelist/internal/config"
	"github.com/misaka-cpu/nft-auth-whitelist/internal/signer"
	"github.com/misaka-cpu/nft-auth-whitelist/internal/store"
)

func testServer(t *testing.T, mutate func(*config.ServerConfig)) (*server, *bytes.Buffer) {
	t.Helper()
	cfg := &config.ServerConfig{
		Listen:     "127.0.0.1:0",
		Username:   "admin",
		Password:   "secret",
		PullToken:  "pull-tok",
		HMACSecret: "hmac-secret",
		TTLSeconds: 3600,
		MaxEntries: 100,
		AllowIPv4:  true,
		AllowIPv6:  false,
		RateLimit:  config.RateLimit{Enabled: true, MaxFailuresPerMinute: 100},
	}
	if mutate != nil {
		mutate(cfg)
	}
	st, err := store.New(t.TempDir(), cfg.MaxEntries)
	if err != nil {
		t.Fatal(err)
	}
	buf := &bytes.Buffer{}
	al := audit.NewWithWriter(buf)
	return newServer(cfg, st, al), buf
}

func TestRootBasicAuthRequired(t *testing.T) {
	srv, _ := testServer(t, nil)
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "1.2.3.4:1111"
	srv.Handler().ServeHTTP(rec, r)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 without auth, got %d", rec.Code)
	}
	if rec.Header().Get("WWW-Authenticate") == "" {
		t.Fatal("expected WWW-Authenticate header")
	}
}

func TestRootGetWithAuthShowsFormWithoutRecording(t *testing.T) {
	srv, _ := testServer(t, nil)
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "1.2.3.4:1111"
	r.SetBasicAuth("admin", "secret")
	srv.Handler().ServeHTTP(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if srv.store.Count() != 0 {
		t.Fatalf("GET / must not record an entry, count=%d", srv.store.Count())
	}
	if !strings.Contains(rec.Body.String(), "method=\"post\"") {
		t.Fatalf("GET / should render a POST form, got %s", rec.Body.String())
	}
}

func TestRootGetWithAuthDoesNotPurgeExpiredEntries(t *testing.T) {
	srv, _ := testServer(t, nil)
	now := time.Date(2026, 6, 26, 12, 0, 0, 0, time.UTC)
	old := now.Add(-2 * time.Minute)
	if _, err := srv.store.Record("9.9.9.9/32", "9.9.9.9", "test", old, time.Minute); err != nil {
		t.Fatal(err)
	}
	srv.now = func() time.Time { return now }

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "1.2.3.4:1111"
	r.SetBasicAuth("admin", "secret")
	srv.Handler().ServeHTTP(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	snap := srv.store.Snapshot(old.Add(30 * time.Second))
	if len(snap) != 1 || snap[0].CIDR != "9.9.9.9/32" {
		t.Fatalf("GET / must not purge or add entries, got %+v", snap)
	}
}

func TestRootUnsupportedMethodDoesNotRecord(t *testing.T) {
	srv, _ := testServer(t, nil)
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPut, "/", nil)
	r.RemoteAddr = "1.2.3.4:1111"
	r.SetBasicAuth("admin", "secret")
	srv.Handler().ServeHTTP(rec, r)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("want 405, got %d: %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Allow") != "GET, POST" {
		t.Fatalf("Allow = %q, want GET, POST", rec.Header().Get("Allow"))
	}
	if srv.store.Count() != 0 {
		t.Fatalf("unsupported method must not record, count=%d", srv.store.Count())
	}
}

func TestRootPostBasicAuthSuccessRecordsRemoteAddr(t *testing.T) {
	srv, _ := testServer(t, nil)
	rec := httptest.NewRecorder()
	// Attempt to spoof via query param AND X-Forwarded-For; both must be ignored.
	r := httptest.NewRequest(http.MethodPost, "/?ip=9.9.9.9", nil)
	r.RemoteAddr = "1.2.3.4:1111"
	r.Header.Set("X-Forwarded-For", "8.8.8.8")
	r.SetBasicAuth("admin", "secret")
	srv.Handler().ServeHTTP(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	snap := srv.store.Snapshot(srv.now())
	if len(snap) != 1 || snap[0].CIDR != "1.2.3.4/32" {
		t.Fatalf("must record RemoteAddr /32 only, got %+v", snap)
	}
}

func TestRootTrustedProxyRecordsCFConnectingIP(t *testing.T) {
	srv, buf := testServer(t, func(c *config.ServerConfig) {
		c.TrustedProxyCIDRs = []string{"127.0.0.1/32"}
	})
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.RemoteAddr = "127.0.0.1:1111"
	r.Header.Set("CF-Connecting-IP", "1.2.3.4")
	r.Header.Set("X-Real-IP", "5.6.7.8")
	r.SetBasicAuth("admin", "secret")

	srv.Handler().ServeHTTP(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	snap := srv.store.Snapshot(srv.now())
	if len(snap) != 1 || snap[0].CIDR != "1.2.3.4/32" {
		t.Fatalf("must record CF-Connecting-IP /32, got %+v", snap)
	}
	auditLog := buf.String()
	if !strings.Contains(auditLog, `"client_ip":"1.2.3.4"`) {
		t.Fatalf("audit must include client_ip, got %s", auditLog)
	}
	if !strings.Contains(auditLog, `"client_ip_source":"cf-connecting-ip"`) {
		t.Fatalf("audit must include client_ip_source, got %s", auditLog)
	}
	if !strings.Contains(auditLog, `"remote_ip":"127.0.0.1"`) {
		t.Fatalf("audit must include remote_ip, got %s", auditLog)
	}
}

func TestRootBasicAuthFailure(t *testing.T) {
	srv, _ := testServer(t, nil)
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "1.2.3.4:1111"
	r.SetBasicAuth("admin", "wrong")
	srv.Handler().ServeHTTP(rec, r)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 on bad password, got %d", rec.Code)
	}
	if srv.store.Count() != 0 {
		t.Fatal("failed auth must not record any entry")
	}
}

func TestRootBasicAuthFailureDoesNotPurgeExpiredEntries(t *testing.T) {
	srv, _ := testServer(t, nil)
	now := time.Date(2026, 6, 25, 12, 0, 0, 0, time.UTC)
	old := now.Add(-2 * time.Minute)
	if _, err := srv.store.Record("1.2.3.4/32", "1.2.3.4", "test", old, time.Minute); err != nil {
		t.Fatal(err)
	}
	srv.now = func() time.Time { return now }

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "5.6.7.8:1111"
	r.SetBasicAuth("admin", "wrong")
	srv.Handler().ServeHTTP(rec, r)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 on bad password, got %d", rec.Code)
	}
	if srv.store.Count() != 1 {
		t.Fatalf("unauthenticated request must not purge expired entries, count=%d", srv.store.Count())
	}
}

func TestExpand24DisabledByDefault(t *testing.T) {
	srv, _ := testServer(t, nil) // AllowCIDRExpandIPv4 defaults false
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/?scope=24", nil)
	r.RemoteAddr = "1.2.3.4:1111"
	r.SetBasicAuth("admin", "secret")
	srv.Handler().ServeHTTP(rec, r)
	snap := srv.store.Snapshot(srv.now())
	if len(snap) != 1 || snap[0].CIDR != "1.2.3.4/32" {
		t.Fatalf("scope=24 must be ignored when disabled, got %+v", snap)
	}
}

func TestExpand24EnabledIPv4Only(t *testing.T) {
	srv, _ := testServer(t, func(c *config.ServerConfig) {
		c.AllowCIDRExpandIPv4 = true
	})
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/?scope=24", nil)
	r.RemoteAddr = "1.2.3.4:1111"
	r.SetBasicAuth("admin", "secret")
	srv.Handler().ServeHTTP(rec, r)
	snap := srv.store.Snapshot(srv.now())
	if len(snap) != 1 || snap[0].CIDR != "1.2.3.0/24" {
		t.Fatalf("scope=24 should widen IPv4, got %+v", snap)
	}
	if !strings.Contains(rec.Body.String(), "风险") {
		t.Fatal("/24 response must contain a risk warning")
	}
}

func TestIPv6DisabledByDefault(t *testing.T) {
	srv, _ := testServer(t, nil) // AllowIPv6 false
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.RemoteAddr = "[2001:db8::1]:1111"
	r.SetBasicAuth("admin", "secret")
	srv.Handler().ServeHTTP(rec, r)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("ipv6 must be forbidden by default, got %d", rec.Code)
	}
	if srv.store.Count() != 0 {
		t.Fatal("ipv6 disallowed must not record")
	}
}

func TestIPv6EnabledRecords128(t *testing.T) {
	srv, _ := testServer(t, func(c *config.ServerConfig) {
		c.AllowIPv6 = true
	})
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.RemoteAddr = "[2001:db8::1]:1111"
	r.SetBasicAuth("admin", "secret")
	srv.Handler().ServeHTTP(rec, r)
	snap := srv.store.Snapshot(srv.now())
	if len(snap) != 1 || snap[0].CIDR != "2001:db8::1/128" {
		t.Fatalf("ipv6 must record /128, got %+v", snap)
	}
}

func TestAllowJSONRequiresBearer(t *testing.T) {
	srv, _ := testServer(t, nil)
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/allow.json", nil)
	srv.Handler().ServeHTTP(rec, r)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("allow.json must require bearer, got %d", rec.Code)
	}
}

func TestAllowExportsSetNoStore(t *testing.T) {
	srv, _ := testServer(t, nil)
	for _, path := range []string{"/allow.json", "/allow.txt"} {
		rec := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, path, nil)
		r.Header.Set("Authorization", "Bearer pull-tok")
		srv.Handler().ServeHTTP(rec, r)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s want 200, got %d", path, rec.Code)
		}
		if got := rec.Header().Get("Cache-Control"); got != "no-store" {
			t.Fatalf("%s Cache-Control = %q, want no-store", path, got)
		}
	}
}

func TestAllowJSONSignedAndVerifiable(t *testing.T) {
	srv, _ := testServer(t, nil)
	// Seed an entry.
	r0 := httptest.NewRequest(http.MethodPost, "/", nil)
	r0.RemoteAddr = "1.2.3.4:1111"
	r0.SetBasicAuth("admin", "secret")
	srv.Handler().ServeHTTP(httptest.NewRecorder(), r0)

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/allow.json", nil)
	r.Header.Set("Authorization", "Bearer pull-tok")
	srv.Handler().ServeHTTP(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	var env signer.Envelope
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	if !signer.Verify(&env, []byte("hmac-secret")) {
		t.Fatal("exported allow.json must verify with the configured secret")
	}
}

func TestHealth(t *testing.T) {
	srv, _ := testServer(t, nil)
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/health", nil)
	srv.Handler().ServeHTTP(rec, r)
	if rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != "ok" {
		t.Fatalf("health should return ok, got %d %q", rec.Code, rec.Body.String())
	}
}

func TestAuditNeverContainsPassword(t *testing.T) {
	srv, buf := testServer(t, nil)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "1.2.3.4:1111"
	r.SetBasicAuth("admin", "super-secret-password")
	srv.Handler().ServeHTTP(httptest.NewRecorder(), r)
	if strings.Contains(buf.String(), "super-secret-password") {
		t.Fatal("audit log must never contain the password")
	}
	if strings.Contains(buf.String(), "pull-tok") || strings.Contains(buf.String(), "hmac-secret") {
		t.Fatal("audit log must never contain token/secret")
	}
}

func TestRateLimitUsesResolvedClientIP(t *testing.T) {
	srv, _ := testServer(t, func(c *config.ServerConfig) {
		c.TrustedProxyCIDRs = []string{"127.0.0.1/32"}
		c.RateLimit.MaxFailuresPerMinute = 1
	})

	request := func(clientIP string) int {
		rec := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = "127.0.0.1:1111"
		r.Header.Set("CF-Connecting-IP", clientIP)
		r.SetBasicAuth("admin", "wrong")
		srv.Handler().ServeHTTP(rec, r)
		return rec.Code
	}

	if got := request("1.1.1.1"); got != http.StatusUnauthorized {
		t.Fatalf("first client got %d", got)
	}
	if got := request("2.2.2.2"); got != http.StatusUnauthorized {
		t.Fatalf("second client shared proxy bucket, got %d", got)
	}
	if got := request("1.1.1.1"); got != http.StatusTooManyRequests {
		t.Fatalf("first client second failure got %d", got)
	}
}

func TestWriteTimeoutAccountsForSerialPush(t *testing.T) {
	base := &config.ServerConfig{}
	if got := writeTimeout(base); got != 15*time.Second {
		t.Fatalf("push disabled: write timeout = %s, want 15s", got)
	}

	withPush := &config.ServerConfig{Push: config.PushConfig{
		Enabled:        true,
		TimeoutSeconds: 10,
		Targets: []config.PushTarget{
			{Name: "a"}, {Name: "b"}, {Name: "c"},
		},
	}}
	// 15s base + 3 targets * 10s worst-case serial push.
	want := 15*time.Second + 3*10*time.Second
	if got := writeTimeout(withPush); got != want {
		t.Fatalf("push enabled: write timeout = %s, want %s", got, want)
	}

	// Enabled but no targets must not extend the deadline.
	empty := &config.ServerConfig{Push: config.PushConfig{Enabled: true, TimeoutSeconds: 10}}
	if got := writeTimeout(empty); got != 15*time.Second {
		t.Fatalf("push enabled with no targets: write timeout = %s, want 15s", got)
	}
}
