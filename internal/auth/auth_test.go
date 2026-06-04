package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestConstantTimeEqual(t *testing.T) {
	if !ConstantTimeEqual("hunter2", "hunter2") {
		t.Fatal("equal strings should match")
	}
	if ConstantTimeEqual("hunter2", "hunter3") {
		t.Fatal("different strings should not match")
	}
	if ConstantTimeEqual("short", "a-much-longer-string") {
		t.Fatal("different-length strings should not match")
	}
	if !ConstantTimeEqual("", "") {
		t.Fatal("empty strings should match")
	}
}

func TestCheckBasicAuth(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.SetBasicAuth("admin", "secret")
	if !CheckBasicAuth(r, "admin", "secret") {
		t.Fatal("valid basic auth should pass")
	}
	if CheckBasicAuth(r, "admin", "wrong") {
		t.Fatal("wrong password should fail")
	}
	if CheckBasicAuth(r, "root", "secret") {
		t.Fatal("wrong username should fail")
	}

	noAuth := httptest.NewRequest(http.MethodGet, "/", nil)
	if CheckBasicAuth(noAuth, "admin", "secret") {
		t.Fatal("missing auth header should fail")
	}
}

func TestCheckBearer(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/allow.json", nil)
	r.Header.Set("Authorization", "Bearer tok-123")
	if !CheckBearer(r, "tok-123") {
		t.Fatal("valid bearer should pass")
	}
	if CheckBearer(r, "tok-456") {
		t.Fatal("wrong token should fail")
	}

	bad := httptest.NewRequest(http.MethodGet, "/allow.json", nil)
	bad.Header.Set("Authorization", "Basic xxx")
	if CheckBearer(bad, "tok-123") {
		t.Fatal("non-bearer scheme should fail")
	}
}

func TestClientIPDefaultRemoteAddr(t *testing.T) {
	e := NewRealIPExtractor(nil, "")
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "203.0.113.9:5555"
	r.Header.Set("X-Forwarded-For", "8.8.8.8")
	got := e.ClientIP(r)
	if got.String() != "203.0.113.9" {
		t.Fatalf("default must use RemoteAddr, got %s", got)
	}
}

func TestClientIPTrustedProxyHonoured(t *testing.T) {
	e := NewRealIPExtractor([]string{"10.0.0.1"}, "X-Forwarded-For")
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.0.0.1:443"
	r.Header.Set("X-Forwarded-For", "198.51.100.7, 10.0.0.1")
	got := e.ClientIP(r)
	if got.String() != "198.51.100.7" {
		t.Fatalf("trusted proxy XFF first hop should be used, got %s", got)
	}
}

func TestClientIPUntrustedPeerXFFIgnored(t *testing.T) {
	// Peer is NOT in trusted proxies: a forged X-Forwarded-For must be ignored.
	e := NewRealIPExtractor([]string{"10.0.0.1"}, "X-Forwarded-For")
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "203.0.113.9:5555" // attacker's real peer
	r.Header.Set("X-Forwarded-For", "8.8.8.8")
	got := e.ClientIP(r)
	if got.String() != "203.0.113.9" {
		t.Fatalf("forged XFF from untrusted peer must be ignored, got %s", got)
	}
}

func TestClientIPTrustedProxyBadHeaderFallsBack(t *testing.T) {
	e := NewRealIPExtractor([]string{"10.0.0.0/8"}, "X-Forwarded-For")
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.1.2.3:443"
	r.Header.Set("X-Forwarded-For", "garbage")
	got := e.ClientIP(r)
	if got.String() != "10.1.2.3" {
		t.Fatalf("invalid header should fall back to RemoteAddr, got %s", got)
	}
}
