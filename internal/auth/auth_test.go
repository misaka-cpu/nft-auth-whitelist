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
