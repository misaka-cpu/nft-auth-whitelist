package clientip

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func requestWithRemote(remote string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = remote
	return r
}

func TestNoTrustedProxyCIDRsIgnoresForgedHeader(t *testing.T) {
	e := New(Config{})
	r := requestWithRemote("9.9.9.9:12345")
	r.Header.Set("CF-Connecting-IP", "1.2.3.4")

	got := e.Extract(r)
	if got.ClientIP.String() != "9.9.9.9" {
		t.Fatalf("client ip = %s, want RemoteAddr", got.ClientIP)
	}
	if got.Source != SourceRemoteAddr {
		t.Fatalf("source = %s, want %s", got.Source, SourceRemoteAddr)
	}
}

func TestTrustedProxyUsesCFConnectingIP(t *testing.T) {
	e := New(Config{TrustedProxyCIDRs: []string{"127.0.0.1/32"}})
	r := requestWithRemote("127.0.0.1:12345")
	r.Header.Set("CF-Connecting-IP", "1.2.3.4")

	got := e.Extract(r)
	if got.ClientIP.String() != "1.2.3.4" {
		t.Fatalf("client ip = %s, want 1.2.3.4", got.ClientIP)
	}
	if got.Source != SourceCFConnectingIP {
		t.Fatalf("source = %s, want %s", got.Source, SourceCFConnectingIP)
	}
	if got.RemoteIP.String() != "127.0.0.1" {
		t.Fatalf("remote ip = %s, want 127.0.0.1", got.RemoteIP)
	}
}

func TestUntrustedPeerIgnoresCFConnectingIP(t *testing.T) {
	e := New(Config{TrustedProxyCIDRs: []string{"127.0.0.1/32"}})
	r := requestWithRemote("9.9.9.9:12345")
	r.Header.Set("CF-Connecting-IP", "1.2.3.4")

	got := e.Extract(r)
	if got.ClientIP.String() != "9.9.9.9" {
		t.Fatalf("client ip = %s, want untrusted RemoteAddr", got.ClientIP)
	}
	if got.Source != SourceRemoteAddr {
		t.Fatalf("source = %s, want %s", got.Source, SourceRemoteAddr)
	}
}

func TestHeaderPriorityPrefersCFConnectingIP(t *testing.T) {
	e := New(Config{TrustedProxyCIDRs: []string{"127.0.0.1/32"}})
	r := requestWithRemote("127.0.0.1:12345")
	r.Header.Set("CF-Connecting-IP", "1.2.3.4")
	r.Header.Set("X-Real-IP", "5.6.7.8")
	r.Header.Set("X-Forwarded-For", "9.9.9.9")

	got := e.Extract(r)
	if got.ClientIP.String() != "1.2.3.4" {
		t.Fatalf("client ip = %s, want CF-Connecting-IP", got.ClientIP)
	}
	if got.Source != SourceCFConnectingIP {
		t.Fatalf("source = %s, want %s", got.Source, SourceCFConnectingIP)
	}
}

func TestInvalidCFConnectingIPFallsThrough(t *testing.T) {
	e := New(Config{TrustedProxyCIDRs: []string{"127.0.0.1/32"}})
	r := requestWithRemote("127.0.0.1:12345")
	r.Header.Set("CF-Connecting-IP", "not-an-ip")
	r.Header.Set("X-Real-IP", "5.6.7.8")

	got := e.Extract(r)
	if got.ClientIP.String() != "5.6.7.8" {
		t.Fatalf("client ip = %s, want X-Real-IP fallback", got.ClientIP)
	}
	if got.Source != SourceXRealIP {
		t.Fatalf("source = %s, want %s", got.Source, SourceXRealIP)
	}
}

func TestXForwardedForUsesFirstValidIP(t *testing.T) {
	e := New(Config{TrustedProxyCIDRs: []string{"127.0.0.1/32"}})
	r := requestWithRemote("127.0.0.1:12345")
	r.Header.Set("X-Forwarded-For", "1.2.3.4, 5.6.7.8")

	got := e.Extract(r)
	if got.ClientIP.String() != "1.2.3.4" {
		t.Fatalf("client ip = %s, want first X-Forwarded-For IP", got.ClientIP)
	}
	if got.Source != SourceXForwardedFor {
		t.Fatalf("source = %s, want %s", got.Source, SourceXForwardedFor)
	}
}

func TestXForwardedForSkipsInvalidParts(t *testing.T) {
	e := New(Config{TrustedProxyCIDRs: []string{"127.0.0.1/32"}})
	r := requestWithRemote("127.0.0.1:12345")
	r.Header.Set("X-Forwarded-For", "garbage, 5.6.7.8")

	got := e.Extract(r)
	if got.ClientIP.String() != "5.6.7.8" {
		t.Fatalf("client ip = %s, want first valid X-Forwarded-For IP", got.ClientIP)
	}
}

func TestIPv6HeaderExtraction(t *testing.T) {
	e := New(Config{TrustedProxyCIDRs: []string{"::1/128"}})
	r := requestWithRemote("[::1]:12345")
	r.Header.Set("CF-Connecting-IP", "2001:db8::1")

	got := e.Extract(r)
	if got.ClientIP.String() != "2001:db8::1" {
		t.Fatalf("client ip = %s, want IPv6 header IP", got.ClientIP)
	}
	if got.Source != SourceCFConnectingIP {
		t.Fatalf("source = %s, want %s", got.Source, SourceCFConnectingIP)
	}
}

func TestAllHeadersInvalidFallsBackToRemoteAddr(t *testing.T) {
	e := New(Config{TrustedProxyCIDRs: []string{"127.0.0.1/32"}})
	r := requestWithRemote("127.0.0.1:12345")
	r.Header.Set("CF-Connecting-IP", "not-an-ip")
	r.Header.Set("X-Real-IP", "also-not-an-ip")
	r.Header.Set("X-Forwarded-For", "bad, worse")

	got := e.Extract(r)
	if got.ClientIP.String() != "127.0.0.1" {
		t.Fatalf("client ip = %s, want RemoteAddr fallback", got.ClientIP)
	}
	if got.Source != SourceRemoteAddr {
		t.Fatalf("source = %s, want %s", got.Source, SourceRemoteAddr)
	}
}
