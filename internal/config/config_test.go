package config

import "testing"

func TestEffectiveClientIPHeadersDefaultForNewTrustedProxyCIDRs(t *testing.T) {
	c := &ServerConfig{TrustedProxyCIDRs: []string{"127.0.0.1/32"}}
	got := c.EffectiveClientIPHeaders()
	want := []string{"CF-Connecting-IP", "X-Real-IP", "X-Forwarded-For"}
	if len(got) != len(want) {
		t.Fatalf("headers = %#v, want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("headers = %#v, want %#v", got, want)
		}
	}
}

func TestEffectiveClientIPHeadersPreservesLegacyRealIPHeader(t *testing.T) {
	c := &ServerConfig{
		TrustedProxies: []string{"10.0.0.1"},
		RealIPHeader:   "X-Forwarded-For",
	}
	got := c.EffectiveClientIPHeaders()
	if len(got) != 1 || got[0] != "X-Forwarded-For" {
		t.Fatalf("headers = %#v, want legacy single header", got)
	}
}

func TestLegacyTrustedProxiesAloneDoNotEnableHeaders(t *testing.T) {
	c := &ServerConfig{TrustedProxies: []string{"10.0.0.1"}}
	if got := c.EffectiveClientIPHeaders(); len(got) != 0 {
		t.Fatalf("legacy trusted_proxies alone must not enable default headers, got %#v", got)
	}
}

func TestEffectiveTrustedProxyCIDRsIncludesLegacyEntries(t *testing.T) {
	c := &ServerConfig{
		TrustedProxyCIDRs: []string{"127.0.0.1/32"},
		TrustedProxies:    []string{"10.0.0.1"},
	}
	got := c.EffectiveTrustedProxyCIDRs()
	want := []string{"127.0.0.1/32", "10.0.0.1"}
	if len(got) != len(want) {
		t.Fatalf("trusted proxies = %#v, want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("trusted proxies = %#v, want %#v", got, want)
		}
	}
}
