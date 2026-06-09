package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTempConfig(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "puller.json")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// Old configs without a "source" field must keep working and default to http.
func TestLoadPullerConfigDefaultsSourceHTTP(t *testing.T) {
	p := writeTempConfig(t, `{
	  "server_url": "https://auth.example.com/allow.json",
	  "pull_token": "tok",
	  "hmac_secret": "secret",
	  "output_allow_txt": "/tmp/allow.txt"
	}`)
	c, err := LoadPullerConfig(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if c.Source != "http" {
		t.Fatalf("source = %q, want http", c.Source)
	}
}

// source=file parses with empty server_url/pull_token and ignores require_https.
func TestLoadPullerConfigFileSource(t *testing.T) {
	p := writeTempConfig(t, `{
	  "source": "file",
	  "input_allow_json": "/var/lib/nft-auth-whitelist/inbox/allow.json",
	  "server_url": "",
	  "pull_token": "",
	  "hmac_secret": "secret",
	  "output_allow_txt": "/tmp/allow.txt",
	  "require_https": true
	}`)
	c, err := LoadPullerConfig(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if c.Source != "file" {
		t.Fatalf("source = %q, want file", c.Source)
	}
	if c.InputAllowJSON == "" {
		t.Fatal("input_allow_json should be set")
	}
}

func TestLoadPullerConfigFileSourceRequiresInput(t *testing.T) {
	p := writeTempConfig(t, `{
	  "source": "file",
	  "input_allow_json": "",
	  "hmac_secret": "secret",
	  "output_allow_txt": "/tmp/allow.txt"
	}`)
	_, err := LoadPullerConfig(p)
	if err == nil || !strings.Contains(err.Error(), "input_allow_json") {
		t.Fatalf("expected input_allow_json error, got %v", err)
	}
}

func TestLoadPullerConfigInvalidSource(t *testing.T) {
	p := writeTempConfig(t, `{
	  "source": "ftp",
	  "hmac_secret": "secret",
	  "output_allow_txt": "/tmp/allow.txt"
	}`)
	_, err := LoadPullerConfig(p)
	if err == nil || !strings.Contains(err.Error(), "source must be") {
		t.Fatalf("expected invalid source error, got %v", err)
	}
}

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
