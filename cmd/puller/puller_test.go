package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/misaka-cpu/nft-auth-whitelist/internal/audit"
	"github.com/misaka-cpu/nft-auth-whitelist/internal/config"
	"github.com/misaka-cpu/nft-auth-whitelist/internal/signer"
)

const testSecret = "hmac-secret"
const testToken = "pull-tok"

func mustSign(t *testing.T, env *signer.Envelope, secret string) []byte {
	t.Helper()
	if err := signer.Sign(env, []byte(secret)); err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func envWithEntries(entries []signer.Entry) *signer.Envelope {
	now := time.Now().UTC()
	return &signer.Envelope{
		Version:   1,
		IssuedAt:  now,
		ExpiresAt: now.Add(5 * time.Minute),
		Entries:   entries,
	}
}

func validEntry(cidr, ip string) signer.Entry {
	now := time.Now().UTC()
	return signer.Entry{IP: ip, CIDR: cidr, Source: "web_auth", CreatedAt: now, ExpiresAt: now.Add(time.Hour), LastSeenAt: now, HitCount: 1}
}

// bodyServer serves a fixed body to bearer-authenticated GETs.
func bodyServer(t *testing.T, body []byte) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+testToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
}

func testPuller(t *testing.T, serverURL string) (*puller, *config.PullerConfig, *bytes.Buffer) {
	t.Helper()
	dir := t.TempDir()
	cfg := &config.PullerConfig{
		ServerURL:       serverURL,
		PullToken:       testToken,
		HMACSecret:      testSecret,
		IntervalSeconds: 60,
		OutputAllowTxt:  filepath.Join(dir, "allow.txt"),
		OutputStateJSON: filepath.Join(dir, "state.json"),
		MaxEntries:      10,
		AllowIPv4:       true,
		AllowIPv6:       false,
		RequireHTTPS:    false, // test servers are http://
		Mode:            "export",
	}
	cfg.NFT.Table = "nft_auth_whitelist"
	buf := &bytes.Buffer{}
	p := newPuller(cfg, audit.NewWithWriter(buf))
	return p, cfg, buf
}

// testFilePuller builds a puller that reads a signed envelope from inputPath.
// require_https is intentionally left true to prove it is ignored for files,
// and server_url / pull_token are empty to prove the file path needs neither.
func testFilePuller(t *testing.T, inputPath string) (*puller, *config.PullerConfig, *bytes.Buffer) {
	t.Helper()
	dir := t.TempDir()
	cfg := &config.PullerConfig{
		Source:          "file",
		InputAllowJSON:  inputPath,
		HMACSecret:      testSecret,
		IntervalSeconds: 60,
		OutputAllowTxt:  filepath.Join(dir, "allow.txt"),
		OutputStateJSON: filepath.Join(dir, "state.json"),
		MaxEntries:      10,
		AllowIPv4:       true,
		AllowIPv6:       false,
		RequireHTTPS:    true, // must be ignored for source=file
		Mode:            "export",
	}
	cfg.NFT.Table = "nft_auth_whitelist"
	buf := &bytes.Buffer{}
	p := newPuller(cfg, audit.NewWithWriter(buf))
	return p, cfg, buf
}

// writeFile writes body to a fresh file in a temp dir and returns its path.
func writeFile(t *testing.T, name string, body []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, body, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPullerFileSourceSuccess(t *testing.T) {
	body := mustSign(t, envWithEntries([]signer.Entry{validEntry("1.2.3.4/32", "1.2.3.4")}), testSecret)
	in := writeFile(t, "allow.json", body)

	p, cfg, buf := testFilePuller(t, in)
	if err := p.runOnce(runOptions{}); err != nil {
		t.Fatalf("runOnce: %v", err)
	}
	got, err := os.ReadFile(cfg.OutputAllowTxt)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(got)) != "1.2.3.4/32" {
		t.Fatalf("allow.txt content = %q", string(got))
	}
	var st pulledState
	b, err := os.ReadFile(cfg.OutputStateJSON)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &st); err != nil {
		t.Fatal(err)
	}
	if st.Count != 1 {
		t.Fatalf("state count = %d", st.Count)
	}
	if !strings.HasPrefix(st.SourceURL, "file:") {
		t.Fatalf("state source = %q, want file: prefix", st.SourceURL)
	}
	if !strings.Contains(buf.String(), "pull.success") || !strings.Contains(buf.String(), "signature.ok") {
		t.Fatal("audit should record pull.success and signature.ok")
	}
}

func TestPullerFileSourceMissingFileKeepsOld(t *testing.T) {
	p, cfg, buf := testFilePuller(t, filepath.Join(t.TempDir(), "does-not-exist.json"))
	os.WriteFile(cfg.OutputAllowTxt, []byte("9.9.9.9/32\n"), 0o644)
	if err := p.runOnce(runOptions{}); err == nil {
		t.Fatal("expected error for missing input file")
	}
	got, _ := os.ReadFile(cfg.OutputAllowTxt)
	if strings.TrimSpace(string(got)) != "9.9.9.9/32" {
		t.Fatalf("old allow.txt must be preserved, got %q", string(got))
	}
	if !strings.Contains(buf.String(), "pull.fail") {
		t.Fatal("audit should record pull.fail")
	}
}

func TestPullerFileSourceBadSignatureKeepsOld(t *testing.T) {
	body := mustSign(t, envWithEntries([]signer.Entry{validEntry("1.2.3.4/32", "1.2.3.4")}), "wrong-secret")
	in := writeFile(t, "allow.json", body)

	p, cfg, buf := testFilePuller(t, in)
	os.WriteFile(cfg.OutputAllowTxt, []byte("9.9.9.9/32\n"), 0o644)
	if err := p.runOnce(runOptions{}); err == nil {
		t.Fatal("expected signature failure error")
	}
	got, _ := os.ReadFile(cfg.OutputAllowTxt)
	if strings.TrimSpace(string(got)) != "9.9.9.9/32" {
		t.Fatalf("old allow.txt must be preserved on signature failure, got %q", string(got))
	}
	if !strings.Contains(buf.String(), "signature.fail") {
		t.Fatal("audit should record signature.fail")
	}
}

func TestPullerFileSourceInvalidJSONKeepsOld(t *testing.T) {
	in := writeFile(t, "allow.json", []byte("{ this is not json"))

	p, cfg, _ := testFilePuller(t, in)
	os.WriteFile(cfg.OutputAllowTxt, []byte("9.9.9.9/32\n"), 0o644)
	if err := p.runOnce(runOptions{}); err == nil {
		t.Fatal("expected JSON parse error")
	}
	got, _ := os.ReadFile(cfg.OutputAllowTxt)
	if strings.TrimSpace(string(got)) != "9.9.9.9/32" {
		t.Fatalf("old allow.txt must be preserved on invalid json, got %q", string(got))
	}
}

func TestPullerSignatureOKWritesAllow(t *testing.T) {
	body := mustSign(t, envWithEntries([]signer.Entry{validEntry("1.2.3.4/32", "1.2.3.4")}), testSecret)
	srv := bodyServer(t, body)
	defer srv.Close()

	p, cfg, _ := testPuller(t, srv.URL)
	if err := p.runOnce(runOptions{}); err != nil {
		t.Fatalf("runOnce: %v", err)
	}
	got, err := os.ReadFile(cfg.OutputAllowTxt)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(got)) != "1.2.3.4/32" {
		t.Fatalf("allow.txt content = %q", string(got))
	}
}

func TestPullerSignatureFailRejected(t *testing.T) {
	// Signed with the WRONG secret.
	body := mustSign(t, envWithEntries([]signer.Entry{validEntry("1.2.3.4/32", "1.2.3.4")}), "wrong-secret")
	srv := bodyServer(t, body)
	defer srv.Close()

	p, cfg, buf := testPuller(t, srv.URL)
	// Seed an old allow.txt that must be preserved.
	os.WriteFile(cfg.OutputAllowTxt, []byte("9.9.9.9/32\n"), 0o644)

	if err := p.runOnce(runOptions{}); err == nil {
		t.Fatal("expected signature failure error")
	}
	got, _ := os.ReadFile(cfg.OutputAllowTxt)
	if strings.TrimSpace(string(got)) != "9.9.9.9/32" {
		t.Fatalf("old allow.txt must be preserved on signature failure, got %q", string(got))
	}
	if !strings.Contains(buf.String(), "signature.fail") {
		t.Fatal("audit should record signature.fail")
	}
}

func TestPullerTamperedRejected(t *testing.T) {
	env := envWithEntries([]signer.Entry{validEntry("1.2.3.4/32", "1.2.3.4")})
	signer.Sign(env, []byte(testSecret))
	env.Entries[0].CIDR = "6.6.6.6/32" // tamper after signing
	body, _ := json.Marshal(env)
	srv := bodyServer(t, body)
	defer srv.Close()

	p, cfg, _ := testPuller(t, srv.URL)
	os.WriteFile(cfg.OutputAllowTxt, []byte("9.9.9.9/32\n"), 0o644)
	if err := p.runOnce(runOptions{}); err == nil {
		t.Fatal("tampered envelope must be rejected")
	}
	got, _ := os.ReadFile(cfg.OutputAllowTxt)
	if strings.TrimSpace(string(got)) != "9.9.9.9/32" {
		t.Fatal("old allow.txt must be preserved on tamper")
	}
}

func TestPullerFetchFailKeepsOld(t *testing.T) {
	p, cfg, buf := testPuller(t, "http://127.0.0.1:1/allow.json") // nothing listening
	os.WriteFile(cfg.OutputAllowTxt, []byte("9.9.9.9/32\n"), 0o644)
	if err := p.runOnce(runOptions{}); err == nil {
		t.Fatal("expected fetch error")
	}
	got, _ := os.ReadFile(cfg.OutputAllowTxt)
	if strings.TrimSpace(string(got)) != "9.9.9.9/32" {
		t.Fatal("old allow.txt must be preserved on fetch failure")
	}
	if !strings.Contains(buf.String(), "pull.fail") {
		t.Fatal("audit should record pull.fail")
	}
}

func TestPullerExpiredEntryNotWritten(t *testing.T) {
	now := time.Now().UTC()
	expired := signer.Entry{IP: "5.5.5.5", CIDR: "5.5.5.5/32", Source: "web_auth", CreatedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Minute), LastSeenAt: now.Add(-time.Hour), HitCount: 1}
	body := mustSign(t, envWithEntries([]signer.Entry{validEntry("1.2.3.4/32", "1.2.3.4"), expired}), testSecret)
	srv := bodyServer(t, body)
	defer srv.Close()

	p, cfg, _ := testPuller(t, srv.URL)
	if err := p.runOnce(runOptions{}); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(cfg.OutputAllowTxt)
	if strings.Contains(string(got), "5.5.5.5") {
		t.Fatal("expired entry must not be written")
	}
	if !strings.Contains(string(got), "1.2.3.4/32") {
		t.Fatal("valid entry must be written")
	}
}

func TestPullerMaxEntriesRejected(t *testing.T) {
	entries := []signer.Entry{
		validEntry("1.1.1.1/32", "1.1.1.1"),
		validEntry("2.2.2.2/32", "2.2.2.2"),
		validEntry("3.3.3.3/32", "3.3.3.3"),
	}
	body := mustSign(t, envWithEntries(entries), testSecret)
	srv := bodyServer(t, body)
	defer srv.Close()

	p, cfg, _ := testPuller(t, srv.URL)
	cfg.MaxEntries = 2
	os.WriteFile(cfg.OutputAllowTxt, []byte("9.9.9.9/32\n"), 0o644)
	if err := p.runOnce(runOptions{}); err == nil {
		t.Fatal("oversized envelope must be rejected")
	}
	got, _ := os.ReadFile(cfg.OutputAllowTxt)
	if strings.TrimSpace(string(got)) != "9.9.9.9/32" {
		t.Fatal("old allow.txt preserved when rejecting oversized envelope")
	}
}

func TestPullerRequireHTTPSRejectsHTTP(t *testing.T) {
	p, cfg, _ := testPuller(t, "http://auth.example.com/allow.json")
	cfg.RequireHTTPS = true
	if err := p.runOnce(runOptions{}); err == nil {
		t.Fatal("require_https must reject http:// url")
	}
}

func TestPullerAtomicWriteAndState(t *testing.T) {
	body := mustSign(t, envWithEntries([]signer.Entry{validEntry("1.2.3.4/32", "1.2.3.4")}), testSecret)
	srv := bodyServer(t, body)
	defer srv.Close()

	p, cfg, _ := testPuller(t, srv.URL)
	if err := p.runOnce(runOptions{}); err != nil {
		t.Fatal(err)
	}
	// No leftover temp files in the output directory.
	dir := filepath.Dir(cfg.OutputAllowTxt)
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".tmp-") {
			t.Fatalf("leftover temp file: %s", e.Name())
		}
	}
	// State JSON written and parseable.
	b, err := os.ReadFile(cfg.OutputStateJSON)
	if err != nil {
		t.Fatal(err)
	}
	var st pulledState
	if err := json.Unmarshal(b, &st); err != nil {
		t.Fatal(err)
	}
	if st.Count != 1 {
		t.Fatalf("state count = %d", st.Count)
	}
}

func TestPullerTokenNotInAudit(t *testing.T) {
	body := mustSign(t, envWithEntries([]signer.Entry{validEntry("1.2.3.4/32", "1.2.3.4")}), testSecret)
	srv := bodyServer(t, body)
	defer srv.Close()

	p, _, buf := testPuller(t, srv.URL)
	p.runOnce(runOptions{})
	if strings.Contains(buf.String(), testToken) || strings.Contains(buf.String(), testSecret) {
		t.Fatal("audit log must not contain token or secret")
	}
}

func TestApplyIgnoredWhenGuardDisabled(t *testing.T) {
	body := mustSign(t, envWithEntries([]signer.Entry{validEntry("1.2.3.4/32", "1.2.3.4")}), testSecret)
	srv := bodyServer(t, body)
	defer srv.Close()

	p, cfg, buf := testPuller(t, srv.URL)
	// mode=export and nft.enabled=false -> apply must NOT be allowed.
	if p.applyAllowed() {
		t.Fatal("apply must not be allowed in export mode with guard disabled")
	}
	if err := p.runOnce(runOptions{Apply: true}); err != nil {
		t.Fatal(err)
	}
	// Export still happened.
	if _, err := os.ReadFile(cfg.OutputAllowTxt); err != nil {
		t.Fatal("export should still write allow.txt")
	}
	if !strings.Contains(buf.String(), "--apply ignored") {
		t.Fatal("audit/stdout should note that --apply was ignored")
	}
}

func TestApplyAllowedWhenEnabled(t *testing.T) {
	p, cfg, _ := testPuller(t, "http://x")
	cfg.NFT.Enabled = true
	if !p.applyAllowed() {
		t.Fatal("apply should be allowed when nft.enabled=true")
	}
	cfg.NFT.Enabled = false
	cfg.Mode = "nft"
	if !p.applyAllowed() {
		t.Fatal("apply should be allowed when mode=nft")
	}
}

func TestDryRunWritesNothing(t *testing.T) {
	body := mustSign(t, envWithEntries([]signer.Entry{validEntry("1.2.3.4/32", "1.2.3.4")}), testSecret)
	srv := bodyServer(t, body)
	defer srv.Close()

	p, cfg, _ := testPuller(t, srv.URL)
	out := &bytes.Buffer{}
	p.stdout = out
	if err := p.runOnce(runOptions{DryRun: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(cfg.OutputAllowTxt); !os.IsNotExist(err) {
		t.Fatal("dry-run must not write allow.txt")
	}
	if !strings.Contains(out.String(), "1.2.3.4/32") {
		t.Fatal("dry-run should print the would-be entries")
	}
	if strings.Contains(out.String(), "flush ruleset") {
		t.Fatal("dry-run nft script must not contain flush ruleset")
	}
}
