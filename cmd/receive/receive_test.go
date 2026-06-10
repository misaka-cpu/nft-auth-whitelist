package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/misaka-cpu/nft-auth-whitelist/internal/audit"
	"github.com/misaka-cpu/nft-auth-whitelist/internal/config"
	"github.com/misaka-cpu/nft-auth-whitelist/internal/pipeline"
	"github.com/misaka-cpu/nft-auth-whitelist/internal/signer"
)

const testSecret = "hmac-secret"

func validEntry(cidr, ip string) signer.Entry {
	now := time.Now().UTC()
	return signer.Entry{IP: ip, CIDR: cidr, Source: "web_auth", CreatedAt: now, ExpiresAt: now.Add(time.Hour), LastSeenAt: now, HitCount: 1}
}

func envWithEntries(entries []signer.Entry) *signer.Envelope {
	now := time.Now().UTC()
	return &signer.Envelope{Version: 1, IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute), Entries: entries}
}

// signedBytes signs env with secret and returns the marshalled envelope.
func signedBytes(t *testing.T, env *signer.Envelope, secret string) []byte {
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

func testReceiver(t *testing.T) (*receiver, *config.ReceiveConfig, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	dir := t.TempDir()
	cfg := &config.ReceiveConfig{
		InputMaxBytes:   1 << 20,
		InboxAllowJSON:  filepath.Join(dir, "inbox", "allow.json"),
		HMACSecret:      testSecret,
		OutputAllowTxt:  filepath.Join(dir, "allow.txt"),
		OutputStateJSON: filepath.Join(dir, "state.json"),
		MaxEntries:      10,
		AllowIPv4:       true,
		AllowIPv6:       false,
		Mode:            "export",
	}
	cfg.NFT.Table = "nft_auth_whitelist"
	auditBuf := &bytes.Buffer{}
	out := &bytes.Buffer{}
	r := newReceiver(cfg, audit.NewWithWriter(auditBuf))
	r.stdout = out
	return r, cfg, auditBuf, out
}

func TestReceiveSuccess(t *testing.T) {
	r, cfg, auditBuf, out := testReceiver(t)
	body := signedBytes(t, envWithEntries([]signer.Entry{validEntry("1.2.3.4/32", "1.2.3.4")}), testSecret)

	if err := r.run(bytes.NewReader(body)); err != nil {
		t.Fatalf("run: %v", err)
	}
	got, err := os.ReadFile(cfg.OutputAllowTxt)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(got)) != "1.2.3.4/32" {
		t.Fatalf("allow.txt = %q", string(got))
	}
	// Inbox copy written.
	inbox, err := os.ReadFile(cfg.InboxAllowJSON)
	if err != nil {
		t.Fatalf("inbox not written: %v", err)
	}
	if !bytes.Equal(inbox, body) {
		t.Fatal("inbox content must equal the received bytes")
	}
	// State json written and parseable.
	var st pipeline.State
	b, err := os.ReadFile(cfg.OutputStateJSON)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &st); err != nil {
		t.Fatal(err)
	}
	if st.Count != 1 || st.SourceURL != "stdin" {
		t.Fatalf("state = %+v", st)
	}
	// Audit records.
	a := auditBuf.String()
	for _, want := range []string{"receive.success", "signature.ok", "output.write.success"} {
		if !strings.Contains(a, want) {
			t.Errorf("audit missing %q", want)
		}
	}
	if !strings.HasPrefix(out.String(), "ok entries=1") {
		t.Fatalf("stdout = %q", out.String())
	}
}

func TestReceiveEmptyInputKeepsOld(t *testing.T) {
	r, cfg, auditBuf, _ := testReceiver(t)
	os.MkdirAll(filepath.Dir(cfg.OutputAllowTxt), 0o755)
	os.WriteFile(cfg.OutputAllowTxt, []byte("9.9.9.9/32\n"), 0o644)

	if err := r.run(bytes.NewReader(nil)); err == nil {
		t.Fatal("expected error on empty input")
	}
	assertPreserved(t, cfg.OutputAllowTxt)
	if !strings.Contains(auditBuf.String(), "receive.fail") {
		t.Error("audit should record receive.fail")
	}
}

func TestReceiveOversizedKeepsOld(t *testing.T) {
	r, cfg, _, _ := testReceiver(t)
	cfg.InputMaxBytes = 16
	os.MkdirAll(filepath.Dir(cfg.OutputAllowTxt), 0o755)
	os.WriteFile(cfg.OutputAllowTxt, []byte("9.9.9.9/32\n"), 0o644)

	big := bytes.Repeat([]byte("A"), 1024)
	if err := r.run(bytes.NewReader(big)); err == nil {
		t.Fatal("expected error on oversized input")
	}
	assertPreserved(t, cfg.OutputAllowTxt)
}

func TestReceiveInvalidJSONKeepsOld(t *testing.T) {
	r, cfg, _, _ := testReceiver(t)
	os.MkdirAll(filepath.Dir(cfg.OutputAllowTxt), 0o755)
	os.WriteFile(cfg.OutputAllowTxt, []byte("9.9.9.9/32\n"), 0o644)

	if err := r.run(bytes.NewReader([]byte("{ not json"))); err == nil {
		t.Fatal("expected error on invalid json")
	}
	assertPreserved(t, cfg.OutputAllowTxt)
}

func TestReceiveBadSignatureKeepsOldAndInbox(t *testing.T) {
	r, cfg, auditBuf, _ := testReceiver(t)
	os.MkdirAll(filepath.Dir(cfg.OutputAllowTxt), 0o755)
	os.WriteFile(cfg.OutputAllowTxt, []byte("9.9.9.9/32\n"), 0o644)
	os.MkdirAll(filepath.Dir(cfg.InboxAllowJSON), 0o755)
	os.WriteFile(cfg.InboxAllowJSON, []byte(`{"old":"inbox"}`), 0o644)

	body := signedBytes(t, envWithEntries([]signer.Entry{validEntry("1.2.3.4/32", "1.2.3.4")}), "wrong-secret")
	if err := r.run(bytes.NewReader(body)); err == nil {
		t.Fatal("expected signature failure")
	}
	assertPreserved(t, cfg.OutputAllowTxt)
	// Inbox must not be overwritten on signature failure.
	inbox, _ := os.ReadFile(cfg.InboxAllowJSON)
	if string(inbox) != `{"old":"inbox"}` {
		t.Fatalf("inbox must be preserved, got %q", string(inbox))
	}
	if !strings.Contains(auditBuf.String(), "signature.fail") {
		t.Error("audit should record signature.fail")
	}
}

func TestReceiveExpiredEnvelopeKeepsOld(t *testing.T) {
	r, cfg, _, _ := testReceiver(t)
	os.MkdirAll(filepath.Dir(cfg.OutputAllowTxt), 0o755)
	os.WriteFile(cfg.OutputAllowTxt, []byte("9.9.9.9/32\n"), 0o644)

	now := time.Now().UTC()
	env := &signer.Envelope{
		Version:   1,
		IssuedAt:  now.Add(-2 * time.Hour),
		ExpiresAt: now.Add(-time.Minute), // already expired
		Entries:   []signer.Entry{validEntry("1.2.3.4/32", "1.2.3.4")},
	}
	body := signedBytes(t, env, testSecret)
	if err := r.run(bytes.NewReader(body)); err == nil {
		t.Fatal("expected expired-envelope error")
	}
	assertPreserved(t, cfg.OutputAllowTxt)
}

func TestReceiveIPv6DroppedByDefault(t *testing.T) {
	r, cfg, _, _ := testReceiver(t)
	// IPv6 disabled (default): the v6 entry must be filtered out, v4 kept.
	entries := []signer.Entry{
		validEntry("1.2.3.4/32", "1.2.3.4"),
		validEntry("2001:db8::1/128", "2001:db8::1"),
	}
	body := signedBytes(t, envWithEntries(entries), testSecret)
	if err := r.run(bytes.NewReader(body)); err != nil {
		t.Fatalf("run: %v", err)
	}
	got, _ := os.ReadFile(cfg.OutputAllowTxt)
	if strings.Contains(string(got), "2001:db8") {
		t.Fatal("ipv6 entry must be dropped when allow_ipv6=false")
	}
	if !strings.Contains(string(got), "1.2.3.4/32") {
		t.Fatal("ipv4 entry must be kept")
	}
}

func TestReceiveNoSecretsInOutput(t *testing.T) {
	r, _, auditBuf, out := testReceiver(t)
	body := signedBytes(t, envWithEntries([]signer.Entry{validEntry("1.2.3.4/32", "1.2.3.4")}), testSecret)
	_ = r.run(bytes.NewReader(body))
	if strings.Contains(auditBuf.String(), testSecret) || strings.Contains(out.String(), testSecret) {
		t.Fatal("audit/stdout must not contain the hmac secret")
	}
}

// assertPreserved fails if the seeded old allow.txt was changed.
func assertPreserved(t *testing.T, path string) {
	t.Helper()
	got, _ := os.ReadFile(path)
	if strings.TrimSpace(string(got)) != "9.9.9.9/32" {
		t.Fatalf("old allow.txt must be preserved, got %q", string(got))
	}
}
