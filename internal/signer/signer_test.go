package signer

import (
	"encoding/json"
	"testing"
	"time"
)

func sampleEnvelope() *Envelope {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	return &Envelope{
		Version:   1,
		IssuedAt:  t0,
		ExpiresAt: t0.Add(5 * time.Minute),
		Entries: []Entry{
			{IP: "1.2.3.4", CIDR: "1.2.3.4/32", Source: "web_auth", CreatedAt: t0, ExpiresAt: t0.Add(time.Hour), LastSeenAt: t0, HitCount: 3},
			{IP: "5.6.7.8", CIDR: "5.6.7.8/32", Source: "web_auth", CreatedAt: t0, ExpiresAt: t0.Add(time.Hour), LastSeenAt: t0, HitCount: 1},
		},
	}
}

func TestSignVerifyOK(t *testing.T) {
	secret := []byte("test-secret")
	env := sampleEnvelope()
	if err := Sign(env, secret); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if env.Signature == "" {
		t.Fatal("signature not set")
	}
	if !Verify(env, secret) {
		t.Fatal("verify failed on valid envelope")
	}
}

func TestSignStable(t *testing.T) {
	secret := []byte("test-secret")
	a := sampleEnvelope()
	b := sampleEnvelope()
	if err := Sign(a, secret); err != nil {
		t.Fatal(err)
	}
	if err := Sign(b, secret); err != nil {
		t.Fatal(err)
	}
	if a.Signature != b.Signature {
		t.Fatalf("signature not stable: %s vs %s", a.Signature, b.Signature)
	}
}

func TestVerifyRoundTripJSON(t *testing.T) {
	secret := []byte("test-secret")
	env := sampleEnvelope()
	if err := Sign(env, secret); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	var got Envelope
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if !Verify(&got, secret) {
		t.Fatal("verify failed after JSON round-trip")
	}
}

func TestVerifyWrongSecret(t *testing.T) {
	env := sampleEnvelope()
	if err := Sign(env, []byte("secret-a")); err != nil {
		t.Fatal(err)
	}
	if Verify(env, []byte("secret-b")) {
		t.Fatal("verify should fail with wrong secret")
	}
}

func TestVerifyTampered(t *testing.T) {
	secret := []byte("test-secret")
	env := sampleEnvelope()
	if err := Sign(env, secret); err != nil {
		t.Fatal(err)
	}
	// Tamper after signing.
	env.Entries[0].CIDR = "9.9.9.9/32"
	if Verify(env, secret) {
		t.Fatal("verify should fail on tampered entry")
	}
}

func TestVerifyBadSignatureHex(t *testing.T) {
	secret := []byte("test-secret")
	env := sampleEnvelope()
	env.Signature = "not-hex-zz"
	if Verify(env, secret) {
		t.Fatal("verify should fail on non-hex signature")
	}
}
