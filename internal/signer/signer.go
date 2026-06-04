// Package signer defines the signed allow.json envelope and the HMAC-SHA256
// signing/verification used between auth-server and puller.
//
// The signature covers a canonical JSON form of the envelope that EXCLUDES the
// signature field itself. Because the canonical form is produced by marshaling
// a fixed Go struct (deterministic field order) and the entry list is sorted by
// the producer, the bytes are stable across producer and consumer.
package signer

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"
)

// Entry is a single authenticated source record.
type Entry struct {
	IP         string    `json:"ip"`
	CIDR       string    `json:"cidr"`
	Source     string    `json:"source"`
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	LastSeenAt time.Time `json:"last_seen_at"`
	HitCount   int       `json:"hit_count"`
}

// Envelope is the signed document exported by auth-server.
type Envelope struct {
	Version   int       `json:"version"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Entries   []Entry   `json:"entries"`
	Signature string    `json:"signature"`
}

// canonicalPayload mirrors Envelope but omits the signature field. It is the
// exact set of bytes that get signed.
type canonicalPayload struct {
	Version   int       `json:"version"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Entries   []Entry   `json:"entries"`
}

// Canonical returns the deterministic bytes that the signature is computed over.
func Canonical(env *Envelope) ([]byte, error) {
	return json.Marshal(canonicalPayload{
		Version:   env.Version,
		IssuedAt:  env.IssuedAt,
		ExpiresAt: env.ExpiresAt,
		Entries:   env.Entries,
	})
}

// Sign computes the HMAC-SHA256 over the canonical form and stores it (hex) in
// env.Signature.
func Sign(env *Envelope, secret []byte) error {
	b, err := Canonical(env)
	if err != nil {
		return err
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(b)
	env.Signature = hex.EncodeToString(mac.Sum(nil))
	return nil
}

// Verify recomputes the HMAC over the canonical form and compares it against the
// stored signature in constant time. It returns false on any decode error or
// mismatch.
func Verify(env *Envelope, secret []byte) bool {
	b, err := Canonical(env)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(b)
	expected := mac.Sum(nil)

	got, err := hex.DecodeString(env.Signature)
	if err != nil {
		return false
	}
	return hmac.Equal(expected, got)
}
