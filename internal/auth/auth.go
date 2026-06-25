// Package auth provides constant-time credential checks (Basic Auth + bearer
// token).
package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"net/http"
	"strings"
)

// ConstantTimeEqual compares two strings in constant time. The inputs are first
// hashed with SHA-256 so the comparison does not leak the secret's length.
func ConstantTimeEqual(a, b string) bool {
	ha := sha256.Sum256([]byte(a))
	hb := sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(ha[:], hb[:]) == 1
}

// CheckBasicAuth validates HTTP Basic Auth credentials in constant time. Both
// the username and password are always compared (no short-circuit) to avoid
// leaking which field was wrong.
func CheckBasicAuth(r *http.Request, username, password string) bool {
	u, p, ok := r.BasicAuth()
	if !ok {
		return false
	}
	okUser := ConstantTimeEqual(u, username)
	okPass := ConstantTimeEqual(p, password)
	return okUser && okPass
}

// CheckBearer validates an "Authorization: Bearer <token>" header in constant
// time.
func CheckBearer(r *http.Request, token string) bool {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, prefix) {
		return false
	}
	return ConstantTimeEqual(strings.TrimPrefix(h, prefix), token)
}
