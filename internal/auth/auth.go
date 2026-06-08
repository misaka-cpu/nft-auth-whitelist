// Package auth provides constant-time credential checks (Basic Auth + bearer
// token). It also keeps a small compatibility wrapper for the older real-IP
// extractor API; new code should use internal/clientip directly.
package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"net"
	"net/http"
	"strings"

	"github.com/misaka-cpu/nft-auth-whitelist/internal/clientip"
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

// RealIPExtractor resolves the client source IP using the legacy single-header
// API. It is retained for compatibility with older internal callers.
type RealIPExtractor struct {
	inner *clientip.Extractor
}

// NewRealIPExtractor builds an extractor. trustedProxies may contain bare IPs or
// CIDRs; an empty header or empty trusted list disables header trust entirely.
func NewRealIPExtractor(trustedProxies []string, header string) *RealIPExtractor {
	headers := []string{}
	if strings.TrimSpace(header) != "" {
		headers = []string{header}
	}
	return &RealIPExtractor{
		inner: clientip.New(clientip.Config{
			TrustedProxyCIDRs: trustedProxies,
			Headers:           headers,
		}),
	}
}

// ClientIP returns the source IP for r. It only consults the configured real-IP
// header when the direct peer is a trusted proxy; for X-Forwarded-For it takes
// the first (leftmost) value. Any failure falls back to the direct peer IP.
func (e *RealIPExtractor) ClientIP(r *http.Request) net.IP {
	if e == nil || e.inner == nil {
		return nil
	}
	return e.inner.Extract(r).ClientIP
}
