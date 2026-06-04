// Package auth provides constant-time credential checks (Basic Auth + bearer
// token) and trusted-proxy aware client IP extraction.
package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"net"
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

// RealIPExtractor resolves the client source IP. By default it uses
// RemoteAddr. A real-IP header is honoured ONLY when the immediate peer
// (RemoteAddr) is one of the configured trusted proxies. This is the guard
// against forged X-Forwarded-For headers from arbitrary public clients.
type RealIPExtractor struct {
	trusted []*net.IPNet
	header  string
}

// NewRealIPExtractor builds an extractor. trustedProxies may contain bare IPs or
// CIDRs; an empty header or empty trusted list disables header trust entirely.
func NewRealIPExtractor(trustedProxies []string, header string) *RealIPExtractor {
	return &RealIPExtractor{
		trusted: parseTrusted(trustedProxies),
		header:  strings.TrimSpace(header),
	}
}

func parseTrusted(list []string) []*net.IPNet {
	var out []*net.IPNet
	for _, s := range list {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if !strings.Contains(s, "/") {
			if strings.Contains(s, ":") {
				s += "/128"
			} else {
				s += "/32"
			}
		}
		if _, n, err := net.ParseCIDR(s); err == nil {
			out = append(out, n)
		}
	}
	return out
}

func (e *RealIPExtractor) peerTrusted(ip net.IP) bool {
	for _, n := range e.trusted {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// ClientIP returns the source IP for r. It only consults the configured real-IP
// header when the direct peer is a trusted proxy; for X-Forwarded-For it takes
// the first (leftmost) value. Any failure falls back to the direct peer IP.
func (e *RealIPExtractor) ClientIP(r *http.Request) net.IP {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	remoteIP := net.ParseIP(strings.TrimSpace(host))

	// Header trust is disabled unless explicitly configured AND the peer is trusted.
	if e.header == "" || len(e.trusted) == 0 || remoteIP == nil {
		return remoteIP
	}
	if !e.peerTrusted(remoteIP) {
		return remoteIP
	}

	hv := r.Header.Get(e.header)
	if hv == "" {
		return remoteIP
	}
	first := hv
	if i := strings.IndexByte(hv, ','); i >= 0 {
		first = hv[:i]
	}
	if parsed := net.ParseIP(strings.TrimSpace(first)); parsed != nil {
		return parsed
	}
	return remoteIP
}
