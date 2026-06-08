// Package clientip extracts a request's client IP while only trusting proxy
// headers from explicitly configured proxy CIDRs.
package clientip

import (
	"net"
	"net/http"
	"strings"
)

const (
	SourceRemoteAddr     = "remote_addr"
	SourceCFConnectingIP = "cf-connecting-ip"
	SourceXRealIP        = "x-real-ip"
	SourceXForwardedFor  = "x-forwarded-for"
)

// Config controls trusted-proxy-aware client IP extraction.
type Config struct {
	TrustedProxyCIDRs []string
	Headers           []string
}

// Result describes the selected client IP and where it came from.
type Result struct {
	ClientIP net.IP
	Source   string
	RemoteIP net.IP
}

// Extractor resolves client IPs from requests.
type Extractor struct {
	trusted []*net.IPNet
	headers []string
}

// DefaultHeaders returns the built-in proxy header priority.
func DefaultHeaders() []string {
	return []string{"CF-Connecting-IP", "X-Real-IP", "X-Forwarded-For"}
}

// New builds an Extractor. A nil Headers slice uses DefaultHeaders; an explicit
// empty slice disables header extraction.
func New(c Config) *Extractor {
	headers := c.Headers
	if headers == nil {
		headers = DefaultHeaders()
	}
	return &Extractor{
		trusted: parseTrusted(c.TrustedProxyCIDRs),
		headers: normalizeHeaders(headers),
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

func normalizeHeaders(headers []string) []string {
	out := make([]string, 0, len(headers))
	for _, h := range headers {
		h = strings.TrimSpace(h)
		if h != "" {
			out = append(out, h)
		}
	}
	return out
}

func remoteIP(remoteAddr string) net.IP {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	return net.ParseIP(strings.TrimSpace(host))
}

func (e *Extractor) peerTrusted(ip net.IP) bool {
	for _, n := range e.trusted {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// Extract returns the client IP for r. It only consults configured headers when
// RemoteAddr is inside a trusted proxy CIDR. Header failures fall back to the
// next configured header, then RemoteAddr.
func (e *Extractor) Extract(r *http.Request) Result {
	remote := remoteIP(r.RemoteAddr)
	res := Result{
		ClientIP: remote,
		Source:   SourceRemoteAddr,
		RemoteIP: remote,
	}
	if remote == nil || len(e.trusted) == 0 || !e.peerTrusted(remote) {
		return res
	}

	for _, header := range e.headers {
		value := r.Header.Get(header)
		if strings.TrimSpace(value) == "" {
			continue
		}
		source := sourceForHeader(header)
		var ip net.IP
		if source == SourceXForwardedFor {
			ip = parseXForwardedFor(value)
		} else {
			ip = parseSingleIP(value)
		}
		if ip != nil {
			res.ClientIP = ip
			res.Source = source
			return res
		}
	}
	return res
}

func sourceForHeader(header string) string {
	switch {
	case strings.EqualFold(header, "CF-Connecting-IP"):
		return SourceCFConnectingIP
	case strings.EqualFold(header, "X-Real-IP"):
		return SourceXRealIP
	case strings.EqualFold(header, "X-Forwarded-For"):
		return SourceXForwardedFor
	default:
		return strings.ToLower(strings.TrimSpace(header))
	}
}

func parseSingleIP(value string) net.IP {
	return net.ParseIP(strings.TrimSpace(value))
}

func parseXForwardedFor(value string) net.IP {
	for _, part := range strings.Split(value, ",") {
		if ip := net.ParseIP(strings.TrimSpace(part)); ip != nil {
			return ip
		}
	}
	return nil
}
