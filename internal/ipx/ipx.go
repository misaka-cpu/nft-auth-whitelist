// Package ipx contains the IP / CIDR validation and normalization helpers.
//
// Two important invariants for this project live here:
//   - users never submit an IP; only the request source IP is turned into a CIDR
//     (CIDRForRequest), and
//   - the puller only accepts CIDRs that pass CanonicalCIDR for the allowed
//     families, so a misbehaving server cannot inject arbitrary strings.
package ipx

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// ParseIP parses a bare IP literal (no port, no CIDR).
func ParseIP(s string) (net.IP, error) {
	ip := net.ParseIP(strings.TrimSpace(s))
	if ip == nil {
		return nil, fmt.Errorf("invalid ip: %q", s)
	}
	return ip, nil
}

// IsIPv4 reports whether ip is an IPv4 address.
func IsIPv4(ip net.IP) bool { return ip.To4() != nil }

// CIDRForRequest converts an authenticated request's source IP into the CIDR to
// record.
//
//   - IPv4 defaults to /32. It is widened to /24 only when both expand24 and
//     allowExpand are true.
//   - IPv6 is always recorded as /128 (never auto-expanded to /64).
//
// The relevant family must be allowed or an error is returned.
func CIDRForRequest(ip net.IP, expand24, allowExpand, allowV4, allowV6 bool) (string, error) {
	if ip == nil {
		return "", fmt.Errorf("nil ip")
	}
	if v4 := ip.To4(); v4 != nil {
		if !allowV4 {
			return "", fmt.Errorf("ipv4 not allowed")
		}
		if expand24 && allowExpand {
			masked := v4.Mask(net.CIDRMask(24, 32))
			return masked.String() + "/24", nil
		}
		return v4.String() + "/32", nil
	}
	// IPv6
	if !allowV6 {
		return "", fmt.Errorf("ipv6 not allowed")
	}
	return ip.String() + "/128", nil
}

// CanonicalCIDR validates a CIDR string against the allowed families and returns
// its canonical (network-masked) form. It is used by the puller to filter the
// entries received from the server. Anything that is not a well formed CIDR of
// an allowed family is rejected.
func CanonicalCIDR(s string, allowV4, allowV6 bool) (string, bool) {
	_, ipnet, err := net.ParseCIDR(strings.TrimSpace(s))
	if err != nil {
		return "", false
	}
	ones, bits := ipnet.Mask.Size()
	switch bits {
	case 32:
		if !allowV4 {
			return "", false
		}
	case 128:
		if !allowV6 {
			return "", false
		}
	default:
		return "", false
	}
	return ipnet.IP.String() + "/" + strconv.Itoa(ones), true
}

// FamilyOfCIDR returns "ipv4", "ipv6" or "" for an invalid CIDR.
func FamilyOfCIDR(s string) string {
	_, ipnet, err := net.ParseCIDR(strings.TrimSpace(s))
	if err != nil {
		return ""
	}
	if _, bits := ipnet.Mask.Size(); bits == 32 {
		return "ipv4"
	}
	return "ipv6"
}
