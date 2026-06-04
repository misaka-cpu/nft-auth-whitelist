package ipx

import (
	"net"
	"testing"
)

func TestCIDRForRequestIPv4Default32(t *testing.T) {
	ip := net.ParseIP("1.2.3.4")
	got, err := CIDRForRequest(ip, false, false, true, false)
	if err != nil {
		t.Fatal(err)
	}
	if got != "1.2.3.4/32" {
		t.Fatalf("want 1.2.3.4/32, got %s", got)
	}
}

func TestCIDRForRequestIPv4Expand24(t *testing.T) {
	ip := net.ParseIP("1.2.3.4")
	// expand requested AND allowed -> /24 masked to network.
	got, err := CIDRForRequest(ip, true, true, true, false)
	if err != nil {
		t.Fatal(err)
	}
	if got != "1.2.3.0/24" {
		t.Fatalf("want 1.2.3.0/24, got %s", got)
	}
}

func TestCIDRForRequestExpandDisabledStays32(t *testing.T) {
	ip := net.ParseIP("1.2.3.4")
	// expand requested but NOT allowed by config -> stays /32.
	got, err := CIDRForRequest(ip, true, false, true, false)
	if err != nil {
		t.Fatal(err)
	}
	if got != "1.2.3.4/32" {
		t.Fatalf("expand must be ignored when not allowed, got %s", got)
	}
}

func TestCIDRForRequestIPv6Default128(t *testing.T) {
	ip := net.ParseIP("2001:db8::1")
	got, err := CIDRForRequest(ip, true, true, false, true)
	if err != nil {
		t.Fatal(err)
	}
	if got != "2001:db8::1/128" {
		t.Fatalf("want /128, got %s (ipv6 must not auto-expand)", got)
	}
}

func TestCIDRForRequestIPv4NotAllowed(t *testing.T) {
	ip := net.ParseIP("1.2.3.4")
	if _, err := CIDRForRequest(ip, false, false, false, true); err == nil {
		t.Fatal("expected error when ipv4 disallowed")
	}
}

func TestCIDRForRequestIPv6NotAllowed(t *testing.T) {
	ip := net.ParseIP("2001:db8::1")
	if _, err := CIDRForRequest(ip, false, false, true, false); err == nil {
		t.Fatal("expected error when ipv6 disallowed")
	}
}

func TestCanonicalCIDR(t *testing.T) {
	cases := []struct {
		in     string
		v4, v6 bool
		want   string
		ok     bool
	}{
		{"1.2.3.4/32", true, false, "1.2.3.4/32", true},
		{"1.2.3.0/24", true, false, "1.2.3.0/24", true},
		{"1.2.3.4/24", true, false, "1.2.3.0/24", true}, // normalized to network
		{"2001:db8::1/128", false, true, "2001:db8::1/128", true},
		{"1.2.3.4/32", false, true, "", false},      // v4 disallowed
		{"2001:db8::1/128", true, false, "", false}, // v6 disallowed
		{"not-an-ip", true, true, "", false},
		{"1.2.3.4", true, true, "", false}, // missing prefix
		{"999.1.1.1/32", true, true, "", false},
	}
	for _, c := range cases {
		got, ok := CanonicalCIDR(c.in, c.v4, c.v6)
		if ok != c.ok || got != c.want {
			t.Errorf("CanonicalCIDR(%q,%v,%v)=%q,%v want %q,%v", c.in, c.v4, c.v6, got, ok, c.want, c.ok)
		}
	}
}

func TestFamilyOfCIDR(t *testing.T) {
	if FamilyOfCIDR("1.2.3.4/32") != "ipv4" {
		t.Error("want ipv4")
	}
	if FamilyOfCIDR("2001:db8::/64") != "ipv6" {
		t.Error("want ipv6")
	}
	if FamilyOfCIDR("garbage") != "" {
		t.Error("want empty for invalid")
	}
}
