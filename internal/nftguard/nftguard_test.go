package nftguard

import (
	"strings"
	"testing"
)

func TestGenerateScriptNoFlushRuleset(t *testing.T) {
	s := GenerateScript(Config{
		Table:             "nft_auth_whitelist",
		Allow4:            []string{"1.2.3.4/32"},
		ProtectedTCPPorts: []int{8443},
	})
	if strings.Contains(s, "flush ruleset") {
		t.Fatal("script must never contain 'flush ruleset'")
	}
}

func TestGenerateScriptOnlyOwnTable(t *testing.T) {
	s := GenerateScript(Config{Table: "nft_auth_whitelist", ProtectedTCPPorts: []int{8443}})
	for _, forbidden := range []string{"self-nat", "self_nat", "self-filter", "self_filter"} {
		if strings.Contains(s, forbidden) {
			t.Fatalf("script must not reference %q", forbidden)
		}
	}
	if !strings.Contains(s, "table inet nft_auth_whitelist") {
		t.Fatal("script should manage its own table")
	}
	// It must not declare any table other than its own.
	if strings.Count(s, "table inet ") != strings.Count(s, "table inet nft_auth_whitelist") {
		t.Fatal("script declares a table other than its own")
	}
}

func TestGenerateScriptOnlyConfiguredPorts(t *testing.T) {
	s := GenerateScript(Config{
		Table:             "nft_auth_whitelist",
		Allow4:            []string{"1.2.3.4/32"},
		ProtectedTCPPorts: []int{8443},
	})
	if !strings.Contains(s, "tcp dport { 8443 }") {
		t.Fatal("configured port 8443 should be protected")
	}
	// SSH (22) was not configured; it must not appear.
	if strings.Contains(s, "22") {
		t.Fatal("unconfigured port (ssh/22) must not appear in script")
	}
	if strings.Contains(s, "udp dport") {
		t.Fatal("no udp ports configured; no udp rules expected")
	}
}

func TestGenerateScriptIntervalSetsUseAutoMerge(t *testing.T) {
	s := GenerateScript(Config{
		Table:             "nft_auth_whitelist",
		Allow4:            []string{"1.2.3.0/24", "1.2.3.4/32"},
		Allow6:            []string{"2001:db8::/64", "2001:db8::1/128"},
		ProtectedTCPPorts: []int{8443},
	})
	if got := strings.Count(s, "auto-merge"); got != 2 {
		t.Fatalf("want auto-merge on both interval sets, got %d occurrences in:\n%s", got, s)
	}
}

func TestGenerateScriptNoPortsIsNoop(t *testing.T) {
	s := GenerateScript(Config{Table: "nft_auth_whitelist"})
	if strings.Contains(s, "drop") {
		t.Fatal("with no protected ports the guard must not drop anything")
	}
	if !strings.Contains(s, "policy accept") {
		t.Fatal("guard chain must use policy accept")
	}
}

func TestGenerateScriptPolicyAccept(t *testing.T) {
	s := GenerateScript(Config{Table: "nft_auth_whitelist", ProtectedTCPPorts: []int{8443}})
	if !strings.Contains(s, "policy accept") {
		t.Fatal("policy must be accept, never a global drop")
	}
}

func TestGenerateScriptIgnoresArbitraryTableNames(t *testing.T) {
	s := GenerateScript(Config{Table: "filter", ProtectedTCPPorts: []int{8443}})
	if strings.Contains(s, "table inet filter") {
		t.Fatal("generator must never manage a caller-selected table")
	}
	if !strings.Contains(s, "table inet nft_auth_whitelist") {
		t.Fatal("generator must use the fixed project table")
	}
}
