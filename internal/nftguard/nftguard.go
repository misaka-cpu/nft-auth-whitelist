// Package nftguard generates (and optionally applies) a standalone, additive
// nftables guard. It is a separate protection layer and is NOT integrated with
// the nftables-nat-rust-enhanced main project.
//
// Hard rules enforced here:
//   - it only ever manages its OWN table (default "nft_auth_whitelist");
//   - it never emits "flush ruleset";
//   - it never touches the main project's self-nat / self-filter tables, or any
//     other user table;
//   - the guard chain has policy accept and only DROPs the explicitly configured
//     protected ports — unconfigured ports and SSH are untouched.
package nftguard

import (
	"fmt"
	"os/exec"
	"sort"
	"strings"
)

// TableName is the only nftables table this package may manage.
const TableName = "nft_auth_whitelist"

// Config describes what to generate. Table is retained for compatibility but
// is intentionally ignored: GenerateScript always uses TableName.
type Config struct {
	Table             string
	Allow4            []string // canonical IPv4 CIDRs
	Allow6            []string // canonical IPv6 CIDRs
	ProtectedTCPPorts []int
	ProtectedUDPPorts []int
}

func portsList(p []int) string {
	cp := append([]int(nil), p...)
	sort.Ints(cp)
	parts := make([]string, 0, len(cp))
	for _, v := range cp {
		parts = append(parts, fmt.Sprintf("%d", v))
	}
	return strings.Join(parts, ", ")
}

func elements(cidrs []string) string {
	cp := append([]string(nil), cidrs...)
	sort.Strings(cp)
	return strings.Join(cp, ", ")
}

// GenerateScript renders the nft script. The idempotent
// create-empty / delete / recreate preamble only affects this project's own
// table; it is deliberately NOT a "flush ruleset".
func GenerateScript(c Config) string {
	table := TableName

	var b strings.Builder
	b.WriteString("#!/usr/sbin/nft -f\n")
	b.WriteString("# nft-auth-whitelist standalone guard (additive, default-off).\n")
	b.WriteString("# This script ONLY manages table inet " + table + ".\n")
	b.WriteString("# It never flushes the ruleset and never touches any other table\n")
	b.WriteString("# (it leaves the main project's tables and your other tables untouched).\n\n")

	// Idempotent reset of just our table.
	fmt.Fprintf(&b, "table inet %s\n", table)
	fmt.Fprintf(&b, "delete table inet %s\n\n", table)

	fmt.Fprintf(&b, "table inet %s {\n", table)
	fmt.Fprintf(&b, "\tset allow4 {\n\t\ttype ipv4_addr\n\t\tflags interval\n\t\tauto-merge\n")
	if e := elements(c.Allow4); e != "" {
		fmt.Fprintf(&b, "\t\telements = { %s }\n", e)
	}
	b.WriteString("\t}\n\n")

	fmt.Fprintf(&b, "\tset allow6 {\n\t\ttype ipv6_addr\n\t\tflags interval\n\t\tauto-merge\n")
	if e := elements(c.Allow6); e != "" {
		fmt.Fprintf(&b, "\t\telements = { %s }\n", e)
	}
	b.WriteString("\t}\n\n")

	// policy accept: untouched ports keep flowing; we only DROP non-allowed
	// traffic to the explicitly protected ports.
	b.WriteString("\tchain guard {\n")
	b.WriteString("\t\ttype filter hook input priority -10; policy accept;\n")

	tcp := portsList(c.ProtectedTCPPorts)
	udp := portsList(c.ProtectedUDPPorts)

	if tcp != "" {
		fmt.Fprintf(&b, "\t\tip saddr @allow4 tcp dport { %s } accept\n", tcp)
		fmt.Fprintf(&b, "\t\tip6 saddr @allow6 tcp dport { %s } accept\n", tcp)
		fmt.Fprintf(&b, "\t\ttcp dport { %s } drop\n", tcp)
	}
	if udp != "" {
		fmt.Fprintf(&b, "\t\tip saddr @allow4 udp dport { %s } accept\n", udp)
		fmt.Fprintf(&b, "\t\tip6 saddr @allow6 udp dport { %s } accept\n", udp)
		fmt.Fprintf(&b, "\t\tudp dport { %s } drop\n", udp)
	}
	if tcp == "" && udp == "" {
		b.WriteString("\t\t# no protected ports configured: guard is a no-op\n")
	}
	b.WriteString("\t}\n")
	b.WriteString("}\n")
	return b.String()
}

// Apply checks the script with `nft -c -f -` and, only on success, applies it
// with `nft -f -`. This is gated by the caller (requires nft enabled AND the
// explicit --apply flag); it executes a real nft binary and must never be
// called from tests or on a dev machine.
func Apply(script string) error {
	if _, err := exec.LookPath("nft"); err != nil {
		return fmt.Errorf("nft binary not found: %w", err)
	}
	check := exec.Command("nft", "-c", "-f", "-")
	check.Stdin = strings.NewReader(script)
	if out, err := check.CombinedOutput(); err != nil {
		return fmt.Errorf("nft -c check failed: %v: %s", err, strings.TrimSpace(string(out)))
	}
	apply := exec.Command("nft", "-f", "-")
	apply.Stdin = strings.NewReader(script)
	if out, err := apply.CombinedOutput(); err != nil {
		return fmt.Errorf("nft -f apply failed: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
