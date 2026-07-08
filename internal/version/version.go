// Package version exposes build metadata for the binaries.
package version

import "fmt"

// These values can be overridden at build time via -ldflags.
var (
	Version = "0.7.1"
	Commit  = "dev"
	Date    = "unknown"
)

// String returns a human readable version string.
func String() string {
	return fmt.Sprintf("nft-auth-whitelist %s (commit %s, built %s)", Version, Commit, Date)
}
