// Command receive runs on the receiving machine (a stand-in for the future
// domestic po0). It is meant to be wired as an SSH forced command: the RFC
// auth-server pushes a signed allow.json over stdin, receive verifies it
// (HMAC / TTL / max_entries / family / CIDR) and, only on success, atomically
// writes the inbox copy and exports allow.txt + state json.
//
// It exposes NO network listener and NO write API. It never applies nft (there
// is deliberately no --apply flag here) and never echoes the input or secrets.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/misaka-cpu/nft-auth-whitelist/internal/audit"
	"github.com/misaka-cpu/nft-auth-whitelist/internal/config"
	"github.com/misaka-cpu/nft-auth-whitelist/internal/version"
)

func main() {
	// flag provides -h/--help automatically; -config / -version are the only
	// inputs. No secret is ever a flag value.
	cfgPath := flag.String("config", "/etc/nft-auth-whitelist/receive.json", "path to receive config")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version.String())
		return
	}

	cfg, err := config.LoadReceiveConfig(*cfgPath)
	if err != nil {
		// Config errors may name fields but never values; safe to print.
		log.Fatalf("config error: %v", err)
	}

	al, err := audit.New(cfg.AuditLog)
	if err != nil {
		log.Fatalf("audit log error: %v", err)
	}
	defer al.Close()

	r := newReceiver(cfg, al)
	if err := r.run(os.Stdin); err != nil {
		// Error strings here are constructed from non-secret material only.
		fmt.Fprintf(os.Stderr, "nft-auth-receive: %v\n", err)
		os.Exit(1)
	}
}
