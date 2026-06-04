// Command puller runs on the domestic (po0) machine. It actively pulls the
// signed allow.json from the auth-server, verifies it, and writes a local
// allowlist file. It does NOT expose any remote API to modify the allowlist.
//
// Default mode is "export": it only writes allow.txt + state JSON. Real nft
// application requires BOTH the guard to be enabled in config AND the explicit
// --apply flag.
package main

import (
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/misaka-cpu/nft-auth-whitelist/internal/audit"
	"github.com/misaka-cpu/nft-auth-whitelist/internal/config"
	"github.com/misaka-cpu/nft-auth-whitelist/internal/version"
)

func main() {
	cfgPath := flag.String("config", "/etc/nft-auth-whitelist/puller.json", "path to puller config")
	once := flag.Bool("once", false, "run a single pull cycle then exit")
	dryRun := flag.Bool("dry-run", false, "print what would be written / the nft script, write nothing")
	apply := flag.Bool("apply", false, "actually apply the nft guard (requires nft enabled in config)")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version.String())
		return
	}

	cfg, err := config.LoadPullerConfig(*cfgPath)
	if err != nil {
		log.Fatalf("config error: %v", err)
	}

	al, err := audit.New(cfg.AuditLog)
	if err != nil {
		log.Fatalf("audit log error: %v", err)
	}
	defer al.Close()

	p := newPuller(cfg, al)
	opts := runOptions{DryRun: *dryRun, Apply: *apply}

	if *once || *dryRun {
		if err := p.runOnce(opts); err != nil {
			// Not fatal in the sense of corrupting state; previous output is kept.
			log.Printf("pull cycle error: %v", err)
		}
		return
	}

	// Loop mode (useful for foreground testing; systemd uses --once + a timer).
	log.Printf("%s", version.String())
	log.Printf("puller loop every %ds (mode=%s)", cfg.IntervalSeconds, cfg.Mode)
	if err := p.runOnce(opts); err != nil {
		log.Printf("pull cycle error: %v", err)
	}
	t := time.NewTicker(time.Duration(cfg.IntervalSeconds) * time.Second)
	defer t.Stop()
	for range t.C {
		if err := p.runOnce(opts); err != nil {
			log.Printf("pull cycle error: %v", err)
		}
	}
}
