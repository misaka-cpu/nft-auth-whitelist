// Command auth-server runs on the foreign (RFC) machine. It serves an
// HTTPS-fronted Basic Auth page that records the visitor's source IP into a
// TTL'd allowlist and exposes a signed, read-only pull endpoint.
//
// SECURITY: this server must be deployed behind HTTPS (Caddy/Nginx/your own
// reverse proxy). Do NOT expose Basic Auth over plain HTTP. The default listen
// address is 127.0.0.1:8088 so it is not directly public by accident.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/misaka-cpu/nft-auth-whitelist/internal/audit"
	"github.com/misaka-cpu/nft-auth-whitelist/internal/config"
	"github.com/misaka-cpu/nft-auth-whitelist/internal/store"
	"github.com/misaka-cpu/nft-auth-whitelist/internal/version"
)

func main() {
	cfgPath := flag.String("config", "/etc/nft-auth-whitelist/server.json", "path to server config")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version.String())
		return
	}

	cfg, err := config.LoadServerConfig(*cfgPath)
	if err != nil {
		log.Fatalf("config error: %v", err)
	}

	al, err := audit.New(cfg.AuditLog)
	if err != nil {
		log.Fatalf("audit log error: %v", err)
	}
	defer al.Close()

	st, err := store.New(cfg.DataDir, cfg.MaxEntries)
	if err != nil {
		log.Fatalf("store error: %v", err)
	}

	srv := newServer(cfg, st, al)

	// Background purge of expired entries; in push mode a purge that removed
	// entries also proactively syncs the smaller allowlist to the receivers.
	stopPurge := make(chan struct{})
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-stopPurge:
				return
			case <-t.C:
				srv.purgeAndSync(time.Now())
			}
		}
	}()

	// Periodic reconcile push: converge receivers that missed a push (network
	// blip, receiver downtime) back to the current allowlist.
	if interval := cfg.Push.ReconcileInterval(); cfg.Push.Enabled && interval > 0 {
		go func() {
			t := time.NewTicker(interval)
			defer t.Stop()
			for {
				select {
				case <-stopPurge:
					return
				case <-t.C:
					srv.reconcileSync(time.Now())
				}
			}
		}()
	}

	httpSrv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		log.Printf("%s", version.String())
		log.Printf("auth-server listening on %s (deploy behind HTTPS!)", cfg.Listen)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen error: %v", err)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	close(stopPurge)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(ctx)
}
