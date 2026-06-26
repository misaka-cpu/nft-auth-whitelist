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

// writeTimeout returns the HTTP server write deadline. The auth handler performs
// the optional SSH push synchronously (one target after another, each capped at
// push.timeout_seconds) before it writes its response. With a fixed 15s deadline
// a slow or numerous set of push targets could trip WriteTimeout and break the
// response even though the entry was already recorded. So when push is enabled we
// extend the deadline to cover the worst-case serial push time plus a base
// response budget. When push is off this stays at the original 15s.
func writeTimeout(cfg *config.ServerConfig) time.Duration {
	const base = 15 * time.Second
	if !cfg.Push.Enabled || len(cfg.Push.Targets) == 0 {
		return base
	}
	per := time.Duration(cfg.Push.TimeoutSeconds) * time.Second
	return base + time.Duration(len(cfg.Push.Targets))*per
}

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

	// Background purge of expired entries.
	stopPurge := make(chan struct{})
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-stopPurge:
				return
			case <-t.C:
				for _, cidr := range st.Purge(time.Now()) {
					al.Log(audit.ActionEntryExpire, audit.ResultOK, map[string]interface{}{"cidr": cidr})
				}
			}
		}
	}()

	httpSrv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      writeTimeout(cfg),
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
