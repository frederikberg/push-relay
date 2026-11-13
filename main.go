// Command push-relay forwards encrypted push notifications to Apple on behalf of any number of
// self-hosted servers, for every app it is configured with. See docs/api.md for the API
// contract and README.md for the security properties this design relies on.
package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	defaultsPath := flag.String("config", "", "path of the defaults file (required)")
	overridePath := flag.String("config-custom", "", "path of the sparse override file; skipped when it does not exist")
	flag.Parse()
	if *defaultsPath == "" {
		log.Error("-config is required")
		os.Exit(2)
	}

	cfg, err := LoadConfig(*defaultsPath, *overridePath)
	if err != nil {
		log.Error("invalid configuration", "error", err)
		os.Exit(1)
	}

	pusher, err := NewAPNSPusher(cfg.APNSKeyPath, cfg.APNSKeyID, cfg.APNSTeamID, cfg.APNSSendTimeout)
	if err != nil {
		log.Error("could not build APNs client", "error", err)
		os.Exit(1)
	}

	metrics := NewMetrics()
	ip := NewIPLimiters(cfg.IP)
	server := NewServer(cfg.Apps, cfg.TicketKeys, cfg.TicketTTL, pusher, ip, metrics, log, cfg.MaxBodyBytes)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	done := make(chan struct{})
	StartSweeper(done, 10*time.Minute, append(cfg.Apps.Sweepable(), ip.Pushes, ip.Registrations)...)
	defer close(done)

	httpServer := &http.Server{Addr: cfg.ListenAddr, Handler: server.Handler()}
	go func() {
		apps := make([]string, 0, len(cfg.Apps.All()))
		for _, app := range cfg.Apps.All() {
			apps = append(apps, app.Name)
		}
		log.Info("listening", "addr", cfg.ListenAddr, "apps", apps)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("http server failed", "error", err)
			stop()
		}
	}()

	<-ctx.Done()
	log.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		log.Error("error during shutdown", "error", err)
	}
}
