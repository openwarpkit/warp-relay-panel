// WARP Relay Agent (MIN) v2.1.0-min
//
// Agent type: allows ALL clients (no whitelist),
// each active client IP gets an individual limit SHARED_LIMIT_MBPS
// symmetrically via CONNMARK + HTB on egress eth0.
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/nellimonix/warp-relay-panel/relay-agent/internal/config"
	"github.com/nellimonix/warp-relay-panel/relay-agent/internal/conntrackgo"
	"github.com/nellimonix/warp-relay-panel/relay-agent/internal/metrics"
	"github.com/nellimonix/warp-relay-panel/relay-agent/internal/ratelimit"
	"github.com/nellimonix/warp-relay-panel/relay-agent/internal/selfupdate"
	"github.com/nellimonix/warp-relay-panel/relay-agent/internal/servermin"
	"github.com/nellimonix/warp-relay-panel/relay-agent/internal/sharedlimit"
	"github.com/nellimonix/warp-relay-panel/relay-agent/internal/traffic"
	"github.com/nellimonix/warp-relay-panel/relay-agent/internal/watchdog"
)

var Version = "2.2.9-min"

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	cfg := config.Load()
	if err := os.MkdirAll(cfg.DataDir, 0o750); err != nil {
		log.Fatalf("Cannot create data dir %s: %v", cfg.DataDir, err)
	}

	// DST_IP for conntrack-filter (auto-detect via DNS if not set)
	dstIP, err := cfg.ResolveDstIP()
	if err != nil {
		log.Fatalf("Cannot resolve WARP DST_IP: %v (set WARP_DST_IP env explicitly)", err)
	}
	log.Printf("WARP DST_IP = %s", dstIP)

	ct := conntrackgo.New()
	defer func() { _ = ct.Close() }()

	tm := traffic.New(
		filepath.Join(cfg.DataDir, "traffic.json"),
		time.Duration(cfg.TrafficInterval)*time.Second,
		ct,
	)
	rl := ratelimit.New(
		filepath.Join(cfg.DataDir, "rate_limits.json"),
		cfg.RateLimitMarkMin, cfg.RateLimitMarkMax,
		ct,
	)
	if applied, failed := rl.RestoreAll(); len(applied) > 0 || len(failed) > 0 {
		log.Printf("Rate-limits restored on startup: %d applied, %d failed", len(applied), len(failed))
	}
	ms := metrics.New(time.Duration(cfg.MetricsSampleInterval)*time.Second, cfg.DataDir)

	wd := &watchdog.Watchdog{
		IpsetName:        cfg.IpsetName,
		EnsureScriptPath: filepath.Join(cfg.DataDir, "ensure_rules.sh"),
		StatusFilePath:   filepath.Join(cfg.DataDir, "self_heal_status.json"),
		Refcount:         nil, // not needed for min-agent
		RateLimit:        rl,
		SkipIpset:        true,
		ForwardTags:      []string{"WR_FORWARD_OUT", "WR_FORWARD_IN"},
	}
	updater := &selfupdate.Updater{
		RepoDir:    cfg.RepoDir,
		InstallDir: cfg.DataDir,
		StatusPath: filepath.Join(cfg.DataDir, "update_status.json"),
		Version:    Version,
		BinaryName: "warp-relay-agent-min",
	}

	sl := sharedlimit.New(ct, rl, sharedlimit.Config{
		LimitMbps:    cfg.SharedLimitMbps,
		ScanInterval: time.Duration(cfg.SharedScanInterval) * time.Second,
		IdleGrace:    time.Duration(cfg.SharedIdleGrace) * time.Second,
		DstIP:        dstIP,
		Ports:        cfg.WarpPorts,
	})

	srv := &servermin.Server{
		Cfg:         cfg,
		Conntrack:   ct,
		Traffic:     tm,
		SharedLimit: sl,
		Metrics:     ms,
		Watchdog:    wd,
		Updater:     updater,
		Version:     Version,
		StartTime:   time.Now(),
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		tm.Loop(ctx, sl.HasIP)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		ms.Loop(ctx)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		wd.Loop(ctx, time.Duration(cfg.RulesWatchdogInterval)*time.Second)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		sl.Loop(ctx)
	}()

	addr := fmt.Sprintf(":%d", cfg.AgentPort)
	log.Printf("WARP Relay Agent MIN v%s starting on %s", Version, addr)
	log.Printf("Shared limit: %.1f Mbps per IP, scan=%ds, idle_grace=%ds, ports=%d",
		cfg.SharedLimitMbps, cfg.SharedScanInterval, cfg.SharedIdleGrace, len(cfg.WarpPorts))

	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           srv.Routes(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		log.Println("Received termination signal, shutting down HTTP...")
		shutdownCtx, c := context.WithTimeout(context.Background(), 10*time.Second)
		defer c()
		cancel() // Stop background workers
		_ = httpSrv.Shutdown(shutdownCtx) // Unblocks ListenAndServe
	}()

	if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("HTTP server error: %v", err)
	}

	log.Println("HTTP stopped. Flushing memory state to disk safely...")
	rl.Close()

	wg.Wait()
	log.Println("All background workers stopped. Exiting.")
}
