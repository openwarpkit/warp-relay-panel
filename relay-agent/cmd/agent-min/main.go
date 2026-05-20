// WARP Relay Agent (MIN) v2.1.0-min
//
// Тип агента: пропускает ВСЕХ клиентов (без whitelist),
// каждый активный клиентский IP получает индивидуальный лимит SHARED_LIMIT_MBPS
// (по умолчанию 25 Mbps) симметрично через CONNMARK + HTB на egress eth0.
//
// Дизайн один и тот же что у full-agent ratelimit, но активные IP получаются
// автоматически из conntrack (а не из API-команд панели).
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
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

var Version = "2.2.5-min"

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	cfg := config.Load()
	if err := os.MkdirAll(cfg.DataDir, 0o755); err != nil {
		log.Fatalf("Cannot create data dir %s: %v", cfg.DataDir, err)
	}

	// DST_IP для conntrack-фильтра (auto-detect через DNS если не задан)
	dstIP, err := cfg.ResolveDstIP()
	if err != nil {
		log.Fatalf("Cannot resolve WARP DST_IP: %v (set WARP_DST_IP env explicitly)", err)
	}
	log.Printf("WARP DST_IP = %s", dstIP)

	ct := conntrackgo.New()
	defer ct.Close()

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
	ms := metrics.New(time.Duration(cfg.MetricsSampleInterval)*time.Second, cfg.DataDir)

	wd := &watchdog.Watchdog{
		IpsetName:        cfg.IpsetName,
		EnsureScriptPath: filepath.Join(cfg.DataDir, "ensure_rules.sh"),
		StatusFilePath:   filepath.Join(cfg.DataDir, "self_heal_status.json"),
		Refcount:         nil, // не нужен min-агенту
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

	go tm.Loop(ctx)
	go ms.Loop(ctx)
	go wd.Loop(ctx, time.Duration(cfg.RulesWatchdogInterval)*time.Second)
	go sl.Loop(ctx)

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
		log.Println("Shutting down...")
		shutdownCtx, c := context.WithTimeout(context.Background(), 10*time.Second)
		defer c()
		httpSrv.Shutdown(shutdownCtx)
		cancel()
	}()

	if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("HTTP server error: %v", err)
	}
}
