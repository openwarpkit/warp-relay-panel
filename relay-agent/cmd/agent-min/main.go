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

	"github.com/openwarpkit/warp-relay-panel/relay-agent/internal/adaptivelimit"
	"github.com/openwarpkit/warp-relay-panel/relay-agent/internal/config"
	"github.com/openwarpkit/warp-relay-panel/relay-agent/internal/conntrackgo"
	"github.com/openwarpkit/warp-relay-panel/relay-agent/internal/metrics"
	"github.com/openwarpkit/warp-relay-panel/relay-agent/internal/ratelimit"
	"github.com/openwarpkit/warp-relay-panel/relay-agent/internal/selfupdate"
	"github.com/openwarpkit/warp-relay-panel/relay-agent/internal/servermin"
	"github.com/openwarpkit/warp-relay-panel/relay-agent/internal/sharedlimit"
	"github.com/openwarpkit/warp-relay-panel/relay-agent/internal/traffic"
	"github.com/openwarpkit/warp-relay-panel/relay-agent/internal/watchdog"
)

var Version = "2.2.19-min"

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
	defer func() {
		if err := ct.Close(); err != nil {
			log.Printf("conntrack shutdown: %v", err)
		}
	}()

	trafInterval := time.Duration(cfg.TrafficInterval) * time.Second
	if cfg.MinTrafficMode == traffic.ModeAggregate {
		trafInterval = 10 * time.Minute
		budgetInterval := time.Duration(cfg.SharedBudgetInterval) * time.Second
		budgetSampleInterval := budgetInterval / 2
		if budgetSampleInterval < 30*time.Second {
			budgetSampleInterval = 30 * time.Second
		}
		if cfg.SharedBudgetTB > 0 && budgetSampleInterval < trafInterval {
			trafInterval = budgetSampleInterval
		}
	}
	tm := traffic.New(
		filepath.Join(cfg.DataDir, "traffic.json"),
		trafInterval,
		ct,
		cfg.MinTrafficMode,
	)
	rl := ratelimit.New(
		filepath.Join(cfg.DataDir, "rate_limits.json"),
		cfg.RateLimitMarkMin, cfg.RateLimitMarkMax,
		ct,
	)
	// Min must not RestoreAll from disk: inactive IPs have no idle tracker and
	// permanently occupy fwmarks. Drop loaded state; sharedlimit re-seeds from
	// live conntrack on the first reconcile.
	if n := rl.Count(); n > 0 {
		ips := make([]string, 0, n)
		for _, l := range rl.All() {
			ips = append(ips, l.IP)
		}
		removed := rl.RemoveBatch(ips)
		log.Printf("Rate-limits: cleared %d disk entries (min seeds from conntrack)", len(removed))
	}
	ms := metrics.New(time.Duration(cfg.MetricsSampleInterval)*time.Second, cfg.DataDir)

	wd := &watchdog.Watchdog{
		IpsetName:        cfg.IpsetName,
		EnsureScriptPath: filepath.Join(cfg.DataDir, "ensure_rules.sh"),
		StatusFilePath:   filepath.Join(cfg.DataDir, "self_heal_status.json"),
		Refcount:         nil, // not needed for min-agent
		RateLimit:        rl,
		SkipIpset:        true,
		ForwardTags:      []string{"WR_FORWARD_OUT", "WR_FORWARD_IN", "WR_MASQUE_FORWARD_OUT", "WR_MASQUE_FORWARD_IN"},
	}
	updater := &selfupdate.Updater{
		RepoDir:    cfg.RepoDir,
		InstallDir: cfg.DataDir,
		StatusPath: filepath.Join(cfg.DataDir, "update_status.json"),
		Version:    Version,
		BinaryName: "warp-relay-agent-min",
	}
	updater.FinalizePending()

	sl := sharedlimit.New(ct, rl, sharedlimit.Config{
		LimitMbps:       cfg.SharedLimitMbps,
		MinLimitMbps:    cfg.SharedMinLimitMbps,
		ScanInterval:    time.Duration(cfg.SharedScanInterval) * time.Second,
		IdleGrace:       time.Duration(cfg.SharedIdleGrace) * time.Second,
		MonthlyBudgetTB: cfg.SharedBudgetTB,
		BudgetDirection: cfg.SharedBudgetMode,
		BudgetInterval:  time.Duration(cfg.SharedBudgetInterval) * time.Second,
		Usage: func() adaptivelimit.Usage {
			totals := tm.GetAll(
				func(string) int { return 0 },
				func(string) []int64 { return nil },
			)
			return adaptivelimit.Usage{
				Month: totals.Month, TXBytes: totals.TotalTXBytes, RXBytes: totals.TotalRXBytes,
			}
		},
		DstIP:       dstIP,
		Ports:       cfg.WarpPorts,
		MasqueDstIP: cfg.MasqueDstIP,
		MasquePorts: cfg.MasquePorts,
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

	if cfg.MinTrafficMode != traffic.ModeOff {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tm.Loop(ctx, sl.HasIP)
		}()
	}

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
	log.Printf("Shared limit: %.1f..%.1f Mbps per IP, budget=%.1f TB/%s, scan=%ds, idle_grace=%ds, ports=%d",
		cfg.SharedMinLimitMbps, cfg.SharedLimitMbps, cfg.SharedBudgetTB, cfg.SharedBudgetMode,
		cfg.SharedScanInterval, cfg.SharedIdleGrace,
		len(cfg.WarpPorts)+len(cfg.MasquePorts))

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
		cancel()
		_ = httpSrv.Shutdown(shutdownCtx)
	}()

	if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("HTTP server error: %v", err)
	}

	log.Println("HTTP stopped. Flushing memory state to disk safely...")
	rl.Close()

	wg.Wait()
	log.Println("All background workers stopped. Exiting.")
}
