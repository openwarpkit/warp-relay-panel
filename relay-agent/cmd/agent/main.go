// WARP Relay Agent v2.2.1 - Go-rewrite of Python agent (relay-agent/agent.py).
// Single binary, low-memory, same API 1:1.
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

	"github.com/openwarpkit/warp-relay-panel/relay-agent/internal/config"
	"github.com/openwarpkit/warp-relay-panel/relay-agent/internal/conntrackgo"
	"github.com/openwarpkit/warp-relay-panel/relay-agent/internal/metrics"
	"github.com/openwarpkit/warp-relay-panel/relay-agent/internal/ratelimit"
	"github.com/openwarpkit/warp-relay-panel/relay-agent/internal/refcount"
	"github.com/openwarpkit/warp-relay-panel/relay-agent/internal/selfupdate"
	"github.com/openwarpkit/warp-relay-panel/relay-agent/internal/server"
	"github.com/openwarpkit/warp-relay-panel/relay-agent/internal/shell"
	"github.com/openwarpkit/warp-relay-panel/relay-agent/internal/traffic"
	"github.com/openwarpkit/warp-relay-panel/relay-agent/internal/watchdog"
)

// Version is set via -ldflags during build.
var Version = "2.2.19"

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	cfg := config.Load()
	if err := os.MkdirAll(cfg.DataDir, 0o750); err != nil {
		log.Fatalf("Cannot create data dir %s: %v", cfg.DataDir, err)
	}
	if removed, err := config.RemoveLegacyPanelCredentials(config.LegacyEnvPath(cfg.DataDir)); err != nil {
		log.Printf("Legacy panel credentials cleanup failed: %v", err)
	} else if removed > 0 {
		log.Printf("Removed %d legacy panel credential settings", removed)
	}

	// Persistent netlink connection for conntrack - opened lazily,
	// reconnects on ENOBUFS.
	ct := conntrackgo.New()
	defer func() {
		if err := ct.Close(); err != nil {
			log.Printf("conntrack shutdown: %v", err)
		}
	}()

	rc := refcount.New(filepath.Join(cfg.DataDir, "refcount.json"))
	tm := traffic.New(
		filepath.Join(cfg.DataDir, "traffic.json"),
		time.Duration(cfg.TrafficInterval)*time.Second,
		ct,
		traffic.ModePerIP,
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
		Refcount:         rc,
		RateLimit:        rl,
	}
	updater := &selfupdate.Updater{
		RepoDir:    cfg.RepoDir,
		InstallDir: cfg.DataDir,
		StatusPath: filepath.Join(cfg.DataDir, "update_status.json"),
		Version:    Version,
		BinaryName: "warp-relay-agent",
	}
	updater.FinalizePending()

	// Debounced ipset persist
	persistTrigger := makeDebouncedPersist(time.Duration(cfg.IpsetPersistDebounce * float64(time.Second)))

	srv := &server.Server{
		Cfg:            cfg,
		Refcount:       rc,
		Traffic:        tm,
		RateLimit:      rl,
		Metrics:        ms,
		Watchdog:       wd,
		Updater:        updater,
		Conntrack:      ct,
		Version:        Version,
		StartTime:      time.Now(),
		PersistTrigger: persistTrigger,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		tm.Loop(ctx, rc.Count)
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

	// Restore rate-limits immediately
	if applied, failed := rl.RestoreAll(); len(applied) > 0 || len(failed) > 0 {
		log.Printf("Rate-limits: restored=%d failed=%d", len(applied), len(failed))
	}

	addr := fmt.Sprintf(":%d", cfg.AgentPort)
	log.Printf("WARP Relay Agent v%s starting on %s", Version, addr)
	log.Printf("ipset: %s, traffic interval: %ds, watchdog: %ds",
		cfg.IpsetName, cfg.TrafficInterval, cfg.RulesWatchdogInterval)

	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           srv.Routes(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	// graceful shutdown
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		log.Println("Received termination signal, shutting down HTTP...")
		shutdownCtx, c := context.WithTimeout(context.Background(), 10*time.Second)
		defer c()
		cancel()                          // Stop background workers
		_ = httpSrv.Shutdown(shutdownCtx) // Unblocks ListenAndServe
	}()

	if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("HTTP server error: %v", err)
	}

	log.Println("HTTP stopped. Flushing memory state to disk safely...")
	rl.Close()
	rc.Close()

	// Wait for background workers to finish their graceful shutdown
	wg.Wait()
	log.Println("All background workers stopped. Exiting.")
}

// makeDebouncedPersist returns a function that defers
// `ipset save > /etc/ipset.rules` via debounce; repeated calls
// within the window reset the timer, saving runs once.
func makeDebouncedPersist(debounce time.Duration) func() {
	var (
		mu    sync.Mutex
		timer *time.Timer
	)
	return func() {
		mu.Lock()
		defer mu.Unlock()
		if timer != nil {
			timer.Stop()
		}
		timer = time.AfterFunc(debounce, func() {
			rc, _, errOut := shell.Run("ipset save > /etc/ipset.rules 2>&1", 10*time.Second)
			if rc != 0 {
				log.Printf("ipset persist failed: %s", errOut)
				return
			}
			log.Println("ipset persisted to /etc/ipset.rules")
		})
	}
}
