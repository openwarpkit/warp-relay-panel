// WARP Relay Agent v2.2.1 — Go-rewrite Python-агента (relay-agent/agent.py).
// Single binary, low-memory, тот же API 1:1.
//
// v2.1.0: горячие операции (conntrack snapshot/delete/mark, ipset add/del/list)
// переведены на native netlink (ti-mo/conntrack, vishvananda/netlink).
// iptables/tc остаются через shell — редкие операции, ROI от netlink невелик.
//
// v2.2.0: в /traffic и /traffic/{ip} добавлено поле "client_ids"
// (clientID, привязанные к IP в refcount.json).
//
// v2.2.1: per-IP CONNMARK переведены с N iptables-mangle правил на один
// nft map @ip2mark (O(1) lookup), per-IP tc fw filter'ы заменены одним
// root tc flow filter — снимает softirq-нагрузку при 100+ rate-limit'ах.
// Откат: RATELIMIT_BACKEND=iptables. Кешируемый conntrack-snapshot, pprof endpoint.
//
// v2.2.2: фикс синтаксиса root flow filter ("flow map key mark addend
// 0xffffffff baseclass 1:1" — для iproute2 6.x), миграционные grep'ы в
// ensure_rules.sh теперь ловят iptables --set-xmark и tc fw chain handle.
// MarkBySrcUDP использует cachedDump → при N новых IP за один reconcile
// один Dump вместо N (снимает CPU-burst при applyTC).
// Watchdog: grep "flow chain" вместо "flow map". nft add element без 2>&1,
// чтобы isExistsErr ловил дубль-add (idempotency).
//
// v2.2.3: SetBatch / MarkBySrcsUDP — N applyTC за 2 fork+exec (nft -f - + tc
// -batch -) + 1 conntrack Dump. RestoreAll и sharedlimit.reconcile используют
// batch — startup-burst 222 IP падает с 30%×12s до 7%×1s.
//
// v2.2.4: RemoveBatch для idle-cleanup в sharedlimit. Default
// SHARED_SCAN_INTERVAL поднят 10s -> 30s (реже reconcile, ниже пиковая
// нагрузка от applyTC; компромисс — клиенты получают лимит до 30s медленнее).
//
// v2.2.5: /whitelist/sync теперь принимает поле "rate_limits" и применяет
// шейпинг батчем сразу после whitelist (panel шлёт rate_limits в payload —
// см. api/relay_client.full_sync). Diff-remove: лимиты, которых нет в payload,
// снимаются — agent state 1-в-1 совпадает с БД после Sync.
// startupResync тоже переведён на SetBatch — N×fork+exec → 2 fork+exec.
//
// v2.2.6: self-heal nft warp_shaper. ratelimit.New() при старте создаёт
// table+map+rule если их нет (ExecStartPre с ensure_rules.sh мог не
// отработать). При runtime-ошибке "No such file or directory" в nft add/
// /SetBatch — inline-init таблицы и повторение операции. Снимает кейс
// «обновили бинарь без systemctl restart → /rate-limit падает с 500».
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
	"github.com/nellimonix/warp-relay-panel/relay-agent/internal/ipsetgo"
	"github.com/nellimonix/warp-relay-panel/relay-agent/internal/metrics"
	"github.com/nellimonix/warp-relay-panel/relay-agent/internal/panel"
	"github.com/nellimonix/warp-relay-panel/relay-agent/internal/ratelimit"
	"github.com/nellimonix/warp-relay-panel/relay-agent/internal/refcount"
	"github.com/nellimonix/warp-relay-panel/relay-agent/internal/selfupdate"
	"github.com/nellimonix/warp-relay-panel/relay-agent/internal/server"
	"github.com/nellimonix/warp-relay-panel/relay-agent/internal/shell"
	"github.com/nellimonix/warp-relay-panel/relay-agent/internal/traffic"
	"github.com/nellimonix/warp-relay-panel/relay-agent/internal/watchdog"
)

// Version проставляется через -ldflags при сборке.
var Version = "2.2.8"

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	cfg := config.Load()
	if err := os.MkdirAll(cfg.DataDir, 0o755); err != nil {
		log.Fatalf("Cannot create data dir %s: %v", cfg.DataDir, err)
	}

	// Persistent netlink connection для conntrack — открывается лениво,
	// переподключается при ENOBUFS.
	ct := conntrackgo.New()
	defer ct.Close()

	rc := refcount.New(filepath.Join(cfg.DataDir, "refcount.json"))
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

	// Debounced ipset persist
	persistTrigger := makeDebouncedPersist(time.Duration(cfg.IpsetPersistDebounce*float64(time.Second)))

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
		tm.Loop(ctx)
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

	// Restore rate-limits сразу
	if applied, failed := rl.RestoreAll(); len(applied) > 0 || len(failed) > 0 {
		log.Printf("Rate-limits: restored=%d failed=%d", len(applied), len(failed))
	}

	// Опциональный startup-resync с панели
	pc := panel.New(cfg.PanelURL, cfg.PanelAPIKey, cfg.RelayID)
	if pc.Configured() {
		go startupResync(pc, rc, rl, cfg)
	} else {
		log.Println("Startup-resync пропущен (PANEL_URL/PANEL_API_KEY/RELAY_ID не заданы)")
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
		log.Println("Shutting down...")
		shutdownCtx, c := context.WithTimeout(context.Background(), 10*time.Second)
		defer c()
		httpSrv.Shutdown(shutdownCtx)
		cancel()
	}()

	if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("HTTP server error: %v", err)
	}

	// Wait for background workers to finish their graceful shutdown
	wg.Wait()
	log.Println("All background workers stopped. Exiting.")
}

// makeDebouncedPersist возвращает функцию, которая откладывает
// `ipset save > /etc/ipset.rules` на debounce; при повторных вызовах
// внутри окна — таймер сбрасывается, save выполняется один раз.
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

func startupResync(
	pc *panel.Client,
	rc *refcount.Map,
	rl *ratelimit.Manager,
	cfg config.Config,
) {
	payload, err := pc.FetchWhitelistPayload()
	if err != nil {
		log.Printf("Startup-resync failed: %v", err)
		return
	}

	// Пересобрать ipset из payload — netlink.
	if err := ipsetgo.Create(cfg.IpsetName, 1000000); err != nil {
		log.Printf("startup-resync: ipset create: %v", err)
	}
	if err := ipsetgo.Flush(cfg.IpsetName); err != nil {
		log.Printf("startup-resync: ipset flush: %v", err)
	}

	uniqueIPs := make(map[string]struct{})
	rcEntries := make(map[string][]int64)
	for _, c := range payload.Clients {
		if !shell.ValidIPv4(c.IP) {
			continue
		}
		uniqueIPs[c.IP] = struct{}{}
		rcEntries[c.IP] = append(rcEntries[c.IP], c.ClientID)
	}
	for ip := range uniqueIPs {
		if err := ipsetgo.Add(cfg.IpsetName, ip); err != nil {
			log.Printf("startup-resync: ipset add %s: %v", ip, err)
		}
	}
	rc.SetAll(rcEntries)
	shell.Run("ipset save > /etc/ipset.rules 2>/dev/null", 10*time.Second)

	// Rate-limits batch'ем — 1 nft + 1 tc + 1 conntrack Dump на все 200+ IP
	// вместо N×fork+exec в цикле (см. ratelimit.SetBatch).
	items := make([]ratelimit.SetItem, 0, len(payload.RateLimits))
	for _, r := range payload.RateLimits {
		if !shell.ValidIPv4(r.IP) {
			continue
		}
		items = append(items, ratelimit.SetItem{
			IP:        r.IP,
			Mbps:      r.Mbps,
			ExpiresAt: r.ExpiresAt,
			ClientID:  r.ClientID,
		})
	}
	if len(items) > 0 {
		_, errs := rl.SetBatch(items)
		for ip, err := range errs {
			log.Printf("Startup-resync: rate-limit %s failed: %v", ip, err)
		}
	}
	log.Printf("Startup-resync done: %d clients, %d rate_limits",
		len(uniqueIPs), len(payload.RateLimits))
}
