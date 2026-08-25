// Package sharedlimit implements automatic CONNMARK+HTB rate-limit
// for the min-agent: scans conntrack, assigns a per-IP limit
// of the configured value to each active client IP,
// and removes it when idle > IdleGrace.
//
// Key difference from the bash prototype: a single netlink-conntrack Dump
// instead of `conntrack -L | awk` every N seconds (~5x CPU improvement).
package sharedlimit

import (
	"context"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/openwarpkit/warp-relay-panel/relay-agent/internal/adaptivelimit"
	"github.com/openwarpkit/warp-relay-panel/relay-agent/internal/conntrackgo"
	"github.com/openwarpkit/warp-relay-panel/relay-agent/internal/ratelimit"
	"github.com/ti-mo/conntrack"
)

type Config struct {
	LimitMbps       float64
	MinLimitMbps    float64
	IdleGrace       time.Duration
	ScanInterval    time.Duration
	MonthlyBudgetTB float64
	BudgetDirection string
	BudgetInterval  time.Duration
	Usage           func() adaptivelimit.Usage
	DstIP           string
	Ports           []uint16
	MasqueDstIP     string
	MasquePorts     []uint16
}

type Entry struct {
	IP       string    `json:"ip"`
	Mark     int       `json:"mark"`
	LastSeen time.Time `json:"last_seen"`
}

type Manager struct {
	cfg                  Config
	ct                   *conntrackgo.Client
	rl                   *ratelimit.Manager
	mu                   sync.Mutex
	opsMu                sync.Mutex
	seen                 map[string]time.Time // ip -> lastSeen
	targets              map[string]map[uint16]bool
	currentLimit         float64
	budgetStatus         adaptivelimit.Status
	previousBudgetSample *adaptivelimit.Sample
}

func New(ct *conntrackgo.Client, rl *ratelimit.Manager, cfg Config) *Manager {
	targets := make(map[string]map[uint16]bool, 2)
	addTarget(targets, cfg.DstIP, cfg.Ports)
	addTarget(targets, cfg.MasqueDstIP, cfg.MasquePorts)
	if cfg.MinLimitMbps <= 0 || cfg.MinLimitMbps > cfg.LimitMbps {
		cfg.MinLimitMbps = cfg.LimitMbps
	}
	if cfg.BudgetDirection == "" {
		cfg.BudgetDirection = "tx"
	}
	return &Manager{
		cfg:          cfg,
		ct:           ct,
		rl:           rl,
		seen:         make(map[string]time.Time, 64),
		targets:      targets,
		currentLimit: cfg.LimitMbps,
		budgetStatus: adaptivelimit.Status{
			Enabled:          cfg.MonthlyBudgetTB > 0 && cfg.Usage != nil,
			Direction:        cfg.BudgetDirection,
			BudgetTB:         cfg.MonthlyBudgetTB,
			DefaultLimitMbps: cfg.LimitMbps,
			MinLimitMbps:     cfg.MinLimitMbps,
			CurrentLimitMbps: cfg.LimitMbps,
			DesiredLimitMbps: cfg.LimitMbps,
		},
	}
}

func addTarget(targets map[string]map[uint16]bool, dstIP string, ports []uint16) {
	if dstIP == "" || len(ports) == 0 {
		return
	}
	portSet := make(map[uint16]bool, len(ports))
	for _, port := range ports {
		portSet[port] = true
	}
	targets[dstIP] = portSet
}

func (m *Manager) matchesTarget(dstIP string, port uint16) bool {
	ports, ok := m.targets[dstIP]
	return ok && ports[port]
}

// reconcile performs one pass:
//   - takes a snapshot of active clients from conntrack
//   - applies rate-limit to new IPs (batch in a single nft+tc call)
//   - removes idle (> IdleGrace) IPs
func (m *Manager) reconcile() {
	// TTL = half of ScanInterval: with default 10s gives 5s cache.
	// /shaped-handler and concurrent traffic requests will get the same snapshot.
	active, err := m.ct.ActiveUDPClientsForTargets(m.targets)
	if err != nil {
		log.Printf("sharedlimit: scan error: %v", err)
		return
	}
	now := time.Now()

	m.mu.Lock()
	// 1. New = active IP without a current limit. Keyed on rl (source of
	// truth), not seen: an IP still in seen but dropped from rl must be
	// re-applied, else it runs unshaped.
	newIPs := make([]string, 0)
	for ip := range active {
		if !m.rl.Has(ip) {
			newIPs = append(newIPs, ip)
		}
		m.seen[ip] = now
	}
	m.mu.Unlock()

	// 2. Idle vs rl (source of truth), not only seen. Restored/historical IPs
	// never enter seen and would otherwise leak marks forever.
	toRemove := make([]string, 0)
	for _, l := range m.rl.All() {
		ip := l.IP
		if _, stillActive := active[ip]; stillActive {
			continue
		}
		m.mu.Lock()
		lastSeen, tracked := m.seen[ip]
		drop := !tracked || now.Sub(lastSeen) > m.cfg.IdleGrace
		if drop {
			delete(m.seen, ip)
		}
		m.mu.Unlock()
		if drop {
			toRemove = append(toRemove, ip)
		}
	}

	// 3. Batch apply for new IPs (outside m.mu - rl has its own mutex).
	go m.applyBatch(newIPs, "scan")

	// 4. Remove limits for idle - batch.
	if len(toRemove) > 0 {
		go func(ips []string) {
			m.opsMu.Lock()
			defer m.opsMu.Unlock()
			removed := m.rl.RemoveBatch(ips)
			log.Printf("sharedlimit: batch -%d (idle)", len(removed))
		}(toRemove)
	}
}

func (m *Manager) applyBatch(newIPs []string, source string) {
	if len(newIPs) == 0 {
		return
	}
	m.opsMu.Lock()
	defer m.opsMu.Unlock()
	m.mu.Lock()
	limitMbps := m.currentLimit
	m.mu.Unlock()
	items := make([]ratelimit.SetItem, 0, len(newIPs))
	for _, ip := range newIPs {
		items = append(items, ratelimit.SetItem{IP: ip, Mbps: limitMbps})
	}
	applied, errs := m.rl.SetBatch(items)
	log.Printf("sharedlimit: %s batch +%d @ %.1f Mbps (%d errors)", source, len(applied), limitMbps, len(errs))
	printed := 0
	for ip, e := range errs {
		if printed < 10 {
			log.Printf("sharedlimit: apply %s failed: %v", ip, e)
			printed++
		}
	}
	if len(errs) > 10 {
		log.Printf("sharedlimit: ... and %d more errors omitted", len(errs)-10)
	}
}

func (m *Manager) Loop(ctx context.Context) {
	log.Printf("sharedlimit: started - limit=%.1f..%.1f Mbps, budget=%.1f TB/%s, targets=%d, ports=%d, scan=%s, idle_grace=%s",
		m.cfg.MinLimitMbps, m.cfg.LimitMbps, m.cfg.MonthlyBudgetTB, m.cfg.BudgetDirection,
		len(m.targets), len(m.cfg.Ports)+len(m.cfg.MasquePorts),
		m.cfg.ScanInterval, m.cfg.IdleGrace)

	m.adjustBudget(time.Now())

	// Initial full sync
	m.reconcile()

	evChan := make(chan conntrack.Event, 4096)
	m.ct.RegisterObserver(evChan)

	t := time.NewTicker(m.cfg.ScanInterval)
	defer t.Stop()
	var budgetC <-chan time.Time
	var budgetTicker *time.Ticker
	if m.cfg.MonthlyBudgetTB > 0 && m.cfg.Usage != nil && m.cfg.BudgetInterval > 0 {
		budgetTicker = time.NewTicker(m.cfg.BudgetInterval)
		budgetC = budgetTicker.C
		defer budgetTicker.Stop()
	}

	pending := make(map[string]struct{})
	debounceTimer := time.NewTimer(time.Hour)
	debounceTimer.Stop()
	timerActive := false

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.reconcile()
		case at := <-budgetC:
			m.adjustBudget(at)
		case ev := <-evChan:
			if ev.Flow == nil || ev.Type == conntrack.EventDestroy {
				continue
			}
			if ev.Flow.TupleOrig.Proto.Protocol != 17 { // protoUDP
				continue
			}
			if !m.matchesTarget(
				ev.Flow.TupleReply.IP.SourceAddress.String(),
				ev.Flow.TupleOrig.Proto.DestinationPort,
			) {
				continue
			}
			src := ev.Flow.TupleOrig.IP.SourceAddress.String()
			if strings.HasPrefix(src, "162.159.") || strings.HasPrefix(src, "172.") {
				continue
			}

			m.mu.Lock()
			_, exists := m.seen[src]
			m.seen[src] = time.Now()
			m.mu.Unlock()

			if !exists {
				pending[src] = struct{}{}
				if !timerActive {
					debounceTimer.Reset(200 * time.Millisecond)
					timerActive = true
				}
				if len(pending) >= 10000 {
					// Emergency Flush: Drop batch immediately to avoid OOM or dropped IPs
					if !debounceTimer.Stop() {
						select {
						case <-debounceTimer.C:
						default:
						}
					}
					timerActive = false
					unique := make([]string, 0, len(pending))
					for ip := range pending {
						unique = append(unique, ip)
					}
					go m.applyBatch(unique, "event_emergency")
					pending = make(map[string]struct{})
				}
			}
		case <-debounceTimer.C:
			timerActive = false
			if len(pending) > 0 {
				unique := make([]string, 0, len(pending))
				for ip := range pending {
					unique = append(unique, ip)
				}
				go m.applyBatch(unique, "event")
				pending = make(map[string]struct{})
			}
		}
	}
}

// Shaped returns the current list of shaped IPs + classid + lastSeen.
func (m *Manager) Shaped() []Entry {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Entry, 0, len(m.seen))
	for ip, lastSeen := range m.seen {
		if l, ok := m.rl.Get(ip); ok {
			out = append(out, Entry{IP: ip, Mark: l.Mark, LastSeen: lastSeen})
		}
	}
	return out
}

// Count returns the number of IPs under limit.
func (m *Manager) Count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.seen)
}

// HasIP checks if IP is active (for traffic filtering).
// Returns 1 if active, 0 if not, to match countFunc signature.
func (m *Manager) HasIP(ip string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.seen[ip]; ok {
		return 1
	}
	return 0
}

// Reset removes all limits and clears state. The Reconcile-loop will
// re-apply limits to current active IPs on the next tick.
func (m *Manager) Reset() {
	m.mu.Lock()
	m.seen = make(map[string]time.Time, 64)
	m.mu.Unlock()

	m.opsMu.Lock()
	defer m.opsMu.Unlock()
	ips := make([]string, 0, m.rl.Count())
	for _, l := range m.rl.All() {
		ips = append(ips, l.IP)
	}
	removed := m.rl.RemoveBatch(ips)
	log.Printf("sharedlimit: reset (%d removed)", len(removed))
}

// Config for /health and /shaped endpoints (readonly view).
func (m *Manager) Cfg() Config { return m.cfg }

func (m *Manager) Status() adaptivelimit.Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.budgetStatus
}

func (m *Manager) adjustBudget(now time.Time) {
	if m.cfg.MonthlyBudgetTB <= 0 || m.cfg.Usage == nil {
		return
	}
	usage := m.cfg.Usage()
	m.mu.Lock()
	current := m.currentLimit
	previous := m.previousBudgetSample
	m.mu.Unlock()

	decision := adaptivelimit.Calculate(adaptivelimit.Config{
		DefaultLimitMbps: m.cfg.LimitMbps,
		MinLimitMbps:     m.cfg.MinLimitMbps,
		MonthlyBudgetTB:  m.cfg.MonthlyBudgetTB,
		Direction:        m.cfg.BudgetDirection,
	}, current, usage, previous, now)
	sample := adaptivelimit.NewSample(usage, m.cfg.BudgetDirection, now)

	if decision.Limit != current {
		m.opsMu.Lock()
		items := make([]ratelimit.SetItem, 0, m.rl.Count())
		for _, limit := range m.rl.All() {
			items = append(items, ratelimit.SetItem{IP: limit.IP, Mbps: decision.Limit})
		}
		_, errs := m.rl.SetBatch(items)
		m.opsMu.Unlock()
		if len(errs) == 0 {
			current = decision.Limit
			log.Printf("sharedlimit: adaptive limit %.1f Mbps, used=%.2f/%.2f TB, pace=%.2f, recent=%.1f Mbps, target=%.1f Mbps",
				current, decision.Status.UsedTB, decision.Status.BudgetTB, decision.Status.Pace,
				decision.Status.RecentMbps, decision.Status.TargetMbps)
		} else {
			decision.Status.Error = "failed to update shaped clients"
			log.Printf("sharedlimit: adaptive update failed for %d IPs", len(errs))
		}
	}
	decision.Status.CurrentLimitMbps = current
	m.mu.Lock()
	m.currentLimit = current
	m.previousBudgetSample = sample
	m.budgetStatus = decision.Status
	m.mu.Unlock()
}
