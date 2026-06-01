// Package sharedlimit implements automatic CONNMARK+HTB rate-limit
// for the min-agent: scans conntrack, assigns a per-IP limit
// of the given value (default 25 Mbps) to each active client IP,
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

	"github.com/nellimonix/warp-relay-panel/relay-agent/internal/conntrackgo"
	"github.com/nellimonix/warp-relay-panel/relay-agent/internal/ratelimit"
	"github.com/ti-mo/conntrack"
)

type Config struct {
	LimitMbps    float64
	IdleGrace    time.Duration
	ScanInterval time.Duration
	DstIP        string
	Ports        []uint16
}

type Entry struct {
	IP       string    `json:"ip"`
	Mark     int       `json:"mark"`
	LastSeen time.Time `json:"last_seen"`
}

type Manager struct {
	cfg      Config
	ct       *conntrackgo.Client
	rl       *ratelimit.Manager
	mu       sync.Mutex
	seen     map[string]time.Time // ip -> lastSeen
	portsSet map[uint16]bool
}

func New(ct *conntrackgo.Client, rl *ratelimit.Manager, cfg Config) *Manager {
	portsSet := make(map[uint16]bool, len(cfg.Ports))
	for _, p := range cfg.Ports {
		portsSet[p] = true
	}
	return &Manager{
		cfg:      cfg,
		ct:       ct,
		rl:       rl,
		seen:     make(map[string]time.Time, 64),
		portsSet: portsSet,
	}
}

// reconcile performs one pass:
//   - takes a snapshot of active clients from conntrack
//   - applies rate-limit to new IPs (batch in a single nft+tc call)
//   - removes idle (> IdleGrace) IPs
func (m *Manager) reconcile() {
	// TTL = half of ScanInterval: with default 10s gives 5s cache.
	// /shaped-handler and concurrent traffic requests will get the same snapshot.
	active, err := m.ct.ActiveUDPClients(m.cfg.DstIP, m.portsSet)
	if err != nil {
		log.Printf("sharedlimit: scan error: %v", err)
		return
	}
	now := time.Now()

	m.mu.Lock()
	// 1. Collect list of new IPs under one lock (without accessing rl).
	newIPs := make([]string, 0)
	for ip := range active {
		if _, ok := m.seen[ip]; !ok {
			newIPs = append(newIPs, ip)
		}
		m.seen[ip] = now
	}
	// 2. Remove idle IPs (only from seen - limit is removed after unlock).
	toRemove := make([]string, 0)
	for ip, lastSeen := range m.seen {
		if _, stillActive := active[ip]; stillActive {
			continue
		}
		if now.Sub(lastSeen) > m.cfg.IdleGrace {
			toRemove = append(toRemove, ip)
			delete(m.seen, ip)
		}
	}
	m.mu.Unlock()

	// 3. Batch apply for new IPs (outside m.mu - rl has its own mutex).
	m.applyBatch(newIPs, "scan")

	// 4. Remove limits for idle - batch.
	if len(toRemove) > 0 {
		removed := m.rl.RemoveBatch(toRemove)
		log.Printf("sharedlimit: batch -%d (idle)", len(removed))
	}
}

func (m *Manager) applyBatch(newIPs []string, source string) {
	if len(newIPs) == 0 {
		return
	}
	items := make([]ratelimit.SetItem, 0, len(newIPs))
	for _, ip := range newIPs {
		items = append(items, ratelimit.SetItem{IP: ip, Mbps: m.cfg.LimitMbps})
	}
	applied, errs := m.rl.SetBatch(items)
	log.Printf("sharedlimit: %s batch +%d @ %.1f Mbps (%d errors)", source, len(applied), m.cfg.LimitMbps, len(errs))
	for ip, e := range errs {
		log.Printf("sharedlimit: apply %s failed: %v", ip, e)
	}
}

func (m *Manager) Loop(ctx context.Context) {
	log.Printf("sharedlimit: started - limit=%.1f Mbps, dst=%s, ports=%d, scan=%s, idle_grace=%s",
		m.cfg.LimitMbps, m.cfg.DstIP, len(m.cfg.Ports),
		m.cfg.ScanInterval, m.cfg.IdleGrace)
		
	// Initial full sync
	m.reconcile()

	evChan := make(chan conntrack.Event, 4096)
	m.ct.RegisterObserver(evChan)

	t := time.NewTicker(m.cfg.ScanInterval)
	defer t.Stop()

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
		case ev := <-evChan:
			if ev.Flow == nil || ev.Type == conntrack.EventDestroy {
				continue
			}
			if ev.Flow.TupleOrig.Proto.Protocol != 17 { // protoUDP
				continue
			}
			if !m.portsSet[ev.Flow.TupleOrig.Proto.DestinationPort] {
				continue
			}
			if ev.Flow.TupleReply.IP.SourceAddress.String() != m.cfg.DstIP {
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
			}
		case <-debounceTimer.C:
			timerActive = false
			if len(pending) > 0 {
				unique := make([]string, 0, len(pending))
				for ip := range pending {
					unique = append(unique, ip)
				}
				m.applyBatch(unique, "event")
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
	ips := make([]string, 0, len(m.seen))
	for ip := range m.seen {
		ips = append(ips, ip)
	}
	m.seen = make(map[string]time.Time, 64)
	m.mu.Unlock()

	for _, ip := range ips {
		m.rl.Remove(ip)
	}
	log.Printf("sharedlimit: reset (%d removed)", len(ips))
}

// Config for /health and /shaped endpoints (readonly view).
func (m *Manager) Cfg() Config { return m.cfg }
