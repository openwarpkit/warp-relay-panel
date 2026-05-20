// Package sharedlimit реализует автоматический CONNMARK+HTB rate-limit
// для min-агента: сканирует conntrack, навешивает per-IP лимит
// заданного значения (по умолчанию 25 Mbps) на каждый активный клиентский IP,
// снимает при простое > IdleGrace.
//
// Принципиальное отличие от bash-прототипа: один Dump netlink-conntrack
// вместо `conntrack -L | awk` каждые N секунд (~5x по CPU).
package sharedlimit

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/nellimonix/warp-relay-panel/relay-agent/internal/conntrackgo"
	"github.com/nellimonix/warp-relay-panel/relay-agent/internal/ratelimit"
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
	seen     map[string]time.Time // ip → lastSeen
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

// reconcile делает один проход:
//   - снимает snapshot активных клиентов из conntrack
//   - новым IP — apply rate-limit (batch одним вызовом nft+tc)
//   - idle (> IdleGrace) — remove
func (m *Manager) reconcile() {
	// TTL = половина ScanInterval: при default 10s даёт 5s кеша. /shaped-handler
	// и параллельные traffic-запросы получат тот же snapshot.
	active, err := m.ct.ActiveUDPClients(m.cfg.ScanInterval/2, m.cfg.DstIP, m.portsSet)
	if err != nil {
		log.Printf("sharedlimit: scan error: %v", err)
		return
	}
	now := time.Now()

	m.mu.Lock()
	// 1. Собрать список новых IP под одним lock'ом (без обращений к rl).
	newIPs := make([]string, 0)
	for ip := range active {
		if _, ok := m.seen[ip]; !ok {
			newIPs = append(newIPs, ip)
		}
		m.seen[ip] = now
	}
	// 2. Удалить idle IP (только из seen — limit снимаем после unlock).
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

	// 3. Batch apply для новых (за пределами m.mu — внутри rl свой mutex).
	if len(newIPs) > 0 {
		items := make([]ratelimit.SetItem, 0, len(newIPs))
		for _, ip := range newIPs {
			items = append(items, ratelimit.SetItem{IP: ip, Mbps: m.cfg.LimitMbps})
		}
		applied, errs := m.rl.SetBatch(items)
		log.Printf("sharedlimit: batch +%d @ %.1f Mbps (%d errors)", len(applied), m.cfg.LimitMbps, len(errs))
		for ip, e := range errs {
			log.Printf("sharedlimit: apply %s failed: %v", ip, e)
		}
	}

	// 4. Удалить лимиты для idle — batch.
	if len(toRemove) > 0 {
		removed := m.rl.RemoveBatch(toRemove)
		log.Printf("sharedlimit: batch -%d (idle)", len(removed))
	}
}

func (m *Manager) Loop(ctx context.Context) {
	log.Printf("sharedlimit: started — limit=%.1f Mbps, dst=%s, ports=%d, scan=%s, idle_grace=%s",
		m.cfg.LimitMbps, m.cfg.DstIP, len(m.cfg.Ports),
		m.cfg.ScanInterval, m.cfg.IdleGrace)
	m.reconcile()
	t := time.NewTicker(m.cfg.ScanInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.reconcile()
		}
	}
}

// Shaped возвращает текущий список IP под лимитом + classid + lastSeen.
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

// Count — кол-во IP под лимитом.
func (m *Manager) Count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.seen)
}

// Reset — снять все лимиты и очистить state. Reconcile-loop при
// следующем тике перенавесит на текущих активных.
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

// Config — для эндпоинтов /health и /shaped (readonly view).
func (m *Manager) Cfg() Config { return m.cfg }
