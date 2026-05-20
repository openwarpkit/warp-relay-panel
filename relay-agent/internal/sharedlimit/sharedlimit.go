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
//   - новым IP — apply rate-limit
//   - idle (> IdleGrace) — remove
func (m *Manager) reconcile() {
	active, err := m.ct.ActiveUDPClients(m.cfg.DstIP, m.portsSet)
	if err != nil {
		log.Printf("sharedlimit: scan error: %v", err)
		return
	}
	now := time.Now()

	m.mu.Lock()
	defer m.mu.Unlock()

	// Новые / обновление lastSeen
	for ip := range active {
		if _, ok := m.seen[ip]; !ok {
			if _, err := m.rl.Set(ip, m.cfg.LimitMbps, "", nil); err != nil {
				log.Printf("sharedlimit: apply %s failed: %v", ip, err)
				continue
			}
			log.Printf("sharedlimit: + %s @ %.1f Mbps", ip, m.cfg.LimitMbps)
		}
		m.seen[ip] = now
	}

	// Удаляем idle (отсутствуют в active И простаивают > IdleGrace)
	for ip, lastSeen := range m.seen {
		if _, stillActive := active[ip]; stillActive {
			continue
		}
		if now.Sub(lastSeen) > m.cfg.IdleGrace {
			if _, ok := m.rl.Remove(ip); ok {
				log.Printf("sharedlimit: - %s (idle %s)", ip, now.Sub(lastSeen).Round(time.Second))
			}
			delete(m.seen, ip)
		}
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
