// Package ratelimit управляет per-IP rate-limit'ами через CONNMARK + HTB.
//
// Дизайн:
//   - на каждый IP — уникальный fwmark M ∈ [10..998]
//   - iptables -t mangle -A PREROUTING -m conntrack --ctorigsrc IP -j CONNMARK --set-mark M
//   - tc class add dev IFACE parent 1: classid 1:M htb rate Nmbit ceil Nmbit burst 16k
//   - tc filter add dev IFACE parent 1:0 prio 1 handle M fw flowid 1:M
//
// POSTROUTING --restore-mark уже стоит (см. ensure_rules.sh) — он переносит
// mark из conntrack на исходящий пакет; tc на egress матчит и шейпит.
// Симметрия: одна conntrack-запись несёт оба направления.
//
// iptables/tc операции — через shell (редкие, экономия от netlink невелика).
// conntrack -U (mark на существующих флоу) — через netlink (горячий путь).
package ratelimit

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nellimonix/warp-relay-panel/relay-agent/internal/conntrackgo"
	"github.com/nellimonix/warp-relay-panel/relay-agent/internal/shell"
)

type Limit struct {
	IP        string  `json:"ip,omitempty"`
	Mbps      float64 `json:"mbps"`
	Mark      int     `json:"mark"`
	ExpiresAt string  `json:"expires_at,omitempty"`
	ClientID  *int64  `json:"client_id,omitempty"`
	AppliedAt string  `json:"applied_at"`
}

type Manager struct {
	mu      sync.Mutex
	path    string
	markMin int
	markMax int
	m       map[string]Limit // ip → Limit
	used    map[int]bool     // mark → in-use
	ct      *conntrackgo.Client
}

func New(path string, markMin, markMax int, ct *conntrackgo.Client) *Manager {
	mgr := &Manager{
		path:    path,
		markMin: markMin,
		markMax: markMax,
		m:       make(map[string]Limit),
		used:    make(map[int]bool),
		ct:      ct,
	}
	mgr.load()
	return mgr
}

func (m *Manager) load() {
	data, err := os.ReadFile(m.path)
	if err != nil {
		return
	}
	var raw map[string]Limit
	if err := json.Unmarshal(data, &raw); err != nil {
		log.Printf("ratelimit: load error: %v", err)
		return
	}
	for ip, l := range raw {
		l.IP = ""
		m.m[ip] = l
		m.used[l.Mark] = true
	}
	log.Printf("Rate limits loaded: %d IPs", len(m.m))
}

func (m *Manager) save() {
	if err := os.MkdirAll(filepath.Dir(m.path), 0o755); err != nil {
		log.Printf("ratelimit: mkdir error: %v", err)
		return
	}
	out := make(map[string]Limit, len(m.m))
	for ip, l := range m.m {
		l.IP = ""
		out[ip] = l
	}
	data, _ := json.MarshalIndent(out, "", "  ")
	if err := os.WriteFile(m.path, data, 0o644); err != nil {
		log.Printf("ratelimit: save error: %v", err)
	}
}

func (m *Manager) allocateMark() (int, error) {
	for x := m.markMin; x <= m.markMax; x++ {
		if !m.used[x] {
			m.used[x] = true
			return x, nil
		}
	}
	return 0, fmt.Errorf("no free fwmark in pool %d..%d", m.markMin, m.markMax)
}

func (m *Manager) releaseMark(mark int) { delete(m.used, mark) }

// applyTC применяет tc/iptables правила — атомарно по best-effort.
func (m *Manager) applyTC(ip string, mbps float64, mark int) error {
	iface := shell.DefaultIface()
	if iface == "" {
		return fmt.Errorf("no default interface")
	}

	checkRC, _, _ := shell.Run(
		fmt.Sprintf("iptables -t mangle -C PREROUTING -m conntrack --ctorigsrc %s -j CONNMARK --set-mark %d 2>/dev/null", ip, mark),
		5*time.Second,
	)
	if checkRC != 0 {
		rc, _, err := shell.Run(
			fmt.Sprintf("iptables -t mangle -A PREROUTING -m conntrack --ctorigsrc %s -j CONNMARK --set-mark %d", ip, mark),
			5*time.Second,
		)
		if rc != 0 {
			return fmt.Errorf("iptables add failed: %s", err)
		}
	}

	rc, _, err := shell.Run(
		fmt.Sprintf("tc class add dev %s parent 1: classid 1:%d htb rate %.2fmbit ceil %.2fmbit burst 16k 2>&1", iface, mark, mbps, mbps),
		5*time.Second,
	)
	if rc != 0 && !isExistsErr(err) {
		return fmt.Errorf("tc class failed: %s", err)
	}

	rc, _, err = shell.Run(
		fmt.Sprintf("tc filter add dev %s protocol ip parent 1:0 prio 1 handle %d fw flowid 1:%d 2>&1", iface, mark, mark),
		5*time.Second,
	)
	if rc != 0 && !isExistsErr(err) {
		return fmt.Errorf("tc filter failed: %s", err)
	}

	// Пометить уже существующие conntrack-флоу с этим src — netlink (быстро).
	if err := m.ct.MarkBySrcUDP(ip, uint32(mark)); err != nil {
		log.Printf("ratelimit: mark existing flows for %s: %v", ip, err)
	}
	return nil
}

func (m *Manager) removeTC(ip string, mark int) {
	iface := shell.DefaultIface()
	if iface == "" {
		return
	}
	shell.Run(
		fmt.Sprintf("iptables -t mangle -D PREROUTING -m conntrack --ctorigsrc %s -j CONNMARK --set-mark %d 2>/dev/null", ip, mark),
		5*time.Second)
	shell.Run(
		fmt.Sprintf("tc filter del dev %s protocol ip parent 1:0 prio 1 handle %d fw 2>/dev/null", iface, mark),
		5*time.Second)
	shell.Run(
		fmt.Sprintf("tc class del dev %s classid 1:%d 2>/dev/null", iface, mark),
		5*time.Second)
	// Сбросить mark на текущих conntrack-флоу — netlink.
	if err := m.ct.MarkBySrcUDP(ip, 0); err != nil {
		log.Printf("ratelimit: reset mark for %s: %v", ip, err)
	}
}

func isExistsErr(stderr string) bool {
	s := strings.ToLower(stderr)
	return strings.Contains(s, "exists") || strings.Contains(s, "file exists")
}

// Set — создать или обновить лимит. Атомарность: при обновлении сохраняем mark.
func (m *Manager) Set(ip string, mbps float64, expiresAt string, clientID *int64) (Limit, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var mark int
	if existing, ok := m.m[ip]; ok {
		mark = existing.Mark
		m.removeTC(ip, mark)
	} else {
		var err error
		mark, err = m.allocateMark()
		if err != nil {
			return Limit{}, err
		}
	}

	if err := m.applyTC(ip, mbps, mark); err != nil {
		if _, existed := m.m[ip]; !existed {
			m.releaseMark(mark)
		}
		return Limit{}, err
	}

	l := Limit{
		Mbps:      mbps,
		Mark:      mark,
		ExpiresAt: expiresAt,
		ClientID:  clientID,
		AppliedAt: time.Now().In(time.FixedZone("MSK", 3*3600)).Format(time.RFC3339),
	}
	m.m[ip] = l
	m.save()
	log.Printf("Rate-limit applied: %s = %.2f Mbps (mark=%d, expires=%s)", ip, mbps, mark, expiresAt)
	out := l
	out.IP = ip
	return out, nil
}

func (m *Manager) Remove(ip string) (Limit, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	l, ok := m.m[ip]
	if !ok {
		return Limit{}, false
	}
	delete(m.m, ip)
	m.removeTC(ip, l.Mark)
	m.releaseMark(l.Mark)
	m.save()
	log.Printf("Rate-limit removed: %s (mark=%d)", ip, l.Mark)
	out := l
	out.IP = ip
	return out, true
}

func (m *Manager) Get(ip string) (Limit, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	l, ok := m.m[ip]
	if !ok {
		return Limit{}, false
	}
	out := l
	out.IP = ip
	return out, true
}

func (m *Manager) All() []Limit {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Limit, 0, len(m.m))
	for ip, l := range m.m {
		l.IP = ip
		out = append(out, l)
	}
	return out
}

func (m *Manager) Count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.m)
}

// RestoreAll переприменяет все лимиты к tc/iptables (используется на старте и watchdog'ом).
func (m *Manager) RestoreAll() (applied []string, failed []string) {
	m.mu.Lock()
	limits := make([]struct {
		IP   string
		Mbps float64
		Mark int
	}, 0, len(m.m))
	for ip, l := range m.m {
		limits = append(limits, struct {
			IP   string
			Mbps float64
			Mark int
		}{ip, l.Mbps, l.Mark})
	}
	m.mu.Unlock()

	for _, l := range limits {
		if err := m.applyTC(l.IP, l.Mbps, l.Mark); err == nil {
			applied = append(applied, l.IP)
		} else {
			failed = append(failed, fmt.Sprintf("%s: %v", l.IP, err))
		}
	}
	return
}

var classRe = regexp.MustCompile(`class htb 1:(\d+)`)

// Verify возвращает список IP, для которых tc-класс отсутствует.
func (m *Manager) Verify() []string {
	iface := shell.DefaultIface()
	if iface == "" {
		return nil
	}
	rc, out, _ := shell.Run(fmt.Sprintf("tc class show dev %s 2>/dev/null", iface), 5*time.Second)
	if rc != 0 {
		m.mu.Lock()
		defer m.mu.Unlock()
		out := make([]string, 0, len(m.m))
		for ip := range m.m {
			out = append(out, ip)
		}
		return out
	}
	existing := make(map[int]bool)
	for _, line := range strings.Split(out, "\n") {
		match := classRe.FindStringSubmatch(line)
		if match != nil {
			if n, err := strconv.Atoi(match[1]); err == nil {
				existing[n] = true
			}
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	missing := make([]string, 0)
	for ip, l := range m.m {
		if !existing[l.Mark] {
			missing = append(missing, ip)
		}
	}
	return missing
}
