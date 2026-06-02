// Package ratelimit manages per-IP rate-limits via CONNMARK + HTB.
//
// Design:
//   - unique fwmark M in [10..998] per IP
//   - nftables map ip2mark: { IP : M } (one shared PREROUTING rule does
//     O(1) lookup and ct mark set instead of N linear iptables rules)
//   - tc class add dev IFACE parent 1: classid 1:M htb rate Nmbit ceil Nmbit burst 16k
//   - one root tc filter "flow map keys nfmark baseclass 1:0" directs
//     each packet to class 1:<nfmark> in O(1) - replaces N per-IP fw filters
//
// POSTROUTING --restore-mark is already set (see ensure_rules.sh) - it copies
// mark from conntrack to outgoing packet; tc flow on egress matches nfmark and shapes.
// Symmetry: one conntrack entry carries both directions.
//
// Initialization of nftables table and tc flow filter is in ensure_rules.sh
// (ExecStartPre + watchdog). Here we only manage per-IP map elements and HTB classes.
//
// nftables/tc ops - via shell (rare, netlink savings are small).
// conntrack -U (mark on existing flows) - via netlink (hot path).
//
// Backend switch: RATELIMIT_BACKEND=iptables falls back to legacy
// per-IP iptables + fw-filter mode (if nft is missing / rollback).
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
	mu       sync.Mutex
	path     string
	markMin  int
	markMax  int
	m        map[string]Limit // ip -> Limit
	used     map[int]bool     // mark → in-use
	ct       *conntrackgo.Client
	useNft   bool // false -> legacy path
	dirty    bool
	notify   chan struct{}
	stop     chan struct{}
	wg       sync.WaitGroup
	shellMu  sync.Mutex
}

func New(path string, markMin, markMax int, ct *conntrackgo.Client) *Manager {
	mgr := &Manager{
		path:    path,
		markMin: markMin,
		markMax: markMax,
		m:       make(map[string]Limit),
		used:    make(map[int]bool),
		ct:      ct,
		useNft:  os.Getenv("RATELIMIT_BACKEND") != "iptables",
		notify:  make(chan struct{}, 1),
		stop:    make(chan struct{}),
	}
	mgr.load()
	mgr.wg.Add(1)
	go mgr.saveWorker()
	// Startup-init: create nft warp_shaper + tc flow filter if missing.
	// Protects against "binary updated but ExecStartPre ensure_rules.sh
	// did not run" - otherwise the first /rate-limit or SetBatch would fail.
	if err := mgr.ensureBackend(); err != nil {
		log.Printf("ratelimit: ensureBackend on startup: %v (watchdog will retry)", err)
	}
	return mgr
}

// ensureBackend idempotently creates nft warp_shaper table + map + rule in
// PREROUTING + root tc flow filter. If already present, returns nil
// with no shell calls after a fast check.
//
// Called:
//   - in New() on agent start
//   - from applyTC/SetBatch if "No such file or directory" from nft
//     (runtime self-heal if table was manually deleted or after reboot)
func (m *Manager) ensureBackend() error {
	if !m.useNft {
		return nil
	}

	// Fast check - if both components are in place, do nothing.
	tableOk := false
	rcT, _, _ := shell.Run("nft list table ip warp_shaper >/dev/null 2>&1", 5*time.Second)
	if rcT == 0 {
		tableOk = true
	}
	iface := shell.DefaultIface()
	flowOk := false
	if iface != "" {
		_, out, _ := shell.Run(fmt.Sprintf("tc filter show dev %s parent 1:0 2>/dev/null", iface), 5*time.Second)
		if strings.Contains(out, "flow chain") {
			flowOk = true
		}
	}
	if tableOk && flowOk {
		return nil
	}

	// nft part - table, PREROUTING chain, map ip2mark, rule ct mark set.
	if !tableOk {
		nftInit := "add table ip warp_shaper\n" +
			"add chain ip warp_shaper prerouting { type filter hook prerouting priority -150 ; }\n" +
			"add map ip warp_shaper ip2mark { type ipv4_addr : mark ; }\n" +
			"add rule ip warp_shaper prerouting ct mark set ip saddr map @ip2mark\n"
		rc, _, errOut := shell.RunStdin("nft -f -", nftInit, 10*time.Second)
		if rc != 0 && !isExistsErr(errOut) {
			return fmt.Errorf("nft init warp_shaper: %s", errOut)
		}
		log.Println("ratelimit: nft warp_shaper table created")
	}

	// tc flow filter - needs HTB qdisc, which is set by ensure_rules.sh.
	// If qdisc is missing, skip; watchdog will run ensure_rules.sh.
	if !flowOk && iface != "" {
		_, qOut, _ := shell.Run(fmt.Sprintf("tc qdisc show dev %s 2>/dev/null", iface), 5*time.Second)
		if strings.Contains(qOut, "qdisc htb 1:") {
			rc, _, errOut := shell.Run(fmt.Sprintf(
				"tc filter add dev %s parent 1:0 protocol ip prio 1 handle 1 flow map key mark addend 0xffffffff baseclass 1:1",
				iface), 5*time.Second)
			if rc == 0 {
				log.Println("ratelimit: tc flow filter created")
			} else if !isExistsErr(errOut) {
				log.Printf("ratelimit: tc flow filter not created: %s", errOut)
			}
		}
	}
	return nil
}

// isMissingErr - nft/tc return this when table/map/class is missing.
// Trigger for runtime self-heal.
func isMissingErr(stderr string) bool {
	s := strings.ToLower(stderr)
	return strings.Contains(s, "no such file or directory") ||
		strings.Contains(s, "no such table") ||
		strings.Contains(s, "could not process rule: no such")
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

func (m *Manager) triggerSave() {
	m.dirty = true
	select {
	case m.notify <- struct{}{}:
	default:
	}
}

func (m *Manager) saveWorker() {
	defer m.wg.Done()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-m.notify:
		case <-ticker.C:
		case <-m.stop:
			return
		}

		m.mu.Lock()
		if !m.dirty {
			m.mu.Unlock()
			continue
		}

		out := make(map[string]Limit, len(m.m))
		for ip, l := range m.m {
			l.IP = ""
			out[ip] = l
		}
		m.dirty = false
		m.mu.Unlock()

		m.writeToDisk(out)
	}
}

// Close gracefully stops the background worker and forces a final save.
func (m *Manager) Close() {
	close(m.stop)
	m.wg.Wait()
	m.ForceSave()
}

// ForceSave writes immediately without debouncing, blocking until done.
func (m *Manager) ForceSave() {
	m.mu.Lock()
	if !m.dirty {
		m.mu.Unlock()
		return
	}
	out := make(map[string]Limit, len(m.m))
	for ip, l := range m.m {
		l.IP = ""
		out[ip] = l
	}
	m.dirty = false
	m.mu.Unlock()

	m.writeToDisk(out)
}

func (m *Manager) writeToDisk(out map[string]Limit) {
	if err := os.MkdirAll(filepath.Dir(m.path), 0o750); err != nil {
		log.Printf("ratelimit: mkdir error: %v", err)
		return
	}

	tmpPath := m.path + ".tmp"
	// #nosec G304 -- Tmp file path is constructed from config
	f, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		log.Printf("ratelimit: create tmp file error: %v", err)
		return
	}

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		log.Printf("ratelimit: write tmp file error: %v", err)
		return
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		log.Printf("ratelimit: sync tmp file error: %v", err)
		return
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmpPath)
		log.Printf("ratelimit: close tmp file error: %v", err)
		return
	}
	if err := os.Rename(tmpPath, m.path); err != nil {
		_ = os.Remove(tmpPath)
		log.Printf("ratelimit: rename error: %v", err)
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

// applyTC applies tc/(nft|iptables) rules - atomically best-effort.
func (m *Manager) applyTC(ip string, mbps float64, mark int) error {
	iface := shell.DefaultIface()
	if iface == "" {
		return fmt.Errorf("no default interface")
	}

	// PREROUTING: set ct mark.
	if m.useNft {
		// idempotent: nft on duplicate returns rc=1 + stderr "File exists".
		// NO 2>&1 - otherwise stderr is redirected to stdout and isExistsErr won't work.
		cmd := fmt.Sprintf("nft add element ip warp_shaper ip2mark '{ %s : 0x%x }'", ip, mark)
		rc, _, err := shell.Run(cmd, 5*time.Second)
		// Runtime self-heal: table might have disappeared (reboot without save,
		// nft flush ruleset, etc.) - recreate it inline and retry.
		if rc != 0 && !isExistsErr(err) && isMissingErr(err) {
			if healErr := m.ensureBackend(); healErr == nil {
				rc, _, err = shell.Run(cmd, 5*time.Second)
			}
		}
		if rc != 0 && !isExistsErr(err) {
			return fmt.Errorf("nft add element failed: %s", err)
		}
	} else {
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
	}

	// HTB-class per IP - needed in both backends for individual rate.
	rc, _, err := shell.Run(
		fmt.Sprintf("tc class add dev %s parent 1: classid 1:%d htb rate %.2fmbit ceil %.2fmbit burst 16k 2>&1", iface, mark, mbps, mbps),
		5*time.Second,
	)
	if rc != 0 && !isExistsErr(err) {
		return fmt.Errorf("tc class failed: %s", err)
	}

	// tc-filter: in nft-mode one root flow filter in ensure_rules.sh routes
	// by nfmark to class 1:M in O(1) - per-IP fw filter not needed. In iptables-mode
	// per-IP fw filters are needed (legacy design).
	if !m.useNft {
		rc, _, err := shell.Run(
			fmt.Sprintf("tc filter add dev %s protocol ip parent 1:0 prio 1 handle %d fw flowid 1:%d 2>&1", iface, mark, mark),
			5*time.Second,
		)
		if rc != 0 && !isExistsErr(err) {
			return fmt.Errorf("tc filter failed: %s", err)
		}
	}

	// Mark already existing conntrack-flows with this src - netlink.
	// maxAge=5s reuses snapshot from sharedlimit.reconcile -> batch applyTC
	// (RestoreAll, adding N new IPs) does 1 Dump, not N.
	// #nosec G115 -- mark is within safe 10..999 range
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
	if m.useNft {
		shell.Run(
			fmt.Sprintf("nft delete element ip warp_shaper ip2mark '{ %s }' 2>/dev/null", ip),
			5*time.Second)
	} else {
		shell.Run(
			fmt.Sprintf("iptables -t mangle -D PREROUTING -m conntrack --ctorigsrc %s -j CONNMARK --set-mark %d 2>/dev/null", ip, mark),
			5*time.Second)
		shell.Run(
			fmt.Sprintf("tc filter del dev %s protocol ip parent 1:0 prio 1 handle %d fw 2>/dev/null", iface, mark),
			5*time.Second)
	}
	shell.Run(
		fmt.Sprintf("tc class del dev %s classid 1:%d 2>/dev/null", iface, mark),
		5*time.Second)
	// Reset mark on current conntrack-flows - netlink.
	// maxAge=5s - same snapshot, see applyTC.
	if err := m.ct.MarkBySrcUDP(ip, 0); err != nil {
		log.Printf("ratelimit: reset mark for %s: %v", ip, err)
	}
}

func isExistsErr(stderr string) bool {
	s := strings.ToLower(stderr)
	return strings.Contains(s, "exists") || strings.Contains(s, "file exists")
}

// Set creates or updates a limit. Atomicity: on update preserve mark.
func (m *Manager) Set(ip string, mbps float64, expiresAt string, clientID *int64) (Limit, error) {
	m.mu.Lock()
	var mark int
	existed := false
	if existing, ok := m.m[ip]; ok {
		mark = existing.Mark
		existed = true
	} else {
		var err error
		mark, err = m.allocateMark()
		if err != nil {
			m.mu.Unlock()
			return Limit{}, err
		}
		m.m[ip] = Limit{Mark: mark}
	}
	m.mu.Unlock()

	m.shellMu.Lock()
	if existed {
		m.removeTC(ip, mark)
	}
	err := m.applyTC(ip, mbps, mark)
	m.shellMu.Unlock()

	m.mu.Lock()
	if err != nil {
		if !existed {
			delete(m.m, ip)
			m.releaseMark(mark)
		}
		m.mu.Unlock()
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
	m.triggerSave()
	m.mu.Unlock()

	log.Printf("Rate-limit applied: %s = %.2f Mbps (mark=%d, expires=%s)", ip, mbps, mark, expiresAt)
	out := l
	out.IP = ip
	return out, nil
}

// SetItem - single item for batch application.
type SetItem struct {
	IP        string
	Mbps      float64
	ExpiresAt string
	ClientID  *int64
}

// SetBatch applies N limits in 2 shell calls (nft and tc -batch) + 1 conntrack Dump.
// Removes CPU burst on RestoreAll (200+ IPs) and sharedlimit.reconcile.
// In iptables mode, falls back to per-IP Set (preserves compatibility).
//
// Returns applied limits and map ip->error for failed ones.
func (m *Manager) SetBatch(items []SetItem) ([]Limit, map[string]error) {
	if len(items) == 0 {
		return nil, nil
	}

	// No batch semantics in iptables-mode, fallback to per-IP.
	if !m.useNft {
		applied := make([]Limit, 0, len(items))
		errs := make(map[string]error)
		for _, it := range items {
			l, err := m.Set(it.IP, it.Mbps, it.ExpiresAt, it.ClientID)
			if err != nil {
				errs[it.IP] = err
				continue
			}
			applied = append(applied, l)
		}
		return applied, errs
	}

	iface := shell.DefaultIface()
	if iface == "" {
		return nil, map[string]error{"*": fmt.Errorf("no default interface")}
	}

	m.mu.Lock()
	// 1. Allocate marks for new IPs, reuse for existing ones.
	type plan struct {
		item  SetItem
		mark  int
		isNew bool
	}
	plans := make([]plan, 0, len(items))
	errs := make(map[string]error)

	// Pre-build used marks array for O(1) allocation during batch processing
	usedMarks := make([]bool, m.markMax+1)
	for _, l := range m.m {
		if l.Mark >= m.markMin && l.Mark <= m.markMax {
			usedMarks[l.Mark] = true
		}
	}
	nextFreeMark := m.markMin

	for _, it := range items {
		var pl plan
		pl.item = it
		if existing, ok := m.m[it.IP]; ok {
			pl.mark = existing.Mark
		} else {
			// Find next free mark O(1) per iteration
			mark := 0
			for i := nextFreeMark; i <= m.markMax; i++ {
				if !usedMarks[i] {
					mark = i
					nextFreeMark = i + 1
					break
				}
			}
			if mark == 0 {
				errs[it.IP] = fmt.Errorf("no free marks available (max %d limits)", m.markMax-m.markMin+1)
				continue
			}
			usedMarks[mark] = true
			m.used[mark] = true
			pl.mark = mark
			pl.isNew = true
			m.m[it.IP] = Limit{Mark: mark}
		}
		plans = append(plans, pl)
	}
	m.mu.Unlock()

	// 2. nft batch: add element only for new IPs. mark of existing IP doesn't
	// change -> its element in map is already correct. delete element in one
	// atomic nft-transaction with add is not allowed: for a new IP delete
	// of missing element returns "No such file" and
	// rolls back the whole transaction with add -> map remains empty.
	var nftBuf, tcBuf strings.Builder
	for _, pl := range plans {
		if pl.isNew {
			fmt.Fprintf(&nftBuf, "add element ip warp_shaper ip2mark { %s : 0x%x }\n", pl.item.IP, pl.mark)
		}
		fmt.Fprintf(&tcBuf, "class replace dev %s parent 1: classid 1:%d htb rate %.2fmbit ceil %.2fmbit burst 16k\n",
			iface, pl.mark, pl.item.Mbps, pl.item.Mbps)
	}

	rollback := func() {
		m.mu.Lock()
		for _, pl := range plans {
			if pl.isNew {
				delete(m.m, pl.item.IP)
				m.used[pl.mark] = false
			}
		}
		m.mu.Unlock()
		var rNftBuf, rTcBuf strings.Builder
		for _, pl := range plans {
			if pl.isNew {
				fmt.Fprintf(&rNftBuf, "delete element ip warp_shaper ip2mark { %s }\n", pl.item.IP)
			}
			fmt.Fprintf(&rTcBuf, "class del dev %s classid 1:%d\n", iface, pl.mark)
		}
		if rTcBuf.Len() > 0 {
			shell.RunStdin("tc -batch -", rTcBuf.String(), 10*time.Second)
		}
		if rNftBuf.Len() > 0 {
			shell.RunStdin("nft -f -", rNftBuf.String(), 10*time.Second)
		}
	}

	// 3. Apply nft batch in one call.
	m.shellMu.Lock()
	if nftBuf.Len() > 0 {
		rc, _, errOut := shell.RunStdin("nft -f -", nftBuf.String(), 30*time.Second)
		if rc != 0 && isMissingErr(errOut) {
			if healErr := m.ensureBackend(); healErr == nil {
				rc, _, errOut = shell.RunStdin("nft -f -", nftBuf.String(), 30*time.Second)
			}
		}
		if rc != 0 && !isExistsErr(errOut) && !isMissingErr(errOut) {
			log.Printf("ratelimit.SetBatch: nft batch returned rc=%d: %s", rc, errOut)
			rollback()
			m.shellMu.Unlock()
			for _, pl := range plans {
				errs[pl.item.IP] = fmt.Errorf("nft batch failed: %s", errOut)
			}
			return nil, errs
		}
	}

	// 4. tc batch: class replace creates class or changes rate without error.
	if tcBuf.Len() > 0 {
		rc, _, errOut := shell.RunStdin("tc -batch -", tcBuf.String(), 30*time.Second)
		if rc != 0 && !isExistsErr(errOut) {
			log.Printf("ratelimit.SetBatch: tc batch returned rc=%d: %s", rc, errOut)
			rollback()
			m.shellMu.Unlock()
			for _, pl := range plans {
				errs[pl.item.IP] = fmt.Errorf("tc batch failed: %s", errOut)
			}
			return nil, errs
		}
	}
	m.shellMu.Unlock()

	// 5. One conntrack Dump -> update mark on existing flows for all new marks.
	srcToMark := make(map[string]uint32, len(plans))
	for _, pl := range plans {
		// #nosec G115 -- mark is within safe 10..999 range
		srcToMark[pl.item.IP] = uint32(pl.mark)
	}
	if _, err := m.ct.MarkBySrcsUDP(srcToMark); err != nil {
		log.Printf("ratelimit.SetBatch: conntrack mark update: %v", err)
	}

	// 6. Write to state + save once.
	now := time.Now().In(time.FixedZone("MSK", 3*3600)).Format(time.RFC3339)
	m.mu.Lock()
	applied := make([]Limit, 0, len(plans))
	for _, pl := range plans {
		l := Limit{
			Mbps:      pl.item.Mbps,
			Mark:      pl.mark,
			ExpiresAt: pl.item.ExpiresAt,
			ClientID:  pl.item.ClientID,
			AppliedAt: now,
		}
		m.m[pl.item.IP] = l
		out := l
		out.IP = pl.item.IP
		applied = append(applied, out)
	}
	m.triggerSave()
	m.mu.Unlock()

	log.Printf("Rate-limit batch applied: %d IPs (1 nft + 1 tc + 1 conntrack-dump)", len(applied))
	return applied, errs
}

func (m *Manager) Remove(ip string) (Limit, bool) {
	m.mu.Lock()
	l, ok := m.m[ip]
	if !ok {
		m.mu.Unlock()
		return Limit{}, false
	}
	delete(m.m, ip)
	m.mu.Unlock()

	m.shellMu.Lock()
	m.removeTC(ip, l.Mark)
	m.shellMu.Unlock()

	m.mu.Lock()
	m.releaseMark(l.Mark)
	m.triggerSave()
	m.mu.Unlock()

	log.Printf("Rate-limit removed: %s (mark=%d)", ip, l.Mark)
	out := l
	out.IP = ip
	return out, true
}

// RemoveBatch removes limits for N IPs in one nft + one tc batch.
// Symmetrical to SetBatch: removes burst during idle-cleanup in sharedlimit.reconcile.
// In iptables-mode - fallback to per-IP Remove.
// Returns list of actually removed IPs (those that were in state).
func (m *Manager) RemoveBatch(ips []string) []Limit {
	if len(ips) == 0 {
		return nil
	}
	if !m.useNft {
		removed := make([]Limit, 0, len(ips))
		for _, ip := range ips {
			if l, ok := m.Remove(ip); ok {
				removed = append(removed, l)
			}
		}
		return removed
	}

	iface := shell.DefaultIface()
	if iface == "" {
		return nil
	}

	m.mu.Lock()
	type p struct {
		ip   string
		mark int
		l    Limit
	}
	plans := make([]p, 0, len(ips))
	for _, ip := range ips {
		l, ok := m.m[ip]
		if ok {
			plans = append(plans, p{ip: ip, mark: l.Mark, l: l})
			delete(m.m, ip)
		}
	}
	m.mu.Unlock()
	if len(plans) == 0 {
		return nil
	}

	var nftBuf, tcBuf strings.Builder
	srcToMark := make(map[string]uint32, len(plans))
	for _, pl := range plans {
		fmt.Fprintf(&nftBuf, "delete element ip warp_shaper ip2mark { %s }\n", pl.ip)
		fmt.Fprintf(&tcBuf, "class del dev %s classid 1:%d\n", iface, pl.mark)
		srcToMark[pl.ip] = 0 // reset mark on conntrack flow
	}

	m.shellMu.Lock()
	tcSuccess := true
	if tcBuf.Len() > 0 {
		rc, _, errOut := shell.RunStdin("tc -batch -", tcBuf.String(), 30*time.Second)
		if rc != 0 && !isMissingErr(errOut) && !isExistsErr(errOut) {
			tcSuccess = false
			log.Printf("ratelimit.RemoveBatch: tc batch returned rc=%d: %s", rc, errOut)
		}
	}
	if nftBuf.Len() > 0 && tcSuccess {
		// Duplicate-delete returns "No such file" - ignore.
		shell.RunStdin("nft -f -", nftBuf.String(), 30*time.Second)
	}
	m.shellMu.Unlock()

	if !tcSuccess {
		return nil
	}

	// 2PC: delete from memory only after successful shell execution
	m.mu.Lock()
	removed := make([]Limit, 0, len(plans))
	for _, pl := range plans {
		m.releaseMark(pl.mark)
		removed = append(removed, pl.l)
	}
	m.triggerSave()
	m.mu.Unlock()

	// Reset mark of existing conntrack flows with one Dump.
	if len(removed) > 0 {
		if _, err := m.ct.MarkBySrcsUDP(srcToMark); err != nil {
			log.Printf("ratelimit.RemoveBatch: conntrack reset mark: %v", err)
		}
		log.Printf("Rate-limit batch removed: %d IPs (1 nft + 1 tc + 1 conntrack-dump)", len(removed))
	}
	return removed
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

// RestoreAll reapplies all limits to tc/(nft|iptables). Called on agent start
// and by watchdog.
//
// In nft-mode, re-seeds map ip2mark entirely (flush + add all elements in one
// transaction) and recreates HTB classes via tc class replace. SetBatch
// isn't suitable: all IPs from state are "existing", and add element there runs
// only for new ones, so it wouldn't fill an empty map.
// In iptables-mode - per-IP applyTC (legacy fallback).
func (m *Manager) RestoreAll() (applied []string, failed []string) {
	if m.useNft {
		iface := shell.DefaultIface()
		if iface == "" {
			return nil, []string{"no default interface"}
		}
		_ = m.ensureBackend()

		m.mu.Lock()
		type ipMark struct {
			ip   string
			mark int
			mbps float64
		}
		all := make([]ipMark, 0, len(m.m))
		for ip, l := range m.m {
			all = append(all, ipMark{ip, l.Mark, l.Mbps})
		}
		m.mu.Unlock()

		if len(all) == 0 {
			return
		}

		var nftBuf, tcBuf strings.Builder
		fmt.Fprintf(&nftBuf, "flush map ip warp_shaper ip2mark\n")
		srcToMark := make(map[string]uint32, len(all))
		for _, e := range all {
			fmt.Fprintf(&nftBuf, "add element ip warp_shaper ip2mark { %s : 0x%x }\n", e.ip, e.mark)
			fmt.Fprintf(&tcBuf, "class replace dev %s parent 1: classid 1:%d htb rate %.2fmbit ceil %.2fmbit burst 16k\n",
				iface, e.mark, e.mbps, e.mbps)
			// #nosec G115 -- mark is within safe 10..999 range
			srcToMark[e.ip] = uint32(e.mark)
		}

		rc, _, errOut := shell.RunStdin("nft -f -", nftBuf.String(), 30*time.Second)
		if rc != 0 && isMissingErr(errOut) {
			if healErr := m.ensureBackend(); healErr == nil {
				rc, _, errOut = shell.RunStdin("nft -f -", nftBuf.String(), 30*time.Second)
			}
		}
		if rc != 0 && !isExistsErr(errOut) {
			log.Printf("ratelimit.RestoreAll: nft batch rc=%d: %s", rc, errOut)
			for _, e := range all {
				failed = append(failed, e.ip)
			}
			return
		}

		if rcTc, _, tcErr := shell.RunStdin("tc -batch -", tcBuf.String(), 30*time.Second); rcTc != 0 && !isExistsErr(tcErr) {
			log.Printf("ratelimit.RestoreAll: tc batch rc=%d: %s", rcTc, tcErr)
		}
		if _, err := m.ct.MarkBySrcsUDP(srcToMark); err != nil {
			log.Printf("ratelimit.RestoreAll: conntrack mark update: %v", err)
		}

		for _, e := range all {
			applied = append(applied, e.ip)
		}
		log.Printf("Rate-limit RestoreAll: re-seeded %d IPs (flush+add map, tc replace)", len(applied))
		return
	}

	// iptables-mode - legacy path, unoptimized.
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

// nftIPRe - IPv4 in `nft list map ip warp_shaper ip2mark` output.
// Format: `elements = { 1.2.3.4 : 0x0000000a, ... }` (optional with timeouts).
var nftIPRe = regexp.MustCompile(`(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*:`)

// Verify returns a list of IPs for which a tc-class or nft-element is missing.
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

	// For nft-backend check that IP is in map @ip2mark. If table is missing
	// (ensure_rules.sh did not run) - Verify forces RestoreAll to reapply,
	// which will attempt to recreate elements (nft error is passed to applyTC).
	nftIPs := map[string]bool{}
	if m.useNft {
		rc, nftOut, _ := shell.Run("nft list map ip warp_shaper ip2mark 2>/dev/null", 5*time.Second)
		if rc == 0 {
			for _, match := range nftIPRe.FindAllStringSubmatch(nftOut, -1) {
				nftIPs[match[1]] = true
			}
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	missing := make([]string, 0)
	for ip, l := range m.m {
		if !existing[l.Mark] {
			missing = append(missing, ip)
			continue
		}
		if m.useNft && !nftIPs[ip] {
			missing = append(missing, ip)
		}
	}
	return missing
}
