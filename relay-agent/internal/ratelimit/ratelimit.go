// Package ratelimit управляет per-IP rate-limit'ами через CONNMARK + HTB.
//
// Дизайн:
//   - на каждый IP — уникальный fwmark M ∈ [10..998]
//   - nftables map ip2mark: { IP : M } (один общий rule в PREROUTING делает
//     O(1) lookup и ct mark set вместо N линейных iptables-правил)
//   - tc class add dev IFACE parent 1: classid 1:M htb rate Nmbit ceil Nmbit burst 16k
//   - один root tc filter "flow map keys nfmark baseclass 1:0" направляет
//     каждый пакет в class 1:<nfmark> за O(1) — заменяет N per-IP fw-фильтров
//
// POSTROUTING --restore-mark уже стоит (см. ensure_rules.sh) — он переносит
// mark из conntrack на исходящий пакет; tc flow на egress матчит nfmark и шейпит.
// Симметрия: одна conntrack-запись несёт оба направления.
//
// Инициализация nftables-таблицы и tc flow filter — в ensure_rules.sh
// (ExecStartPre + watchdog). Здесь только per-IP элементы map'ы и HTB-классы.
//
// nftables/tc операции — через shell (редкие, экономия от netlink невелика).
// conntrack -U (mark на существующих флоу) — через netlink (горячий путь).
//
// Переключатель backend'а: RATELIMIT_BACKEND=iptables откатывает на старый
// per-IP iptables + fw-filter режим (на случай отсутствия nft / отката).
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
	m        map[string]Limit // ip → Limit
	used     map[int]bool     // mark → in-use
	ct       *conntrackgo.Client
	useNft   bool // false → старый путь (iptables PREROUTING + tc fw-filter per IP)
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
	}
	mgr.load()
	// Startup-init: создать nft warp_shaper + tc flow filter если их нет.
	// Защищает от сценария «бинарь обновили, но ExecStartPre с ensure_rules.sh
	// не отработал» — без этого первый /rate-limit / SetBatch падал бы с
	// "No such file or directory".
	if err := mgr.ensureBackend(); err != nil {
		log.Printf("ratelimit: ensureBackend on startup: %v (watchdog will retry)", err)
	}
	return mgr
}

// ensureBackend идемпотентно создаёт nft warp_shaper-table + map + rule в
// PREROUTING + root tc flow filter. Если всё уже на месте — возвращает nil
// без shell-вызовов после быстрой проверки.
//
// Вызывается:
//   - в New() при старте агента
//   - из applyTC/SetBatch если получили "No such file or directory" от nft
//     (runtime self-heal — кто-то снёс таблицу руками или после ребута)
func (m *Manager) ensureBackend() error {
	if !m.useNft {
		return nil
	}

	// Быстрая проверка — если оба компонента на месте, ничего не делаем.
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

	// nft часть — таблица, chain в PREROUTING, map ip2mark, rule ct mark set.
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

	// tc flow filter — нужен HTB qdisc, который ставит ensure_rules.sh.
	// Если qdisc нет — пропускаем; watchdog запустит ensure_rules.sh.
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

// isMissingErr — nft / tc возвращают это сообщение когда таблица/map/класс
// отсутствует. Триггер для runtime self-heal.
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

	tmpPath := m.path + ".tmp"
	f, err := os.Create(tmpPath)
	if err != nil {
		log.Printf("ratelimit: create tmp file error: %v", err)
		return
	}

	if _, err := f.Write(data); err != nil {
		f.Close()
		log.Printf("ratelimit: write tmp file error: %v", err)
		return
	}
	if err := f.Sync(); err != nil {
		f.Close()
		log.Printf("ratelimit: sync tmp file error: %v", err)
		return
	}
	if err := f.Close(); err != nil {
		log.Printf("ratelimit: close tmp file error: %v", err)
		return
	}
	if err := os.Rename(tmpPath, m.path); err != nil {
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

// applyTC применяет tc/(nft|iptables) правила — атомарно по best-effort.
func (m *Manager) applyTC(ip string, mbps float64, mark int) error {
	iface := shell.DefaultIface()
	if iface == "" {
		return fmt.Errorf("no default interface")
	}

	// PREROUTING: проставить ct mark.
	if m.useNft {
		// idempotent: nft при дубликате возвращает rc=1 + stderr "File exists".
		// БЕЗ 2>&1 — иначе stderr перенаправится в stdout и isExistsErr не сработает.
		cmd := fmt.Sprintf("nft add element ip warp_shaper ip2mark '{ %s : 0x%x }'", ip, mark)
		rc, _, err := shell.Run(cmd, 5*time.Second)
		// Runtime self-heal: таблица могла исчезнуть (ребут без сохранения,
		// `nft flush ruleset`, и т.п.) — создаём её inline и повторяем.
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

	// HTB-класс per IP — нужен в обоих backend'ах для индивидуальной ставки.
	rc, _, err := shell.Run(
		fmt.Sprintf("tc class add dev %s parent 1: classid 1:%d htb rate %.2fmbit ceil %.2fmbit burst 16k 2>&1", iface, mark, mbps, mbps),
		5*time.Second,
	)
	if rc != 0 && !isExistsErr(err) {
		return fmt.Errorf("tc class failed: %s", err)
	}

	// tc-фильтр: в nft-режиме один root flow filter в ensure_rules.sh маршрутизирует
	// по nfmark в class 1:M за O(1) — per-IP fw filter не нужен. В iptables-режиме
	// нужны per-IP fw filter'ы (старый дизайн).
	if !m.useNft {
		rc, _, err := shell.Run(
			fmt.Sprintf("tc filter add dev %s protocol ip parent 1:0 prio 1 handle %d fw flowid 1:%d 2>&1", iface, mark, mark),
			5*time.Second,
		)
		if rc != 0 && !isExistsErr(err) {
			return fmt.Errorf("tc filter failed: %s", err)
		}
	}

	// Пометить уже существующие conntrack-флоу с этим src — netlink.
	// maxAge=5s переиспользует snapshot от sharedlimit.reconcile → batch applyTC
	// (RestoreAll, добавление N новых IP) делает 1 Dump, а не N.
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
	// Сбросить mark на текущих conntrack-флоу — netlink.
	// maxAge=5s — тот же snapshot, см. applyTC.
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

// SetItem — один элемент для batch-применения.
type SetItem struct {
	IP        string
	Mbps      float64
	ExpiresAt string
	ClientID  *int64
}

// SetBatch применяет N лимитов за 2 shell-вызова (nft и tc -batch) + 1 conntrack-Dump.
// Снимает burst-CPU при RestoreAll (200+ IP) и sharedlimit.reconcile с большим числом
// новых клиентов. В iptables-режиме откатывается на пер-IP Set (сохраняет совместимость).
//
// Возвращает примененные лимиты и map ip→error для упавших.
func (m *Manager) SetBatch(items []SetItem) ([]Limit, map[string]error) {
	if len(items) == 0 {
		return nil, nil
	}

	// В iptables-режиме нет batch-семантики, fallback на per-IP.
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
	// 1. Аллоцировать mark'и для новых IP, переиспользовать для существующих.
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
		}
		plans = append(plans, pl)
	}
	m.mu.Unlock()

	// 2. nft batch: add element только для новых IP. mark существующего IP не
	// меняется → его элемент в map уже корректен. delete element в одной
	// атомарной nft-транзакции с add недопустим: для нового IP delete
	// отсутствующего элемента возвращает "No such file or directory" и
	// откатывает всю транзакцию вместе с add → map остаётся пустой.
	var nftBuf, tcBuf strings.Builder
	for _, pl := range plans {
		if pl.isNew {
			fmt.Fprintf(&nftBuf, "add element ip warp_shaper ip2mark { %s : 0x%x }\n", pl.item.IP, pl.mark)
		}
		fmt.Fprintf(&tcBuf, "class replace dev %s parent 1: classid 1:%d htb rate %.2fmbit ceil %.2fmbit burst 16k\n",
			iface, pl.mark, pl.item.Mbps, pl.item.Mbps)
	}

	// 3. Применить nft batch одним вызовом.
	if nftBuf.Len() > 0 {
		rc, _, errOut := shell.RunStdin("nft -f -", nftBuf.String(), 30*time.Second)
		if rc != 0 && isMissingErr(errOut) {
			if healErr := m.ensureBackend(); healErr == nil {
				rc, _, errOut = shell.RunStdin("nft -f -", nftBuf.String(), 30*time.Second)
			}
		}
		if rc != 0 && !isExistsErr(errOut) && !isMissingErr(errOut) {
			log.Printf("ratelimit.SetBatch: nft batch returned rc=%d: %s", rc, errOut)
		}
	}

	// 4. tc batch: class replace создаёт класс или меняет rate без ошибки.
	if tcBuf.Len() > 0 {
		rc, _, errOut := shell.RunStdin("tc -batch -", tcBuf.String(), 30*time.Second)
		if rc != 0 && !isExistsErr(errOut) {
			log.Printf("ratelimit.SetBatch: tc batch returned rc=%d: %s", rc, errOut)
		}
	}

	// 5. Один conntrack Dump → обновить mark на существующих flow'ах для всех new mark'ов.
	srcToMark := make(map[string]uint32, len(plans))
	for _, pl := range plans {
		srcToMark[pl.item.IP] = uint32(pl.mark)
	}
	if _, err := m.ct.MarkBySrcsUDP(srcToMark); err != nil {
		log.Printf("ratelimit.SetBatch: conntrack mark update: %v", err)
	}

	// 6. Записать в state + save один раз.
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
	m.save()
	m.mu.Unlock()

	log.Printf("Rate-limit batch applied: %d IPs (1 nft + 1 tc + 1 conntrack-dump)", len(applied))
	return applied, errs
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

// RemoveBatch снимает лимиты для N IP одним nft + одним tc batch'ем.
// Симметрично SetBatch: снимает burst при idle-cleanup в sharedlimit.reconcile.
// В iptables-режиме — fallback на per-IP Remove.
// Возвращает список реально снятых IP (тех, что были в state).
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
	}
	plans := make([]p, 0, len(ips))
	for _, ip := range ips {
		l, ok := m.m[ip]
		if !ok {
			continue
		}
		plans = append(plans, p{ip, l.Mark})
		delete(m.m, ip)
		m.releaseMark(l.Mark)
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
		srcToMark[pl.ip] = 0 // сбросить mark на conntrack-флоу
	}

	if nftBuf.Len() > 0 {
		// Дубликат-delete вернёт "No such file or directory" — игнорируем.
		shell.RunStdin("nft -f -", nftBuf.String(), 30*time.Second)
	}
	if tcBuf.Len() > 0 {
		shell.RunStdin("tc -batch -", tcBuf.String(), 30*time.Second)
	}
	// Сбросить mark существующих conntrack-flow'ов одним Dump'ом.
	if _, err := m.ct.MarkBySrcsUDP(srcToMark); err != nil {
		log.Printf("ratelimit.RemoveBatch: conntrack reset mark: %v", err)
	}

	removed := make([]Limit, 0, len(plans))
	for _, pl := range plans {
		removed = append(removed, Limit{IP: pl.ip, Mark: pl.mark})
	}
	m.mu.Lock()
	m.save()
	m.mu.Unlock()
	log.Printf("Rate-limit batch removed: %d IPs (1 nft + 1 tc + 1 conntrack-dump)", len(removed))
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

// RestoreAll переприменяет все лимиты к tc/(nft|iptables). Вызывается на старте
// агента и watchdog'ом.
//
// В nft-режиме пересевает map ip2mark целиком (flush + add всех элементов одной
// транзакцией) и пересоздаёт HTB-классы через tc class replace. SetBatch для
// этого не годится: все IP из state — "существующие", а add element там бежит
// только для новых, поэтому пустую map он бы не заполнил.
// В iptables-режиме — пер-IP applyTC (legacy fallback).
func (m *Manager) RestoreAll() (applied []string, failed []string) {
	if m.useNft {
		iface := shell.DefaultIface()
		if iface == "" {
			return nil, []string{"no default interface"}
		}
		m.ensureBackend()

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

	// iptables-режим — legacy путь, не оптимизирован.
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

// nftIPRe — IPv4 в выводе `nft list map ip warp_shaper ip2mark`.
// Формат: `elements = { 1.2.3.4 : 0x0000000a, ... }` (опционально с timeouts).
var nftIPRe = regexp.MustCompile(`(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*:`)

// Verify возвращает список IP, для которых отсутствует tc-класс или nft-элемент.
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

	// Для nft-backend проверяем что IP есть в map @ip2mark. Если таблицы нет
	// (ensure_rules.sh не отработал) — Verify заставит RestoreAll переапплаить,
	// что попытается воссоздать элементы (ошибка nft пробросится в applyTC).
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
