// Package traffic собирает per-IP трафик через netlink-conntrack
// и хранит месячный агрегат на диске (MSK-таймзона).
package traffic

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/nellimonix/warp-relay-panel/relay-agent/internal/conntrackgo"
	"github.com/nellimonix/warp-relay-panel/relay-agent/internal/shell"
)

var msk = time.FixedZone("MSK", 3*3600)

type ipStats struct {
	TX      int64  `json:"tx"`
	RX      int64  `json:"rx"`
	Updated string `json:"updated,omitempty"`
}

type fileFmt struct {
	Month     string             `json:"month"`
	IPs       map[string]ipStats `json:"ips"`
	LastReset string             `json:"last_reset,omitempty"`
}

type connKey struct {
	src, dst       string
	sport, dport   uint16
}

type Monitor struct {
	mu       sync.Mutex
	path     string
	interval time.Duration
	state    fileFmt
	lastConn map[connKey][2]uint64
	ct       *conntrackgo.Client
}

func New(path string, interval time.Duration, ct *conntrackgo.Client) *Monitor {
	m := &Monitor{
		path:     path,
		interval: interval,
		lastConn: make(map[connKey][2]uint64),
		ct:       ct,
	}
	m.load()
	return m
}

func nowMSK() time.Time { return time.Now().In(msk) }

func (m *Monitor) load() {
	data, err := os.ReadFile(m.path)
	if err != nil {
		m.state = m.empty()
		return
	}
	var f fileFmt
	if err := json.Unmarshal(data, &f); err != nil || f.Month == "" {
		m.state = m.empty()
		return
	}
	if f.IPs == nil {
		f.IPs = make(map[string]ipStats)
	}
	m.state = f
	log.Printf("Traffic loaded: month=%s, IPs=%d", f.Month, len(f.IPs))
}

func (m *Monitor) empty() fileFmt {
	return fileFmt{
		Month:     nowMSK().Format("2006-01"),
		IPs:       make(map[string]ipStats),
		LastReset: nowMSK().Format(time.RFC3339),
	}
}

func (m *Monitor) save() {
	if err := os.MkdirAll(filepath.Dir(m.path), 0o755); err != nil {
		log.Printf("traffic: mkdir error: %v", err)
		return
	}
	data, _ := json.MarshalIndent(m.state, "", "  ")
	if err := os.WriteFile(m.path, data, 0o644); err != nil {
		log.Printf("traffic: save error: %v", err)
	}
}

func (m *Monitor) checkMonthReset() {
	cur := nowMSK().Format("2006-01")
	if m.state.Month != cur {
		log.Printf("Monthly reset (MSK): %s → %s", m.state.Month, cur)
		m.state = m.empty()
		m.lastConn = make(map[connKey][2]uint64)
		m.save()
	}
}

func (m *Monitor) Collect() {
	flows, err := m.ct.SnapshotUDP()
	if err != nil {
		log.Printf("traffic: conntrack snapshot error: %v", err)
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.checkMonthReset()

	now := nowMSK().Format(time.RFC3339)
	changed := false
	current := make(map[connKey][2]uint64, len(flows))

	for i := range flows {
		f := &flows[i]
		k := connKey{src: f.SrcIP, dst: f.DstIP, sport: f.SrcPort, dport: f.DstPort}
		current[k] = [2]uint64{f.BytesOrig, f.BytesReply}

		var dtx, drx int64
		if prev, ok := m.lastConn[k]; ok {
			if f.BytesOrig >= prev[0] {
				dtx = int64(f.BytesOrig - prev[0])
			}
			if f.BytesReply >= prev[1] {
				drx = int64(f.BytesReply - prev[1])
			}
		}
		if dtx > 0 || drx > 0 {
			s := m.state.IPs[f.SrcIP]
			s.TX += dtx
			s.RX += drx
			s.Updated = now
			m.state.IPs[f.SrcIP] = s
			changed = true
		}
	}
	m.lastConn = current
	if changed {
		m.save()
	}
}

func (m *Monitor) Loop(ctx context.Context) {
	t := time.NewTicker(m.interval)
	defer t.Stop()
	m.Collect()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.Collect()
		}
	}
}

// PerIP — публичная структура для эндпоинтов.
type PerIP struct {
	IP          string `json:"ip,omitempty"`
	TXBytes     int64  `json:"tx_bytes"`
	RXBytes     int64  `json:"rx_bytes"`
	TotalBytes  int64  `json:"total_bytes"`
	TXHuman     string `json:"tx_human"`
	RXHuman     string `json:"rx_human"`
	TotalHuman  string `json:"total_human"`
	ClientsOnIP int    `json:"clients_on_ip"`
	Updated     string `json:"updated,omitempty"`
}

type Summary struct {
	Month        string           `json:"month"`
	LastReset    string           `json:"last_reset,omitempty"`
	IPs          map[string]PerIP `json:"ips"`
	TotalTXBytes int64            `json:"total_tx_bytes"`
	TotalRXBytes int64            `json:"total_rx_bytes"`
	TotalBytes   int64            `json:"total_bytes"`
	TotalTX      string           `json:"total_tx"`
	TotalRX      string           `json:"total_rx"`
	Total        string           `json:"total"`
	IPCount      int              `json:"ip_count"`
}

func (m *Monitor) GetAll(refCount func(string) int) Summary {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.checkMonthReset()
	out := Summary{
		Month:     m.state.Month,
		LastReset: m.state.LastReset,
		IPs:       make(map[string]PerIP, len(m.state.IPs)),
	}
	var totalTX, totalRX int64
	for ip, s := range m.state.IPs {
		totalTX += s.TX
		totalRX += s.RX
		out.IPs[ip] = PerIP{
			TXBytes: s.TX, RXBytes: s.RX, TotalBytes: s.TX + s.RX,
			TXHuman:     shell.FormatBytes(s.TX),
			RXHuman:     shell.FormatBytes(s.RX),
			TotalHuman:  shell.FormatBytes(s.TX + s.RX),
			ClientsOnIP: refCount(ip),
			Updated:     s.Updated,
		}
	}
	out.TotalTXBytes = totalTX
	out.TotalRXBytes = totalRX
	out.TotalBytes = totalTX + totalRX
	out.TotalTX = shell.FormatBytes(totalTX)
	out.TotalRX = shell.FormatBytes(totalRX)
	out.Total = shell.FormatBytes(totalTX + totalRX)
	out.IPCount = len(out.IPs)
	return out
}

func (m *Monitor) GetIP(ip string, refCount func(string) int, clients func(string) []int64) (PerIP, []int64, string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.state.IPs[ip]
	if !ok {
		return PerIP{IP: ip}, clients(ip), m.state.Month, false
	}
	return PerIP{
		IP:          ip,
		TXBytes:     s.TX, RXBytes: s.RX, TotalBytes: s.TX + s.RX,
		TXHuman:     shell.FormatBytes(s.TX),
		RXHuman:     shell.FormatBytes(s.RX),
		TotalHuman:  shell.FormatBytes(s.TX + s.RX),
		ClientsOnIP: refCount(ip),
		Updated:     s.Updated,
	}, clients(ip), m.state.Month, true
}

func (m *Monitor) Reset() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.state = m.empty()
	m.lastConn = make(map[connKey][2]uint64)
	m.save()
	log.Println("Traffic data manually reset")
	return m.state.Month
}

func (m *Monitor) Month() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.state.Month
}
