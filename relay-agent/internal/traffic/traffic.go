// Package traffic collects per-IP traffic via netlink-conntrack
// and stores a monthly aggregate on disk (MSK timezone).
package traffic

import (
	"context"
	"encoding/json"
	"log"
	"math"
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
	Month      string             `json:"month"`
	IPs        map[string]ipStats `json:"ips"`
	OrphanedTX int64              `json:"orphaned_tx"`
	OrphanedRX int64              `json:"orphaned_rx"`
	LastReset  string             `json:"last_reset,omitempty"`
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

func (m *Monitor) save(state fileFmt) {
	if err := os.MkdirAll(filepath.Dir(m.path), 0o750); err != nil {
		log.Printf("traffic: mkdir error: %v", err)
		return
	}
	tmpPath := m.path + ".tmp"
	// #nosec G304 -- Tmp file path is constructed from config
	f, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		log.Printf("traffic: save error (create tmp): %v", err)
		return
	}

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(state); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		log.Printf("traffic: save error (write tmp): %v", err)
		return
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		log.Printf("traffic: save error (sync tmp): %v", err)
		return
	}
	if err := f.Close(); err != nil {
        _ = os.Remove(tmpPath)
        log.Printf("traffic: save error (close tmp): %v", err)
        return
    }
	if err := os.Rename(tmpPath, m.path); err != nil {
		_ = os.Remove(tmpPath)
		log.Printf("traffic: save error (rename): %v", err)
	}
}

func (m *Monitor) checkMonthReset() *fileFmt {
	cur := nowMSK().Format("2006-01")
	if m.state.Month != cur {
		log.Printf("Monthly reset (MSK): %s → %s", m.state.Month, cur)
		m.state = m.empty()
		m.lastConn = make(map[connKey][2]uint64)
		
		cp := m.state
		cp.IPs = make(map[string]ipStats)
		return &cp
	}
	return nil
}

func (m *Monitor) Collect(countFunc func(string) int) {
	// TTL = half period: traffic.Loop runs with m.interval (default 30s),
	// so a 15s cache allows the HTTP /traffic handler to cheaply reuse
	// the same snapshot without blocking the collector.
	flows, err := m.ct.SnapshotUDP()
	if err != nil {
		log.Printf("traffic: conntrack snapshot error: %v", err)
		return
	}

	m.mu.Lock()
	resetState := m.checkMonthReset()

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
				diff := f.BytesOrig - prev[0]
				if diff > math.MaxInt64 {
					dtx = math.MaxInt64
				} else {
					dtx = int64(diff)
				}
			}
			if f.BytesReply >= prev[1] {
				diff := f.BytesReply - prev[1]
				if diff > math.MaxInt64 {
					drx = math.MaxInt64
				} else {
					drx = int64(diff)
				}
			}
		}
		if dtx > 0 || drx > 0 {
			if countFunc != nil && countFunc(f.SrcIP) == 0 {
				// Unauthorized / unknown IP - add to orphaned totals but do NOT allocate per-IP entry
				// to prevent Unbounded Memory Leak DDoS vector.
				m.state.OrphanedTX += dtx
				m.state.OrphanedRX += drx
				changed = true
				continue
			}

			s := m.state.IPs[f.SrcIP]
			s.TX += dtx
			s.RX += drx
			s.Updated = now
			m.state.IPs[f.SrcIP] = s
			changed = true
		}
	}
	m.lastConn = current
	var stateCopy *fileFmt
	if changed {
		cp := m.state
		cp.IPs = make(map[string]ipStats, len(m.state.IPs))
		for k, v := range m.state.IPs {
			cp.IPs[k] = v
		}
		stateCopy = &cp
	}
	m.mu.Unlock()

	if resetState != nil && !changed {
		m.save(*resetState)
	} else if stateCopy != nil {
		m.save(*stateCopy)
	}
}

func (m *Monitor) Loop(ctx context.Context, countFunc func(string) int) {
	log.Printf("traffic: started collector every %s", m.interval)
	t := time.NewTicker(m.interval)
	defer t.Stop()

	// First immediate collection on start
	m.Collect(countFunc)

	for {
		select {
		case <-ctx.Done():
			log.Println("traffic: shutdown signal received, saving final snapshot...")
			m.Collect(countFunc)
			return
		case <-t.C:
			m.Collect(countFunc)
		}
	}
}

// PerIP is the public struct for endpoints.
type PerIP struct {
	IP          string  `json:"ip,omitempty"`
	TXBytes     int64   `json:"tx_bytes"`
	RXBytes     int64   `json:"rx_bytes"`
	TotalBytes  int64   `json:"total_bytes"`
	TXHuman     string  `json:"tx_human"`
	RXHuman     string  `json:"rx_human"`
	TotalHuman  string  `json:"total_human"`
	ClientsOnIP int     `json:"clients_on_ip"`
	ClientIDs   []int64 `json:"client_ids"`
	Updated     string  `json:"updated,omitempty"`
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

func (m *Monitor) GetAll(refCount func(string) int, clients func(string) []int64) Summary {
	m.mu.Lock()
	if resetState := m.checkMonthReset(); resetState != nil {
		go m.save(*resetState)
	}
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
			Updated:     s.Updated,
		}
	}
	totalTX += m.state.OrphanedTX
	totalRX += m.state.OrphanedRX
	out.TotalTXBytes = totalTX
	out.TotalRXBytes = totalRX
	out.TotalBytes = totalTX + totalRX
	out.TotalTX = shell.FormatBytes(totalTX)
	out.TotalRX = shell.FormatBytes(totalRX)
	out.Total = shell.FormatBytes(totalTX + totalRX)
	out.IPCount = len(out.IPs)
	m.mu.Unlock()

	for ip, p := range out.IPs {
		p.ClientsOnIP = refCount(ip)
		ids := clients(ip)
		if ids == nil {
			ids = []int64{}
		}
		p.ClientIDs = ids
		out.IPs[ip] = p
	}

	return out
}

func (m *Monitor) GetIP(ip string, refCount func(string) int, clients func(string) []int64) (PerIP, []int64, string, bool) {
	m.mu.Lock()
	s, ok := m.state.IPs[ip]
	month := m.state.Month
	m.mu.Unlock()

	ids := clients(ip)
	if ids == nil {
		ids = []int64{}
	}
	
	if !ok {
		return PerIP{IP: ip, ClientIDs: ids}, ids, month, false
	}
	return PerIP{
		IP:          ip,
		TXBytes:     s.TX, RXBytes: s.RX, TotalBytes: s.TX + s.RX,
		TXHuman:     shell.FormatBytes(s.TX),
		RXHuman:     shell.FormatBytes(s.RX),
		TotalHuman:  shell.FormatBytes(s.TX + s.RX),
		ClientsOnIP: refCount(ip),
		ClientIDs:   ids,
		Updated:     s.Updated,
	}, ids, month, true
}

func (m *Monitor) Reset() string {
	m.mu.Lock()
	m.state = m.empty()
	m.lastConn = make(map[connKey][2]uint64)
	cp := m.state
	cp.IPs = make(map[string]ipStats)
	m.mu.Unlock()
	
	m.save(cp)
	log.Println("Traffic data manually reset")
	return cp.Month
}
