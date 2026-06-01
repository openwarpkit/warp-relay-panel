package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nellimonix/warp-relay-panel/relay-agent/internal/ipsetgo"
	"github.com/nellimonix/warp-relay-panel/relay-agent/internal/shell"
)

func (s *Server) loadStatusFile(path string) interface{} {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var v interface{}
	if err := json.Unmarshal(data, &v); err != nil {
		return nil
	}
	return v
}

func (s *Server) saveSyncStatus(status map[string]interface{}) {
	path := s.Cfg.DataDir + "/sync_status.json"
	os.MkdirAll(s.Cfg.DataDir, 0o755)
	data, _ := json.MarshalIndent(status, "", "  ")
	tmpPath := path + ".tmp"
	f, err := os.Create(tmpPath)
	if err != nil {
		return
	}
	defer f.Close()

	if _, err := f.Write(data); err != nil {
		return
	}
	if err := f.Sync(); err != nil {
		return
	}
	if err := f.Close(); err != nil {
		return
	}
	os.Rename(tmpPath, path)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	fwd := "0"
	if data, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward"); err == nil {
		fwd = strings.TrimSpace(string(data))
	}

	ipsetCnt := 0
	if n, err := ipsetgo.Count(s.Cfg.IpsetName); err == nil {
		ipsetCnt = n
	}

	ctCur, ctMax := "0", "0"
	if data, err := os.ReadFile("/proc/sys/net/netfilter/nf_conntrack_count"); err == nil {
		ctCur = strings.TrimSpace(string(data))
	}
	if data, err := os.ReadFile("/proc/sys/net/netfilter/nf_conntrack_max"); err == nil {
		ctMax = strings.TrimSpace(string(data))
	}

	loadVal := 0.0
	if data, err := os.ReadFile("/proc/loadavg"); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) > 0 {
			loadVal, _ = strconv.ParseFloat(fields[0], 64)
		}
	}

	memTotal, memAvail := 0, 0
	if data, err := os.ReadFile("/proc/meminfo"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				key := strings.TrimSuffix(fields[0], ":")
				v, _ := strconv.Atoi(fields[1])
				if key == "MemTotal" {
					memTotal = v
				}
				if key == "MemAvailable" {
					memAvail = v
				}
			}
		}
	}
	memUsed := memTotal - memAvail

	t := s.Traffic.GetAll(s.Refcount.Count, s.Refcount.ClientsFor)
	online := s.onlineClients()
	metrics := s.Metrics.Snapshot()

	resp := map[string]interface{}{
		"status":         "ok",
		"version":        s.Version,
		"uptime_seconds": int(time.Since(s.StartTime).Seconds()),
		"ip_forward":     fwd == "1",
		"ipset_count":    ipsetCnt,
		"online_clients": online["count"],
		"conntrack":      fmt.Sprintf("%s/%s", ctCur, ctMax),
		"load":           loadVal,
		"memory_mb": map[string]int{
			"used":  (memUsed + 512) / 1024,
			"total": (memTotal + 512) / 1024,
		},
		"cpu_percent_total":    metrics.CPUPercentTotal,
		"cpu_percent_per_core": metrics.CPUPercentPerCore,
		"cpu_count":            metrics.CPUCount,
		"agent_process":        metrics.AgentProcess,
		"network_speed":        metrics.NetworkSpeed,
		"disk":                 s.Metrics.Disk(),
		"rate_limits_count":    s.RateLimit.Count(),
		"traffic_month":        t.Month,
		"traffic_total":        t.Total,
		"traffic_ips":          t.IPCount,
		"last_update":          s.loadStatusFile(s.Cfg.DataDir + "/update_status.json"),
		"last_sync":            s.loadStatusFile(s.Cfg.DataDir + "/sync_status.json"),
		"last_self_heal":       s.Watchdog.LastStatus(),
	}
	writeJSON(w, 200, resp)
}

func (s *Server) onlineClients() map[string]interface{} {
	whitelist, _ := ipsetgo.Members(s.Cfg.IpsetName)
	// 2s cache - deduplicate parallel /health, /stats, /online from panel.
	assured, err := s.Conntrack.AssuredUDPSrcs()
	if err != nil {
		assured = map[string]struct{}{}
	}
	onlineIPs := []string{}
	for ip := range whitelist {
		if _, ok := assured[ip]; ok {
			onlineIPs = append(onlineIPs, ip)
		}
	}
	sort.Strings(onlineIPs)
	clients := []map[string]interface{}{}
	for _, ip := range onlineIPs {
		clients = append(clients, map[string]interface{}{
			"ip":         ip,
			"client_ids": s.Refcount.ClientsFor(ip),
		})
	}
	return map[string]interface{}{
		"count":             len(onlineIPs),
		"whitelist_total":   len(whitelist),
		"conntrack_assured": len(assured),
		"clients":           clients,
	}
}

// /stats
func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	online := s.onlineClients()

	stats, err := s.Conntrack.StatsUDP()
	if err != nil {
		writeError(w, 500, "conntrack stats: "+err.Error())
		return
	}

	// top 10 dport
	type portCount struct {
		Port  uint16
		Count int
	}
	pc := make([]portCount, 0, len(stats.TopPorts))
	for p, c := range stats.TopPorts {
		pc = append(pc, portCount{p, c})
	}
	sort.Slice(pc, func(i, j int) bool { return pc[i].Count > pc[j].Count })
	if len(pc) > 10 {
		pc = pc[:10]
	}
	topPorts := map[string]int{}
	for _, p := range pc {
		topPorts[strconv.Itoa(int(p.Port))] = p.Count
	}

	iface := shell.DefaultIface()
	speed := map[string]interface{}{}
	if iface != "" {
		rxBytes := readSysfsInt("/sys/class/net/" + iface + "/statistics/rx_bytes")
		txBytes := readSysfsInt("/sys/class/net/" + iface + "/statistics/tx_bytes")
		speed = map[string]interface{}{
			"interface":      iface,
			"rx_bytes_total": rxBytes,
			"tx_bytes_total": txBytes,
		}
	}

	writeJSON(w, 200, map[string]interface{}{
		"online":    online,
		"sessions":  map[string]int{"assured": stats.Assured, "unreplied": stats.Unreplied},
		"top_ports": topPorts,
		"network":   speed,
		"traffic":   s.Traffic.GetAll(s.Refcount.Count, s.Refcount.ClientsFor),
	})
}

func readSysfsInt(path string) int64 {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	n, _ := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	return n
}
