package servermin

import (
	"cmp"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/nellimonix/warp-relay-panel/relay-agent/internal/shell"
)

func (s *Server) loadStatusFile(path string) interface{} {
	// #nosec G304 -- Status file path is controlled by config
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

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	fwd := "0"
	if data, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward"); err == nil {
		fwd = strings.TrimSpace(string(data))
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

	t := s.Traffic.GetAll(noRefcount, noClients)
	online := s.onlineClients()
	mtx := s.Metrics.Snapshot()
	cfg := s.SharedLimit.Cfg()

	resp := map[string]interface{}{
		"status":         "ok",
		"agent_type":     "min",
		"version":        s.Version,
		"uptime_seconds": int(time.Since(s.StartTime).Seconds()),
		"ip_forward":     fwd == "1",
		"online_clients": online["count"],
		"shaped_clients": s.SharedLimit.Count(),
		"shared_limit":   map[string]interface{}{
			"mbps":          cfg.LimitMbps,
			"scan_interval": int(cfg.ScanInterval.Seconds()),
			"idle_grace":    int(cfg.IdleGrace.Seconds()),
			"dst_ip":        cfg.DstIP,
			"warp_ports":    len(cfg.Ports),
		},
		"conntrack": fmt.Sprintf("%s/%s", ctCur, ctMax),
		"load":      loadVal,
		"memory_mb": map[string]int{
			"used":  (memUsed + 512) / 1024,
			"total": (memTotal + 512) / 1024,
		},
		"cpu_percent_total":    mtx.CPUPercentTotal,
		"cpu_percent_per_core": mtx.CPUPercentPerCore,
		"cpu_count":            mtx.CPUCount,
		"agent_process":        mtx.AgentProcess,
		"network_speed":        mtx.NetworkSpeed,
		"disk":                 s.Metrics.Disk(),
		"traffic_month":        t.Month,
		"traffic_total":        t.Total,
		"traffic_ips":          t.IPCount,
		"last_update":          s.loadStatusFile(s.Cfg.DataDir + "/update_status.json"),
		"last_self_heal":       s.Watchdog.LastStatus(),
	}
	writeJSON(w, 200, resp)
}

// noRefcount - min-agent has no refcount, but Traffic expects a callback.
// Returns 0 for all IPs ("clients_on_ip" field in /traffic will be 0).
func noRefcount(ip string) int { return 0 }

func noClients(ip string) []int64 { return nil }

func (s *Server) onlineClients() map[string]interface{} {
	// 2s cache - deduplicate parallel /health and /stats from panel.
	assured, err := s.Conntrack.AssuredUDPSrcs()
	if err != nil {
		assured = map[string]struct{}{}
	}
	online := make([]string, 0, len(assured))
	for ip := range assured {
		online = append(online, ip)
	}
	slices.Sort(online)
	clients := make([]map[string]interface{}, 0, len(online))
	for _, ip := range online {
		clients = append(clients, map[string]interface{}{"ip": ip})
	}
	return map[string]interface{}{
		"count":             len(online),
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

	type portCount struct {
		Port  uint16
		Count int
	}
	pc := make([]portCount, 0, len(stats.TopPorts))
	for p, c := range stats.TopPorts {
		pc = append(pc, portCount{p, c})
	}
	slices.SortFunc(pc, func(a, b portCount) int { return cmp.Compare(b.Count, a.Count) })
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
		"agent_type": "min",
		"online":     online,
		"sessions":   map[string]int{"assured": stats.Assured, "unreplied": stats.Unreplied},
		"top_ports":  topPorts,
		"network":    speed,
		"traffic":    s.Traffic.GetAll(noRefcount, noClients),
	})
}

func readSysfsInt(path string) int64 {
	// #nosec G304 -- Sysfs path is constructed from interface name
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	n, _ := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	return n
}
