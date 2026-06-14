// Package metrics is a background sampler for CPU/network/process via gopsutil.
package metrics

import (
	"context"
	"log"
	"os"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/process"

	"github.com/openwarpkit/warp-relay-panel/relay-agent/internal/shell"
)

type NetworkSpeed struct {
	RxBps   int64  `json:"rx_bps"`
	TxBps   int64  `json:"tx_bps"`
	RxHuman string `json:"rx_human"`
	TxHuman string `json:"tx_human"`
}

type AgentProcess struct {
	CPUPercent float64 `json:"cpu_percent"`
	MemoryMB   float64 `json:"memory_mb"`
	NumThreads int32   `json:"num_threads"`
	NumFDs     int32   `json:"num_fds"`
}

type DiskUsage struct {
	TotalGB float64 `json:"total_gb"`
	UsedGB  float64 `json:"used_gb"`
	FreeGB  float64 `json:"free_gb"`
	Percent float64 `json:"percent"`
}

type Snapshot struct {
	CPUPercentTotal   float64      `json:"cpu_percent_total"`
	CPUPercentPerCore []float64    `json:"cpu_percent_per_core"`
	CPUCount          int          `json:"cpu_count"`
	NetworkSpeed      NetworkSpeed `json:"network_speed"`
	AgentProcess      AgentProcess `json:"agent_process"`
}

type Sampler struct {
	mu       sync.RWMutex
	interval time.Duration
	dataDir  string

	cpuTotal   float64
	cpuPerCore []float64
	netSpeed   NetworkSpeed
	procStats  AgentProcess

	proc *process.Process

	lastNet [3]int64 // rx, tx, ts(ns)
}

func New(interval time.Duration, dataDir string) *Sampler {
	// #nosec G115 -- Linux PID always fits in int32
	p, err := process.NewProcess(int32(os.Getpid()))
	if err != nil {
		log.Printf("metrics: cannot get process: %v", err)
	}
	return &Sampler{
		interval: interval,
		dataDir:  dataDir,
		proc:     p,
	}
}

func (s *Sampler) Snapshot() Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cnt, _ := cpu.Counts(true)
	return Snapshot{
		CPUPercentTotal:   s.cpuTotal,
		CPUPercentPerCore: s.cpuPerCore,
		CPUCount:          cnt,
		NetworkSpeed:      s.netSpeed,
		AgentProcess:      s.procStats,
	}
}

func (s *Sampler) Disk() DiskUsage {
	path := s.dataDir
	if _, err := os.Stat(path); err != nil {
		path = "/"
	}
	d, err := disk.Usage(path)
	if err != nil {
		return DiskUsage{}
	}
	return DiskUsage{
		TotalGB: round2(float64(d.Total) / (1024 * 1024 * 1024)),
		UsedGB:  round2(float64(d.Used) / (1024 * 1024 * 1024)),
		FreeGB:  round2(float64(d.Free) / (1024 * 1024 * 1024)),
		Percent: round2(d.UsedPercent),
	}
}

func round2(f float64) float64 {
	return float64(int(f*100)) / 100
}

func (s *Sampler) Loop(ctx context.Context) {
	// Warmup
	_, _ = cpu.Percent(0, false)
	_, _ = cpu.Percent(0, true)
	if s.proc != nil {
		_, _ = s.proc.CPUPercent()
	}

	iface := shell.DefaultIface()
	t := time.NewTicker(s.interval)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.sample(iface)
		}
	}
}

func (s *Sampler) sample(iface string) {
	totals, err := cpu.Percent(0, false)
	var total float64
	if err == nil && len(totals) > 0 {
		total = round2(totals[0])
	}
	perCore, err := cpu.Percent(0, true)
	if err == nil {
		for i, v := range perCore {
			perCore[i] = round2(v)
		}
	}

	var procStats AgentProcess
	if s.proc != nil {
		if cpuPct, err := s.proc.CPUPercent(); err == nil {
			procStats.CPUPercent = round2(cpuPct)
		}
		if mi, err := s.proc.MemoryInfo(); err == nil {
			procStats.MemoryMB = round2(float64(mi.RSS) / (1024 * 1024))
		}
		if nt, err := s.proc.NumThreads(); err == nil {
			procStats.NumThreads = nt
		}
		if nfd, err := s.proc.NumFDs(); err == nil {
			procStats.NumFDs = nfd
		}
	}

	var ns NetworkSpeed
	if iface != "" {
		rx := readInt64("/sys/class/net/" + iface + "/statistics/rx_bytes")
		tx := readInt64("/sys/class/net/" + iface + "/statistics/tx_bytes")
		ts := time.Now().UnixNano()
		s.mu.Lock()
		if s.lastNet[2] != 0 {
			dt := float64(ts-s.lastNet[2]) / 1e9
			if dt > 0 {
				ns.RxBps = int64(float64(maxInt64(rx-s.lastNet[0], 0)) / dt)
				ns.TxBps = int64(float64(maxInt64(tx-s.lastNet[1], 0)) / dt)
			}
		}
		s.lastNet = [3]int64{rx, tx, ts}
		ns.RxHuman = shell.FormatBytes(ns.RxBps) + "/s"
		ns.TxHuman = shell.FormatBytes(ns.TxBps) + "/s"
		s.mu.Unlock()
	}

	s.mu.Lock()
	s.cpuTotal = total
	s.cpuPerCore = perCore
	s.procStats = procStats
	s.netSpeed = ns
	s.mu.Unlock()
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func readInt64(path string) int64 {
	// #nosec G304 -- Reading counters from /sys
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	v, _ := parseInt64(string(data))
	return v
}

func parseInt64(s string) (int64, error) {
	var n int64
	for _, ch := range s {
		if ch == '\n' || ch == ' ' || ch == '\t' || ch == '\r' {
			continue
		}
		if ch < '0' || ch > '9' {
			break
		}
		n = n*10 + int64(ch-'0')
	}
	return n, nil
}
