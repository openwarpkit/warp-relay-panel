package config

import (
	"context"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// ResolveDstIP returns WarpDstIP, if empty - resolves via DNS.
func (c Config) ResolveDstIP() (string, error) {
	if c.WarpDstIP != "" {
		return c.WarpDstIP, nil
	}
	hn := c.WarpDstHostname
	if hn == "" {
		hn = "engage.cloudflareclient.com"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	r := &net.Resolver{}
	addrs, err := r.LookupHost(ctx, hn)
	if err != nil {
		return "", err
	}
	for _, a := range addrs {
		ip := net.ParseIP(a)
		if ip != nil && ip.To4() != nil {
			return ip.String(), nil
		}
	}
	return "", net.UnknownNetworkError("no IPv4 for " + hn)
}

type Config struct {
	AgentSecret           string
	AgentPort             int
	IpsetName             string
	DataDir               string
	RepoDir               string
	TrafficInterval       int
	RulesWatchdogInterval int
	MetricsSampleInterval int
	IpsetPersistDebounce  float64

	PanelURL    string
	PanelAPIKey string
	RelayID     string

	RateLimitMarkMin int
	RateLimitMarkMax int

	// Min-agent (shared limit) - ignored by full-agent.
	SharedLimitMbps    float64
	SharedScanInterval int      // sec
	SharedIdleGrace    int      // sec
	WarpDstIP          string   // "" = auto-detect (engage.cloudflareclient.com)
	WarpPorts          []uint16 // default - embed
	WarpDstHostname    string   // auto-detect source (default engage.cloudflareclient.com)
}

func Load() Config {
	return Config{
		AgentSecret:           env("AGENT_SECRET", "change-me"),
		AgentPort:             envInt("AGENT_PORT", 7580),
		IpsetName:             env("IPSET_NAME", "warp_whitelist"),
		DataDir:               env("DATA_DIR", "/opt/warp-relay-agent"),
		RepoDir:               env("REPO_DIR", "/opt/warp-relay-panel"),
		TrafficInterval:       envInt("TRAFFIC_INTERVAL", 30),
		RulesWatchdogInterval: envInt("RULES_WATCHDOG_INTERVAL", 30),
		MetricsSampleInterval: envInt("METRICS_SAMPLE_INTERVAL", 1),
		IpsetPersistDebounce:  envFloat("IPSET_PERSIST_DEBOUNCE", 3.0),

		PanelURL:    strings.TrimRight(env("PANEL_URL", ""), "/"),
		PanelAPIKey: env("PANEL_API_KEY", ""),
		RelayID:     env("RELAY_ID", ""),

		RateLimitMarkMin: 10,
		RateLimitMarkMax: 998,

		SharedLimitMbps:    envFloat("SHARED_LIMIT_MBPS", 25.0),
		SharedScanInterval: envInt("SHARED_SCAN_INTERVAL", 30),
		SharedIdleGrace:    envInt("SHARED_IDLE_GRACE", 60),
		WarpDstIP:          env("WARP_DST_IP", ""),
		WarpDstHostname:    env("WARP_DST_HOSTNAME", "engage.cloudflareclient.com"),
		WarpPorts:          parsePorts(env("WARP_PORTS", "")),
	}
}

// DefaultWarpPorts - list of UDP ports for WARP, same as setup_relay.sh.
var DefaultWarpPorts = []uint16{
	500, 854, 859, 864, 878, 880, 890, 891, 894, 903, 908, 928, 934, 939,
	942, 943, 945, 946, 955, 968, 987, 988, 1002, 1010, 1014, 1018, 1070,
	1074, 1180, 1387, 1701, 1843, 2371, 2408, 2506, 3138, 3476, 3581, 3854,
	4177, 4198, 4233, 4500, 5279, 5956, 7103, 7152, 7156, 7281, 7559, 8319,
	8742, 8854, 8886,
}

// parsePorts: "500,854,..." -> []uint16. Empty string -> DefaultWarpPorts.
func parsePorts(s string) []uint16 {
	if s == "" {
		return DefaultWarpPorts
	}
	out := []uint16{}
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			continue
		}
		out = append(out, uint16(n))
	}
	if len(out) == 0 {
		return DefaultWarpPorts
	}
	return out
}

func env(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func envFloat(key string, def float64) float64 {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
	}
	return def
}
