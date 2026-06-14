// Package watchdog checks firewall + tc rules integrity
// and restores them if missing.
package watchdog

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/openwarpkit/warp-relay-panel/relay-agent/internal/ipsetgo"
	"github.com/openwarpkit/warp-relay-panel/relay-agent/internal/ratelimit"
	"github.com/openwarpkit/warp-relay-panel/relay-agent/internal/refcount"
	"github.com/openwarpkit/warp-relay-panel/relay-agent/internal/shell"
)

type Status struct {
	Timestamp string   `json:"timestamp"`
	Broken    []string `json:"broken,omitempty"`
	Actions   []string `json:"actions,omitempty"`
}

type Watchdog struct {
	IpsetName        string
	EnsureScriptPath string
	StatusFilePath   string
	Refcount         *refcount.Map      // can be nil (min-agent)
	RateLimit        *ratelimit.Manager // can be nil
	SkipIpset        bool               // true for min-agent (no whitelist)
	ForwardTags      []string           // comment tags to expect in FORWARD ("WR_WHITELIST_OUT" for full, "WR_FORWARD_OUT" for min)
}

type Checks struct {
	Ipset      bool
	NAT        bool
	Forward    bool
	IPForward  bool
	HTB        bool
	NftShaper  bool // nft table warp_shaper + map ip2mark
	FlowFilter bool // tc root "flow map keys nfmark" filter
}

func (w *Watchdog) check() Checks {
	var c Checks

	if w.SkipIpset {
		c.Ipset = true
	} else {
		c.Ipset = ipsetgo.Exists(w.IpsetName)
	}

	_, natOut, _ := shell.Run("iptables -t nat -S 2>/dev/null", 5*time.Second)
	c.NAT = strings.Contains(natOut, "WR_RULE")

	_, fwdOut, _ := shell.Run("iptables -S FORWARD 2>/dev/null", 5*time.Second)
	tags := w.ForwardTags
	if len(tags) == 0 {
		tags = []string{"WR_WHITELIST_OUT", "WR_WHITELIST_IN"}
	}
	c.Forward = true
	for _, t := range tags {
		if !strings.Contains(fwdOut, t) {
			c.Forward = false
			break
		}
	}

	// #nosec G304 -- Reading static kernel sysfs path is safe
	if data, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward"); err == nil {
		c.IPForward = strings.TrimSpace(string(data)) == "1"
	}

	iface := shell.DefaultIface()
	c.HTB = true
	if iface != "" {
		rc, out, _ := shell.Run(fmt.Sprintf("tc qdisc show dev %s 2>/dev/null", iface), 5*time.Second)
		c.HTB = rc == 0 && strings.Contains(out, "qdisc htb 1:")
	}

	// nftables warp_shaper + tc flow filter - only if backend is not disabled.
	// Skip if nft binary is missing (legacy iptables mode).
	useNft := os.Getenv("RATELIMIT_BACKEND") != "iptables"
	if useNft {
		rcNft, _, _ := shell.Run("nft list table ip warp_shaper >/dev/null 2>&1", 5*time.Second)
		c.NftShaper = (rcNft == 0)
		c.FlowFilter = true
		if iface != "" {
			rc, out, _ := shell.Run(fmt.Sprintf("tc filter show dev %s parent 1:0 2>/dev/null", iface), 5*time.Second)
			// Real output in iproute2 6.x: "filter ... flow chain 0 handle 0x1 map keys mark ..."
			c.FlowFilter = rc == 0 && strings.Contains(out, "flow chain")
		}
	} else {
		// in iptables mode these checks are not relevant - return true to avoid heal
		c.NftShaper = true
		c.FlowFilter = true
	}
	return c
}

func brokenList(c Checks) []string {
	out := []string{}
	if !c.Ipset {
		out = append(out, "ipset")
	}
	if !c.NAT {
		out = append(out, "nat")
	}
	if !c.Forward {
		out = append(out, "forward")
	}
	if !c.IPForward {
		out = append(out, "ip_forward")
	}
	if !c.HTB {
		out = append(out, "htb")
	}
	if !c.NftShaper {
		out = append(out, "nft_shaper")
	}
	if !c.FlowFilter {
		out = append(out, "flow_filter")
	}
	return out
}

func (w *Watchdog) heal(c Checks) []string {
	actions := []string{}
	if !c.Ipset || !c.NAT || !c.Forward || !c.HTB || !c.NftShaper || !c.FlowFilter {
		if _, err := os.Stat(w.EnsureScriptPath); err == nil {
			shell.Run(fmt.Sprintf("bash %s 2>&1", w.EnsureScriptPath), 60*time.Second)
			actions = append(actions, "ran ensure_rules.sh")
		} else {
			log.Printf("ensure_rules.sh not found at %s", w.EnsureScriptPath)
		}
	}
	if !c.IPForward {
		shell.Run("sysctl -w net.ipv4.ip_forward=1 2>/dev/null", 5*time.Second)
		actions = append(actions, "enabled ip_forward")
	}

	// After ensure_rules.sh - rebuild ipset from refcount if necessary
	// (only for full-agent; min doesn't have ipset/refcount)
	if !w.SkipIpset && w.Refcount != nil {
		after := w.check()
		if after.Ipset {
			current, err := ipsetgo.Members(w.IpsetName)
			if err == nil {
				expected := w.Refcount.IPs()
				missing := []string{}
				for _, ip := range expected {
					if _, ok := current[ip]; !ok {
						missing = append(missing, ip)
					}
				}
				if len(missing) > 0 {
					for _, ip := range missing {
						if err := ipsetgo.Add(w.IpsetName, ip); err != nil {
							log.Printf("watchdog: re-add %s: %v", ip, err)
						}
					}
					shell.Run("ipset save > /etc/ipset.rules 2>/dev/null", 10*time.Second)
					actions = append(actions, fmt.Sprintf("re-added %d IPs to ipset from refcount", len(missing)))
				}
			}
		}
	}

	return actions
}

// reconcileRateLimits reapplies limits on nft-map / tc-classes drift.
// Runs every tick independently of firewall checks.
func (w *Watchdog) reconcileRateLimits() {
	if w.RateLimit == nil {
		return
	}
	broken := w.RateLimit.Verify()
	if len(broken) == 0 {
		return
	}
	applied, _ := w.RateLimit.RestoreAll()
	log.Printf("Self-heal: rate-limit drift (%d missing) -> restored %d", len(broken), len(applied))
	w.saveStatus(Status{
		Timestamp: time.Now().In(time.FixedZone("MSK", 3*3600)).Format(time.RFC3339),
		Broken:    []string{fmt.Sprintf("rate_limit_drift:%d", len(broken))},
		Actions:   []string{fmt.Sprintf("restored %d rate-limits", len(applied))},
	})
}

func (w *Watchdog) saveStatus(s Status) {
	if err := os.MkdirAll(filepath.Dir(w.StatusFilePath), 0o750); err != nil {
		log.Printf("watchdog: mkdir error: %v", err)
		return
	}

	tmpPath := w.StatusFilePath + ".tmp"
	// #nosec G304 -- Tmp file path is constructed from config
	f, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		log.Printf("watchdog: create tmp file error: %v", err)
		return
	}

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(s); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		log.Printf("watchdog: write tmp file error: %v", err)
		return
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		log.Printf("watchdog: sync tmp file error: %v", err)
		return
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmpPath)
		log.Printf("watchdog: close tmp file error: %v", err)
		return
	}
	if err := os.Rename(tmpPath, w.StatusFilePath); err != nil {
		_ = os.Remove(tmpPath)
		log.Printf("watchdog: rename error: %v", err)
	}
}

// LastStatus reads from disk (for /health).
func (w *Watchdog) LastStatus() *Status {
	// #nosec G304 -- Status file path is controlled by config
	data, err := os.ReadFile(w.StatusFilePath)
	if err != nil {
		return nil
	}
	var s Status
	if err := json.Unmarshal(data, &s); err != nil {
		return nil
	}
	return &s
}

func (w *Watchdog) Loop(ctx context.Context, interval time.Duration) {
	log.Printf("Rules watchdog started (interval=%s)", interval)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c := w.check()
			broken := brokenList(c)
			if len(broken) > 0 {
				log.Printf("Self-heal: broken=%v", broken)
				actions := w.heal(c)
				w.saveStatus(Status{
					Timestamp: time.Now().In(time.FixedZone("MSK", 3*3600)).Format(time.RFC3339),
					Broken:    broken,
					Actions:   actions,
				})
				log.Printf("Self-heal actions: %v", actions)
			}
			w.reconcileRateLimits()
		}
	}
}
