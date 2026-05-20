// Package watchdog проверяет целостность правил firewall + tc
// и восстанавливает их при пропаже.
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

	"github.com/nellimonix/warp-relay-panel/relay-agent/internal/ipsetgo"
	"github.com/nellimonix/warp-relay-panel/relay-agent/internal/ratelimit"
	"github.com/nellimonix/warp-relay-panel/relay-agent/internal/refcount"
	"github.com/nellimonix/warp-relay-panel/relay-agent/internal/shell"
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
	Refcount         *refcount.Map      // может быть nil (min-agent)
	RateLimit        *ratelimit.Manager // может быть nil
	SkipIpset        bool               // true для min-agent (нет whitelist)
	ForwardTags      []string           // какие comment-теги ждать в FORWARD ("WR_WHITELIST_OUT" для full, "WR_FORWARD_OUT" для min)
}

type Checks struct {
	Ipset     bool
	NAT       bool
	Forward   bool
	IPForward bool
	HTB       bool
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

	if data, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward"); err == nil {
		c.IPForward = strings.TrimSpace(string(data)) == "1"
	}

	iface := shell.DefaultIface()
	c.HTB = true
	if iface != "" {
		rc, out, _ := shell.Run(fmt.Sprintf("tc qdisc show dev %s 2>/dev/null", iface), 5*time.Second)
		c.HTB = rc == 0 && strings.Contains(out, "qdisc htb 1:")
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
	return out
}

func (w *Watchdog) heal(c Checks) []string {
	actions := []string{}
	if !c.Ipset || !c.NAT || !c.Forward || !c.HTB {
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

	// После ensure_rules.sh — пересобрать ipset из refcount, если надо
	// (только для full-агента; min не имеет ipset/refcount)
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

	// Rate-limit'ы (для full — из API; для min — переприменит sharedlimit на следующем reconcile,
	// но Verify+RestoreAll работает и для min, т.к. sharedlimit пишет в тот же rate_limits.json).
	if w.RateLimit != nil {
		broken := w.RateLimit.Verify()
		if len(broken) > 0 {
			applied, _ := w.RateLimit.RestoreAll()
			actions = append(actions, fmt.Sprintf("restored %d rate-limits", len(applied)))
		}
	}

	return actions
}

func (w *Watchdog) saveStatus(s Status) {
	if err := os.MkdirAll(filepath.Dir(w.StatusFilePath), 0o755); err != nil {
		log.Printf("watchdog: mkdir error: %v", err)
		return
	}
	data, _ := json.MarshalIndent(s, "", "  ")
	os.WriteFile(w.StatusFilePath, data, 0o644)
}

// LastStatus читает с диска (для /health).
func (w *Watchdog) LastStatus() *Status {
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
		}
	}
}
