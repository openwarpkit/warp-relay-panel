// Package shell — тонкий wrapper для выполнения внешних команд.
// Все операции с iptables/ipset/tc/conntrack пока через shell. Под нагрузкой
// узкие места (traffic collector, online clients) можно потом перевести
// на netlink (ti-mo/conntrack, vishvananda/netlink), сохранив тот же API.
package shell

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/vishvananda/netlink"
)

var (
	defaultIfaceCache string
	defaultIfaceMu    sync.RWMutex
)

var ipv4Re = regexp.MustCompile(`^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$`)

// Run executes a shell command with timeout. Returns (rc, stdout, stderr).
func Run(cmd string, timeout time.Duration) (int, string, string) {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	c := exec.CommandContext(ctx, "/bin/sh", "-c", cmd)
	stdout, err := c.Output()
	stderrStr := ""
	rc := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			rc = exitErr.ExitCode()
			stderrStr = string(exitErr.Stderr)
		} else {
			rc = -1
			stderrStr = err.Error()
		}
	}
	return rc, strings.TrimSpace(string(stdout)), strings.TrimSpace(stderrStr)
}

// RunStdin executes `cmd` with the given string piped to stdin. Used for batch
// operations: `nft -f -`, `tc -batch -`, `iptables-restore`. One fork+exec per
// batch instead of N — снимает burst CPU при applyTC десятков IP сразу.
func RunStdin(cmd, stdin string, timeout time.Duration) (int, string, string) {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	c := exec.CommandContext(ctx, "/bin/sh", "-c", cmd)
	c.Stdin = strings.NewReader(stdin)
	var stderrBuf strings.Builder
	c.Stderr = &stderrBuf
	stdout, err := c.Output()
	rc := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			rc = exitErr.ExitCode()
		} else {
			rc = -1
			stderrBuf.WriteString(err.Error())
		}
	}
	return rc, strings.TrimSpace(string(stdout)), strings.TrimSpace(stderrBuf.String())
}

// ValidIPv4 — быстрая проверка по regex (полная валидация — net.ParseIP).
func ValidIPv4(ip string) bool {
	if !ipv4Re.MatchString(ip) {
		return false
	}
	addr := net.ParseIP(ip)
	return addr != nil && addr.To4() != nil
}

// FormatBytes форматирует байты в человекочитаемый вид (4.2 GB и т.п.).
func FormatBytes(b int64) string {
	const k = 1024.0
	units := []string{"B", "KB", "MB", "GB", "TB", "PB"}
	v := float64(b)
	if b < 0 {
		v = -v
	}
	i := 0
	for v >= k && i < len(units)-1 {
		v /= k
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%d %s", b, units[0])
	}
	sign := ""
	if b < 0 {
		sign = "-"
	}
	return fmt.Sprintf("%s%.1f %s", sign, v, units[i])
}

// DefaultIface возвращает имя дефолтного интерфейса (например "eth0").
func DefaultIface() string {
	defaultIfaceMu.RLock()
	if defaultIfaceCache != "" {
		defer defaultIfaceMu.RUnlock()
		return defaultIfaceCache
	}
	defaultIfaceMu.RUnlock()

	defaultIfaceMu.Lock()
	defer defaultIfaceMu.Unlock()
	if defaultIfaceCache != "" {
		return defaultIfaceCache
	}

	routes, err := netlink.RouteList(nil, netlink.FAMILY_V4)
	if err == nil {
		for _, r := range routes {
			if r.Dst == nil { // default route
				link, err := netlink.LinkByIndex(r.LinkIndex)
				if err == nil {
					defaultIfaceCache = link.Attrs().Name
					return defaultIfaceCache
				}
			}
		}
	}

	_, out, _ := Run("ip route | awk '/default/ {print $5; exit}'", 5*time.Second)
	defaultIfaceCache = out
	return out
}
