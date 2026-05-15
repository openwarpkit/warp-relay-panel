// Package ipsetgo — netlink-обёртка вокруг github.com/vishvananda/netlink
// для ipset-операций. Заменяет shell-вызовы ipset.
//
// Save (ipset save > /etc/ipset.rules) намеренно остаётся через shell:
// формат файла — ipset-CLI-специфичный, дёргается раз в дебаунс (~3s),
// не имеет смысла переписывать.
package ipsetgo

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/vishvananda/netlink"
)

// Add добавляет IP в ipset. Идемпотентно — EEXIST не считается ошибкой.
func Add(setname, ipStr string) error {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return fmt.Errorf("invalid ip: %s", ipStr)
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	err := netlink.IpsetAdd(setname, &netlink.IPSetEntry{IP: ip})
	if err != nil && !isEexist(err) {
		return err
	}
	return nil
}

// Del удаляет IP из ipset. Идемпотентно — ENOENT не считается ошибкой.
func Del(setname, ipStr string) error {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return fmt.Errorf("invalid ip: %s", ipStr)
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	err := netlink.IpsetDel(setname, &netlink.IPSetEntry{IP: ip})
	if err != nil && !isEnoent(err) {
		return err
	}
	return nil
}

// Members возвращает все IP в ipset как set.
func Members(setname string) (map[string]struct{}, error) {
	res, err := netlink.IpsetList(setname)
	if err != nil {
		return nil, err
	}
	out := make(map[string]struct{}, len(res.Entries))
	for _, e := range res.Entries {
		if e.IP != nil {
			out[e.IP.String()] = struct{}{}
		}
	}
	return out, nil
}

// Count — число элементов. Использует NumEntries из дампа метаданных.
func Count(setname string) (int, error) {
	res, err := netlink.IpsetList(setname)
	if err != nil {
		return 0, err
	}
	if res.NumEntries > 0 {
		return int(res.NumEntries), nil
	}
	return len(res.Entries), nil
}

// Exists возвращает true, если ipset существует.
func Exists(setname string) bool {
	_, err := netlink.IpsetList(setname)
	return err == nil
}

// Flush очищает ipset.
func Flush(setname string) error {
	return netlink.IpsetFlush(setname)
}

// Create создаёт ipset hash:ip с заданным maxelem. Идемпотентно (Replace=false).
// Если уже существует с тем же типом — ошибка не считается ошибкой.
func Create(setname string, maxelem uint32) error {
	err := netlink.IpsetCreate(setname, "hash:ip", netlink.IpsetCreateOptions{
		MaxElements: maxelem,
		Family:      2, // AF_INET (IPv4)
	})
	if err != nil && !isEexist(err) {
		return err
	}
	return nil
}

func isEexist(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "exist") || errors.Is(err, errEEXIST)
}

func isEnoent(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "not exist") || strings.Contains(s, "no such") ||
		strings.Contains(s, "enoent") || errors.Is(err, errENOENT)
}

// errEEXIST/ENOENT — фантомные ошибки для errors.Is fallback.
// vishvananda/netlink возвращает текстовые ошибки, не syscall.Errno напрямую,
// поэтому опираемся на text-match.
var (
	errEEXIST = errors.New("EEXIST")
	errENOENT = errors.New("ENOENT")
)
