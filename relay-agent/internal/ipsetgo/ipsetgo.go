// Package ipsetgo is a netlink-wrapper around github.com/vishvananda/netlink
// for ipset operations. Replaces shell calls to ipset.
//
// Save (ipset save > /etc/ipset.rules) intentionally remains via shell:
// the file format is ipset-CLI specific, triggered once per debounce (~3s),
// doesn't make sense to rewrite.
package ipsetgo

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"syscall"

	"github.com/vishvananda/netlink"
)

// Add adds an IP to the ipset. Idempotent - EEXIST is not an error.
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

// Del removes an IP from the ipset. Idempotent - ENOENT is not an error.
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

// Members returns all IPs in the ipset as a set.
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

// Count returns the number of elements. Uses NumEntries from metadata dump.
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

// Exists returns true if the ipset exists.
func Exists(setname string) bool {
	_, err := netlink.IpsetList(setname)
	return err == nil
}

// Flush clears the ipset.
func Flush(setname string) error {
	return netlink.IpsetFlush(setname)
}

// Create creates an ipset hash:ip with given maxelem. Idempotent (Replace=false).
// If it already exists with the same type, error is not considered an error.
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

// Destroy destroys the ipset.
func Destroy(setname string) error {
	return netlink.IpsetDestroy(setname)
}

// Swap swaps the content of two ipsets.
func Swap(setname1, setname2 string) error {
	return netlink.IpsetSwap(setname1, setname2)
}

func isEexist(err error) bool {
	if err == nil {
		return false
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		if errno == syscall.EEXIST {
			return true
		}
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "file exists") || strings.Contains(s, "already added") || strings.Contains(s, "already exists")
}

func isEnoent(err error) bool {
	if err == nil {
		return false
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		if errno == syscall.ENOENT {
			return true
		}
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "no such file") || strings.Contains(s, "not added") || strings.Contains(s, "does not exist")
}
