package conntrackgo

import (
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ti-mo/conntrack"
	"github.com/ti-mo/netfilter"
)

const protoUDP = 17

// UDPFlow — минимальный набор для traffic accounting.
type UDPFlow struct {
	SrcIP      string
	DstIP      string
	SrcPort    uint16
	DstPort    uint16
	BytesOrig  uint64
	BytesReply uint64
	Assured    bool
}

type FlowKey struct {
	SrcIP   string
	DstIP   string
	SrcPort uint16
	DstPort uint16
}

type Client struct {
	mu   sync.Mutex
	conn *conntrack.Conn

	flowsMu sync.RWMutex
	flows   map[FlowKey]conntrack.Flow

	stopListen chan struct{}
}

func New() *Client {
	c := &Client{
		flows:      make(map[FlowKey]conntrack.Flow, 10000),
		stopListen: make(chan struct{}),
	}
	c.enableAccounting()
	go c.listenWorker()
	return c
}

func (c *Client) enableAccounting() {
	const path = "/proc/sys/net/netfilter/nf_conntrack_acct"
	data, err := os.ReadFile(path)
	if err == nil && strings.TrimSpace(string(data)) == "1" {
		return
	}
	if err := os.WriteFile(path, []byte("1\n"), 0o644); err == nil {
		log.Println("conntrack accounting enabled (nf_conntrack_acct=1)")
	}
}

func (c *Client) ensureConn() (*conntrack.Conn, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		return c.conn, nil
	}
	conn, err := conntrack.Dial(nil)
	if err != nil {
		return nil, fmt.Errorf("conntrack.Dial: %w", err)
	}
	c.conn = conn
	return c.conn, nil
}

func (c *Client) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}
}

func (c *Client) Close() error {
	close(c.stopListen)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		err := c.conn.Close()
		c.conn = nil
		return err
	}
	return nil
}

func (c *Client) listenWorker() {
	for {
		select {
		case <-c.stopListen:
			return
		default:
		}

		conn, err := c.ensureConn()
		if err != nil {
			log.Printf("conntrack listenWorker: dial failed: %v", err)
			time.Sleep(5 * time.Second)
			continue
		}

		flows, err := conn.Dump(nil)
		if err == nil {
			c.flowsMu.Lock()
			c.flows = make(map[FlowKey]conntrack.Flow, len(flows))
			for _, f := range flows {
				if f.TupleOrig.Proto.Protocol == protoUDP {
					k := FlowKey{
						SrcIP:   f.TupleOrig.IP.SourceAddress.String(),
						DstIP:   f.TupleOrig.IP.DestinationAddress.String(),
						SrcPort: f.TupleOrig.Proto.SourcePort,
						DstPort: f.TupleOrig.Proto.DestinationPort,
					}
					c.flows[k] = f
				}
			}
			c.flowsMu.Unlock()
		} else {
			log.Printf("conntrack listenWorker: dump failed: %v", err)
		}

		evChan := make(chan conntrack.Event, 1024)
		errChan, err := conn.Listen(evChan, 4, netfilter.GroupsCT)
		if err != nil {
			log.Printf("conntrack listenWorker: listen failed: %v", err)
			c.reset()
			time.Sleep(5 * time.Second)
			continue
		}

	loop:
		for {
			select {
			case <-c.stopListen:
				return
			case ev, ok := <-evChan:
				if !ok {
					break loop
				}
				if ev.Flow == nil || ev.Flow.TupleOrig.Proto.Protocol != protoUDP {
					continue
				}
				k := FlowKey{
					SrcIP:   ev.Flow.TupleOrig.IP.SourceAddress.String(),
					DstIP:   ev.Flow.TupleOrig.IP.DestinationAddress.String(),
					SrcPort: ev.Flow.TupleOrig.Proto.SourcePort,
					DstPort: ev.Flow.TupleOrig.Proto.DestinationPort,
				}

				c.flowsMu.Lock()
				switch ev.Type {
				case conntrack.EventNew, conntrack.EventUpdate:
					c.flows[k] = *ev.Flow
				case conntrack.EventDestroy:
					delete(c.flows, k)
				}
				c.flowsMu.Unlock()

			case err := <-errChan:
				log.Printf("conntrack listenWorker: worker error: %v", err)
				break loop
			}
		}

		c.reset()
		time.Sleep(1 * time.Second)
	}
}

func (c *Client) SnapshotUDP() ([]UDPFlow, error) {
	c.flowsMu.RLock()
	defer c.flowsMu.RUnlock()

	out := make([]UDPFlow, 0, len(c.flows))
	for _, f := range c.flows {
		src := f.TupleOrig.IP.SourceAddress.String()
		dst := f.TupleOrig.IP.DestinationAddress.String()
		sport := f.TupleOrig.Proto.SourcePort
		dport := f.TupleOrig.Proto.DestinationPort
		if strings.HasPrefix(src, "162.159.") || strings.HasPrefix(src, "172.") {
			continue
		}
		if dport == 22 || sport == 22 {
			continue
		}
		out = append(out, UDPFlow{
			SrcIP:      src,
			DstIP:      dst,
			SrcPort:    sport,
			DstPort:    dport,
			BytesOrig:  f.CountersOrig.Bytes,
			BytesReply: f.CountersReply.Bytes,
			Assured:    f.Status.Assured(),
		})
	}
	return out, nil
}

func (c *Client) AssuredUDPSrcs() (map[string]struct{}, error) {
	c.flowsMu.RLock()
	defer c.flowsMu.RUnlock()

	out := make(map[string]struct{}, 256)
	for _, f := range c.flows {
		if !f.Status.Assured() {
			continue
		}
		src := f.TupleOrig.IP.SourceAddress.String()
		if strings.HasPrefix(src, "162.159.") {
			continue
		}
		out[src] = struct{}{}
	}
	return out, nil
}

func (c *Client) DeleteBySrcUDP(srcIP string) error {
	conn, err := c.ensureConn()
	if err != nil {
		return err
	}

	c.flowsMu.RLock()
	var toDelete []conntrack.Flow
	for _, f := range c.flows {
		if f.TupleOrig.IP.SourceAddress.String() == srcIP {
			toDelete = append(toDelete, f)
		}
	}
	c.flowsMu.RUnlock()

	for _, f := range toDelete {
		if err := conn.Delete(f); err != nil {
			if !errIsENOENT(err) {
				log.Printf("conntrack delete %s: %v", srcIP, err)
			}
		}
	}
	return nil
}

func (c *Client) MarkBySrcsUDP(srcToMark map[string]uint32) (int, error) {
	if len(srcToMark) == 0 {
		return 0, nil
	}
	conn, err := c.ensureConn()
	if err != nil {
		return 0, err
	}

	c.flowsMu.RLock()
	var toUpdate []conntrack.Flow
	for _, f := range c.flows {
		src := f.TupleOrig.IP.SourceAddress.String()
		newMark, ok := srcToMark[src]
		if ok && f.Mark != newMark {
			fCopy := f
			fCopy.Mark = newMark
			toUpdate = append(toUpdate, fCopy)
		}
	}
	c.flowsMu.RUnlock()

	updated := 0
	for _, f := range toUpdate {
		if err := conn.Update(f); err != nil {
			if !errIsENOENT(err) {
				log.Printf("conntrack update mark %s: %v", f.TupleOrig.IP.SourceAddress.String(), err)
			}
			continue
		}
		updated++
	}
	return updated, nil
}

func (c *Client) MarkBySrcUDP(srcIP string, mark uint32) error {
	conn, err := c.ensureConn()
	if err != nil {
		return err
	}

	c.flowsMu.RLock()
	var toUpdate []conntrack.Flow
	for _, f := range c.flows {
		if f.TupleOrig.IP.SourceAddress.String() == srcIP {
			fCopy := f
			fCopy.Mark = mark
			toUpdate = append(toUpdate, fCopy)
		}
	}
	c.flowsMu.RUnlock()

	updated := 0
	for _, f := range toUpdate {
		if err := conn.Update(f); err != nil {
			if !errIsENOENT(err) {
				log.Printf("conntrack update mark %s: %v", srcIP, err)
			}
			continue
		}
		updated++
	}
	return nil
}

func errIsENOENT(err error) bool {
	if err == nil {
		return false
	}
	var errno syscall.Errno
	if asErrno(err, &errno) {
		return errno == syscall.ENOENT
	}
	return false
}

func asErrno(err error, target *syscall.Errno) bool {
	for err != nil {
		if e, ok := err.(syscall.Errno); ok {
			*target = e
			return true
		}
		type unwrapper interface{ Unwrap() error }
		u, ok := err.(unwrapper)
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

func (c *Client) ActiveUDPClients(dstIP string, ports map[uint16]bool) (map[string]struct{}, error) {
	c.flowsMu.RLock()
	defer c.flowsMu.RUnlock()

	out := make(map[string]struct{}, 64)
	for _, f := range c.flows {
		if !ports[f.TupleOrig.Proto.DestinationPort] {
			continue
		}
		if f.TupleReply.IP.SourceAddress.String() != dstIP {
			continue
		}
		src := f.TupleOrig.IP.SourceAddress.String()
		if strings.HasPrefix(src, "162.159.") || strings.HasPrefix(src, "172.") {
			continue
		}
		out[src] = struct{}{}
	}
	return out, nil
}

type UDPStats struct {
	Assured   int
	Unreplied int
	TopPorts  map[uint16]int // dport → count
}

func (c *Client) StatsUDP() (UDPStats, error) {
	c.flowsMu.RLock()
	defer c.flowsMu.RUnlock()

	out := UDPStats{TopPorts: make(map[uint16]int, 64)}
	for _, f := range c.flows {
		if f.TupleOrig.Proto.DestinationPort == 22 ||
			f.TupleOrig.Proto.SourcePort == 22 {
			continue
		}
		if f.Status.Assured() {
			out.Assured++
		}
		if !f.Status.SeenReply() {
			out.Unreplied++
		}
		out.TopPorts[f.TupleOrig.Proto.DestinationPort]++
	}
	return out, nil
}

func (c *Client) PingDeadline(d time.Duration) error {
	conn, err := c.ensureConn()
	if err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { _, e := conn.StatsGlobal(); done <- e }()
	select {
	case e := <-done:
		return e
	case <-time.After(d):
		return fmt.Errorf("conntrack ping timeout")
	}
}
