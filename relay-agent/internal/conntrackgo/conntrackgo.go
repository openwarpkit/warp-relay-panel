package conntrackgo

import (
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"
	"net"

	"github.com/ti-mo/conntrack"
	"github.com/ti-mo/netfilter"
)

const protoUDP = 17
const numShards = 256

// UDPFlow is the minimal set for traffic accounting.
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

func (k FlowKey) Hash() uint32 {
	hash := uint32(2166136261)
	for i := 0; i < len(k.SrcIP); i++ {
		hash ^= uint32(k.SrcIP[i])
		hash *= 16777619
	}
	for i := 0; i < len(k.DstIP); i++ {
		hash ^= uint32(k.DstIP[i])
		hash *= 16777619
	}
	hash ^= uint32(k.SrcPort)
	hash *= 16777619
	hash ^= uint32(k.DstPort)
	hash *= 16777619
	return hash
}

type flowShard struct {
	mu    sync.RWMutex
	flows map[FlowKey]conntrack.Flow
}

type Client struct {
	shards [numShards]*flowShard

	obsMu     sync.RWMutex
	observers []chan<- conntrack.Event

	stopListen chan struct{}
	closeOnce  sync.Once
	wg         sync.WaitGroup
}

func New() *Client {
	c := &Client{
		stopListen: make(chan struct{}),
	}
	for i := 0; i < numShards; i++ {
		c.shards[i] = &flowShard{
			flows: make(map[FlowKey]conntrack.Flow, 64),
		}
	}
	c.enableAccounting()
	
	c.wg.Add(2)
	go c.listenWorker()
	go c.reconcileWorker()
	
	return c
}

func (c *Client) RegisterObserver(ch chan<- conntrack.Event) {
	c.obsMu.Lock()
	defer c.obsMu.Unlock()
	c.observers = append(c.observers, ch)
}

func (c *Client) getShard(k FlowKey) *flowShard {
	return c.shards[k.Hash()%numShards]
}

func (c *Client) enableAccounting() {
	const path = "/proc/sys/net/netfilter/nf_conntrack_acct"
	data, err := os.ReadFile(path)
	if err == nil && strings.TrimSpace(string(data)) == "1" {
		return
	}
	// #nosec G306 -- Kernel /proc requires default permissions
	if err := os.WriteFile(path, []byte("1\n"), 0o644); err == nil {
		log.Println("conntrack accounting enabled (nf_conntrack_acct=1)")
	}
}

func (c *Client) Close() error {
	c.closeOnce.Do(func() {
		close(c.stopListen)
	})
	c.wg.Wait()
	return nil
}

func (c *Client) listenWorker() {
	defer c.wg.Done()
	for {
		select {
		case <-c.stopListen:
			return
		default:
		}

		conn, err := conntrack.Dial(nil)
		if err != nil {
			log.Printf("conntrack listenWorker: dial failed: %v", err)
			time.Sleep(5 * time.Second)
			continue
		}

		// Increase netlink socket receive buffer to 4MB to prevent ENOBUFS (No buffer space available)
		// under high UDP connection storms. If ENOBUFS still occurs, listenWorker will catch it
		// from errChan, close the private socket, and self-heal by reconnecting and re-dumping state.
		if err := conn.SetReadBuffer(4 * 1024 * 1024); err != nil {
			log.Printf("conntrack: warning: failed to set 4MB read buffer (sysctl net.core.rmem_max too small?): %v", err)
		}

		// Initial sync
		flows, err := conn.Dump(nil)
		if err == nil {
			for i := 0; i < numShards; i++ {
				c.shards[i].mu.Lock()
				c.shards[i].flows = make(map[FlowKey]conntrack.Flow, len(flows)/numShards+1)
				c.shards[i].mu.Unlock()
			}
			for _, f := range flows {
				if f.TupleOrig.Proto.Protocol == protoUDP {
					k := FlowKey{
						SrcIP:   f.TupleOrig.IP.SourceAddress.String(),
						DstIP:   f.TupleOrig.IP.DestinationAddress.String(),
						SrcPort: f.TupleOrig.Proto.SourcePort,
						DstPort: f.TupleOrig.Proto.DestinationPort,
					}
					shard := c.getShard(k)
					shard.mu.Lock()
					shard.flows[k] = f
					shard.mu.Unlock()
				}
			}
		} else {
			log.Printf("conntrack listenWorker: dump failed: %v", err)
		}

		evChan := make(chan conntrack.Event, 4096)
		errChan, listenErr := conn.Listen(evChan, 4, netfilter.GroupsCT)
		if listenErr != nil {
			log.Printf("conntrack listenWorker: listen failed: %v", listenErr)
			_ = conn.Close()
			time.Sleep(5 * time.Second)
			continue
		}

	loop:
		for {
			select {
			case <-c.stopListen:
				_ = conn.Close()
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

				shard := c.getShard(k)
				shard.mu.Lock()
				switch ev.Type {
				case conntrack.EventNew, conntrack.EventUpdate:
					shard.flows[k] = *ev.Flow
				case conntrack.EventDestroy:
					delete(shard.flows, k)
				}
				shard.mu.Unlock()

				c.obsMu.RLock()
				for _, ch := range c.observers {
					select {
					case ch <- ev:
					default:
					}
				}
				c.obsMu.RUnlock()

			case err := <-errChan:
				log.Printf("conntrack listenWorker: worker error: %v", err)
				break loop
			}
		}

		_ = conn.Close()
		time.Sleep(1 * time.Second)
	}
}

// reconcileWorker periodically syncs byte counters and removes zombies
func (c *Client) reconcileWorker() {
	defer c.wg.Done()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-c.stopListen:
			return
		case <-ticker.C:
			c.reconcileOnce()
		}
	}
}

func (c *Client) reconcileOnce() {
	conn, err := conntrack.Dial(nil)
	if err != nil {
		return
	}
	defer conn.Close()
	flows, err := conn.Dump(nil)
	if err != nil {
		return
	}

	activeKernel := make(map[FlowKey]conntrack.Flow, len(flows))
	for _, f := range flows {
		if f.TupleOrig.Proto.Protocol == protoUDP {
			k := FlowKey{
				SrcIP:   f.TupleOrig.IP.SourceAddress.String(),
				DstIP:   f.TupleOrig.IP.DestinationAddress.String(),
				SrcPort: f.TupleOrig.Proto.SourcePort,
				DstPort: f.TupleOrig.Proto.DestinationPort,
			}
			activeKernel[k] = f
		}
	}

	for i := 0; i < numShards; i++ {
		shard := c.shards[i]
		shard.mu.Lock()
		for k := range shard.flows {
			if kf, ok := activeKernel[k]; ok {
				flow := shard.flows[k]
				flow.CountersOrig = kf.CountersOrig
				flow.CountersReply = kf.CountersReply
				flow.Status = kf.Status
				shard.flows[k] = flow
			} else {
				delete(shard.flows, k)
			}
		}
		shard.mu.Unlock()
	}
}

func isFilteredIP(src string) bool {
	if strings.HasPrefix(src, "162.159.") {
		return true
	}
	ip := net.ParseIP(src)
	if ip == nil {
		return false
	}
	return ip.IsPrivate() || ip.IsLoopback()
}

func (c *Client) SnapshotUDP() ([]UDPFlow, error) {
	var out []UDPFlow
	for i := 0; i < numShards; i++ {
		shard := c.shards[i]
		shard.mu.RLock()
		for _, f := range shard.flows {
			src := f.TupleOrig.IP.SourceAddress.String()
			dst := f.TupleOrig.IP.DestinationAddress.String()
			sport := f.TupleOrig.Proto.SourcePort
			dport := f.TupleOrig.Proto.DestinationPort
			if isFilteredIP(src) {
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
		shard.mu.RUnlock()
	}
	return out, nil
}

func (c *Client) AssuredUDPSrcs() (map[string]struct{}, error) {
	out := make(map[string]struct{}, 256)
	for i := 0; i < numShards; i++ {
		shard := c.shards[i]
		shard.mu.RLock()
		for _, f := range shard.flows {
			if !f.Status.Assured() {
				continue
			}
			src := f.TupleOrig.IP.SourceAddress.String()
			if strings.HasPrefix(src, "162.159.") {
				continue
			}
			out[src] = struct{}{}
		}
		shard.mu.RUnlock()
	}
	return out, nil
}

func (c *Client) DeleteBySrcUDP(srcIP string) error {
	conn, err := conntrack.Dial(nil)
	if err != nil {
		return fmt.Errorf("conntrack.Dial: %w", err)
	}
	defer conn.Close()

	var toDelete []conntrack.Flow
	for i := 0; i < numShards; i++ {
		shard := c.shards[i]
		shard.mu.RLock()
		for _, f := range shard.flows {
			if f.TupleOrig.IP.SourceAddress.String() == srcIP {
				toDelete = append(toDelete, f)
			}
		}
		shard.mu.RUnlock()
	}

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
	conn, err := conntrack.Dial(nil)
	if err != nil {
		return 0, fmt.Errorf("conntrack.Dial: %w", err)
	}
	defer conn.Close()

	var toUpdate []conntrack.Flow
	for i := 0; i < numShards; i++ {
		shard := c.shards[i]
		shard.mu.RLock()
		for _, f := range shard.flows {
			src := f.TupleOrig.IP.SourceAddress.String()
			newMark, ok := srcToMark[src]
			if ok && f.Mark != newMark {
				fCopy := f
				fCopy.Mark = newMark
				toUpdate = append(toUpdate, fCopy)
			}
		}
		shard.mu.RUnlock()
	}

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
	conn, err := conntrack.Dial(nil)
	if err != nil {
		return fmt.Errorf("conntrack.Dial: %w", err)
	}
	defer conn.Close()

	var toUpdate []conntrack.Flow
	for i := 0; i < numShards; i++ {
		shard := c.shards[i]
		shard.mu.RLock()
		for _, f := range shard.flows {
			if f.TupleOrig.IP.SourceAddress.String() == srcIP {
				fCopy := f
				fCopy.Mark = mark
				toUpdate = append(toUpdate, fCopy)
			}
		}
		shard.mu.RUnlock()
	}

	for _, f := range toUpdate {
		if err := conn.Update(f); err != nil {
			if !errIsENOENT(err) {
				log.Printf("conntrack update mark %s: %v", srcIP, err)
			}
			continue
		}
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
	out := make(map[string]struct{}, 64)
	for i := 0; i < numShards; i++ {
		shard := c.shards[i]
		shard.mu.RLock()
		for _, f := range shard.flows {
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
		shard.mu.RUnlock()
	}
	return out, nil
}

type UDPStats struct {
	Assured   int
	Unreplied int
	TopPorts  map[uint16]int // dport -> count
}

func (c *Client) StatsUDP() (UDPStats, error) {
	out := UDPStats{TopPorts: make(map[uint16]int, 64)}
	for i := 0; i < numShards; i++ {
		shard := c.shards[i]
		shard.mu.RLock()
		for _, f := range shard.flows {
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
		shard.mu.RUnlock()
	}
	return out, nil
}

func (c *Client) PingDeadline(d time.Duration) error {
	conn, err := conntrack.Dial(nil)
	if err != nil {
		return err
	}
	defer conn.Close()
	done := make(chan error, 1)
	go func() { _, e := conn.StatsGlobal(); done <- e }()
	select {
	case e := <-done:
		return e
	case <-time.After(d):
		return fmt.Errorf("conntrack ping timeout")
	}
}
