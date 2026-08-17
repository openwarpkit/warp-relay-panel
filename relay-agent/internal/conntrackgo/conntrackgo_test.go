package conntrackgo

import (
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestFlowKeyHash(t *testing.T) {
	k1 := FlowKey{SrcIP: [4]byte{1, 2, 3, 4}, DstIP: [4]byte{5, 6, 7, 8}, SrcPort: 1234, DstPort: 80}
	k2 := FlowKey{SrcIP: [4]byte{1, 2, 3, 4}, DstIP: [4]byte{5, 6, 7, 8}, SrcPort: 1234, DstPort: 80}
	k3 := FlowKey{SrcIP: [4]byte{1, 2, 3, 5}, DstIP: [4]byte{5, 6, 7, 8}, SrcPort: 1234, DstPort: 80}

	if k1.Hash() != k2.Hash() {
		t.Errorf("expected hashes to match for identical keys")
	}
	if k1.Hash() == k3.Hash() {
		t.Errorf("expected hashes to differ for different keys")
	}
}

func TestIsFilteredIP(t *testing.T) {
	tests := []struct {
		ip       string
		filtered bool
	}{
		{"162.159.1.1", true}, // Cloudflare edge
		{"127.0.0.1", true},   // Loopback
		{"10.0.0.1", true},    // Private
		{"192.168.1.1", true}, // Private
		{"8.8.8.8", false},    // Public
		{"invalid", false},
	}

	for _, tt := range tests {
		if res := isFilteredIP(tt.ip); res != tt.filtered {
			t.Errorf("isFilteredIP(%q) = %v, want %v", tt.ip, res, tt.filtered)
		}
	}
}

func TestErrIsENOENT(t *testing.T) {
	if !errIsENOENT(syscall.ENOENT) {
		t.Errorf("expected true for ENOENT")
	}
	if errIsENOENT(syscall.EEXIST) {
		t.Errorf("expected false for EEXIST")
	}
	if errIsENOENT(nil) {
		t.Errorf("expected false for nil")
	}
}

func TestWaitForWorkersCompletes(t *testing.T) {
	c := &Client{}
	if err := c.waitForWorkers(time.Second); err != nil {
		t.Fatal(err)
	}
}

func TestWaitForWorkersTimeout(t *testing.T) {
	c := &Client{}
	var release sync.Once
	blocked := make(chan struct{})
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		<-blocked
	}()
	t.Cleanup(func() {
		release.Do(func() { close(blocked) })
	})

	err := c.waitForWorkers(20 * time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "did not stop") {
		t.Fatalf("unexpected error: %v", err)
	}
	release.Do(func() { close(blocked) })
}
