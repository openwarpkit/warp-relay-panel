package sharedlimit

import (
	"testing"
	"time"
)

func TestSharedLimitBasic(t *testing.T) {
	cfg := Config{
		LimitMbps:    25.0,
		IdleGrace:    10 * time.Second,
		ScanInterval: 5 * time.Second,
		DstIP:        "1.1.1.1",
		Ports:        []uint16{500, 1000},
	}

	m := &Manager{
		cfg:      cfg,
		seen:     make(map[string]time.Time),
		portsSet: map[uint16]bool{500: true, 1000: true},
	}

	if m.Cfg().LimitMbps != 25.0 {
		t.Errorf("expected 25.0, got %f", m.Cfg().LimitMbps)
	}

	if m.Count() != 0 {
		t.Errorf("expected 0, got %d", m.Count())
	}

	if m.HasIP("1.2.3.4") != 0 {
		t.Errorf("expected 0 for unseen IP")
	}

	m.mu.Lock()
	m.seen["1.2.3.4"] = time.Now()
	m.mu.Unlock()

	if m.Count() != 1 {
		t.Errorf("expected 1, got %d", m.Count())
	}
	if m.HasIP("1.2.3.4") != 1 {
		t.Errorf("expected 1 for seen IP")
	}

	m.mu.Lock()
	m.seen = make(map[string]time.Time)
	m.mu.Unlock()

	if m.Count() != 0 {
		t.Errorf("expected 0 after reset")
	}
}
