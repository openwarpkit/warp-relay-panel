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
		MasqueDstIP:  "162.159.198.2",
		MasquePorts:  []uint16{443, 4443},
	}

	m := &Manager{
		cfg:  cfg,
		seen: make(map[string]time.Time),
		targets: map[string]map[uint16]bool{
			"1.1.1.1":       {500: true, 1000: true},
			"162.159.198.2": {443: true, 4443: true},
		},
	}

	if !m.matchesTarget("162.159.198.2", 443) {
		t.Fatal("expected MASQUE target to match")
	}
	if m.matchesTarget("1.1.1.1", 443) {
		t.Fatal("MASQUE port must not match WARP target")
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
