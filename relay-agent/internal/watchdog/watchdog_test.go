package watchdog

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSaveAndLoadStatus(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "watchdog-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	w := &Watchdog{
		StatusFilePath: filepath.Join(tmpDir, "status.json"),
	}

	// Should be nil initially
	if status := w.LastStatus(); status != nil {
		t.Fatalf("expected nil status, got %v", status)
	}

	// Save status
	w.saveStatus(Status{
		Timestamp: "2024-01-01T00:00:00Z",
		Broken:    []string{"ipset"},
		Actions:   []string{"reloaded"},
	})

	// Check if loaded correctly
	status := w.LastStatus()
	if status == nil {
		t.Fatal("expected status, got nil")
	}
	if status.Timestamp != "2024-01-01T00:00:00Z" {
		t.Errorf("unexpected timestamp: %s", status.Timestamp)
	}
	if len(status.Broken) != 1 || status.Broken[0] != "ipset" {
		t.Errorf("unexpected broken list: %v", status.Broken)
	}
	if len(status.Actions) != 1 || status.Actions[0] != "reloaded" {
		t.Errorf("unexpected actions list: %v", status.Actions)
	}
}

func TestBrokenList(t *testing.T) {
	tests := []struct {
		checks Checks
		expect int
	}{
		{Checks{Ipset: true, NAT: true, Forward: true, IPForward: true, HTB: true, NftShaper: true, FlowFilter: true}, 0},
		{Checks{Ipset: false, NAT: true, Forward: true, IPForward: true, HTB: true, NftShaper: true, FlowFilter: true}, 1},
		{Checks{Ipset: false, NAT: false, Forward: false, IPForward: false, HTB: false, NftShaper: false, FlowFilter: false}, 7},
	}

	for i, tt := range tests {
		list := brokenList(tt.checks)
		if len(list) != tt.expect {
			t.Errorf("test %d: expected %d items, got %d", i, tt.expect, len(list))
		}
	}
}
