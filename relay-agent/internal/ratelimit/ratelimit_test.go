package ratelimit

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsMissingErr(t *testing.T) {
	if !isMissingErr("no such file or directory") {
		t.Error("expected true")
	}
	if !isMissingErr("could not process rule: no such table") {
		t.Error("expected true")
	}
	if isMissingErr("file exists") {
		t.Error("expected false")
	}
}

func TestIsExistsErr(t *testing.T) {
	if !isExistsErr("file exists") {
		t.Error("expected true")
	}
	if isExistsErr("no such file") {
		t.Error("expected false")
	}
}

func TestManagerLoadSave(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "ratelimit-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	dbPath := filepath.Join(tmpDir, "ratelimit.json")

	// Create manager, it will create empty state
	m := New(dbPath, 10, 20, nil)
	defer m.Close()

	m.mu.Lock()
	m.m["1.2.3.4"] = Limit{Mbps: 10.0, Mark: 10, ExpiresAt: "never"}
	m.used[10] = true
	m.dirty = true
	m.mu.Unlock()

	// Manual trigger
	m.ForceSave()

	_, err = os.ReadFile(dbPath)
	if err != nil {
		t.Fatalf("save() did not write file: %v", err)
	}

	// Reload
	m2 := New(dbPath, 10, 20, nil)
	defer m2.Close()

	m2.mu.Lock()
	l, ok := m2.m["1.2.3.4"]
	m2.mu.Unlock()

	if !ok {
		t.Fatal("expected IP to be loaded")
	}
	if l.Mbps != 10.0 {
		t.Errorf("expected Mbps 10.0, got %f", l.Mbps)
	}
	if l.Mark != 10 {
		t.Errorf("expected Mark 10, got %d", l.Mark)
	}
}

func TestAllocateMark(t *testing.T) {
	m := &Manager{
		markMin: 1,
		markMax: 2,
		m:       make(map[string]Limit),
		used:    make(map[int]bool),
	}

	mark1, err := m.allocateMark()
	if err != nil {
		t.Fatal(err)
	}
	if mark1 != 1 {
		t.Errorf("expected 1, got %d", mark1)
	}

	mark2, err := m.allocateMark()
	if err != nil {
		t.Fatal(err)
	}
	if mark2 != 2 {
		t.Errorf("expected 2, got %d", mark2)
	}

	_, err = m.allocateMark()
	if err == nil {
		t.Fatal("expected error when no marks available")
	}

	m.releaseMark(mark1)
	mark3, err := m.allocateMark()
	if err != nil {
		t.Fatal(err)
	}
	if mark3 != 1 {
		t.Errorf("expected 1, got %d", mark3)
	}
}

func FuzzRatelimitLoad(f *testing.F) {
	// Add valid JSON seed
	f.Add([]byte(`{"1.1.1.1":{"mbps":10.5,"mark":11,"applied_at":"now"}}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"1.1.1.1":{}}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		tmpFile := filepath.Join(t.TempDir(), "ratelimit_fuzz.json")
		_ = os.WriteFile(tmpFile, data, 0o644)

		m := New(tmpFile, 10, 999, nil)
		// Should not panic on corrupted JSON.
		m.Get("1.1.1.1")
		m.Count()
		m.Close()
	})
}
