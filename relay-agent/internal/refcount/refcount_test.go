package refcount

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRefcount(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "refcount-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	dbPath := filepath.Join(tmpDir, "refcount.json")
	r := New(dbPath)

	// Add new client
	canRemove := r.Add("1.1.1.1", 1, "")
	if canRemove {
		t.Error("expected false since oldIP was empty")
	}
	if r.Count("1.1.1.1") != 1 {
		t.Errorf("expected 1, got %d", r.Count("1.1.1.1"))
	}

	// Move client
	canRemove = r.Add("2.2.2.2", 1, "1.1.1.1")
	if !canRemove {
		t.Error("expected true, since 1.1.1.1 dropped to 0 clients")
	}
	if r.Count("1.1.1.1") != 0 {
		t.Errorf("expected 0 for 1.1.1.1")
	}
	if r.Count("2.2.2.2") != 1 {
		t.Errorf("expected 1 for 2.2.2.2")
	}

	// Add second client to same IP
	r.Add("2.2.2.2", 2, "")
	if r.Count("2.2.2.2") != 2 {
		t.Errorf("expected 2 clients on 2.2.2.2")
	}

	// Remove one client
	empty := r.RemoveClient("2.2.2.2", 1)
	if empty {
		t.Error("expected false, one client left")
	}

	// Remove all clients
	empty = r.RemoveClient("2.2.2.2", 0)
	if !empty {
		t.Error("expected true, removed all")
	}
}

func TestSetAllAndLoad(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "refcount-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	dbPath := filepath.Join(tmpDir, "refcount.json")
	r := New(dbPath)

	r.SetAll(map[string][]int64{
		"1.1.1.1": {1, 2},
		"2.2.2.2": {3},
	})

	ips := r.IPs()
	if len(ips) != 2 || ips[0] != "1.1.1.1" || ips[1] != "2.2.2.2" {
		t.Errorf("unexpected IPs: %v", ips)
	}

	// Reload
	r2 := New(dbPath)
	if r2.Count("1.1.1.1") != 2 {
		t.Errorf("expected 2 clients for 1.1.1.1, got %d", r2.Count("1.1.1.1"))
	}
}

func BenchmarkRefcountAdd(b *testing.B) {
	tmpDir, _ := os.MkdirTemp("", "refcount-bench")
	defer func() { _ = os.RemoveAll(tmpDir) }()
	r := New(filepath.Join(tmpDir, "refcount.json"))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Just keep adding clients to the same IP to test map & slice allocations
		r.Add("192.168.1.1", int64(i), "")
	}
}

func BenchmarkRefcountRemove(b *testing.B) {
	tmpDir, _ := os.MkdirTemp("", "refcount-bench")
	defer func() { _ = os.RemoveAll(tmpDir) }()
	r := New(filepath.Join(tmpDir, "refcount.json"))

	r.mu.Lock()
	clients := make(map[int64]struct{}, 10000)
	for i := int64(0); i < 10000; i++ {
		clients[i] = struct{}{}
	}
	r.m["10.0.0.1"] = clients
	r.mu.Unlock()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Remove elements one by one
		r.RemoveClient("10.0.0.1", int64(i%10000))
	}
}

func FuzzRefcountLoad(f *testing.F) {
	// Add valid JSON seed (map[string][]int64 format)
	f.Add([]byte(`{"1.1.1.1":[1, 2], "2.2.2.2":[5]}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"1.1.1.1":[]}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		tmpFile := filepath.Join(t.TempDir(), "refcount_fuzz.json")
		_ = os.WriteFile(tmpFile, data, 0o644)
		
		r := New(tmpFile)
		// Should not panic on corrupted JSON.
		// Test some basic operations to ensure internal state is safe even if load failed.
		r.Count("1.1.1.1")
		r.IPs()
		r.Close()
	})
}
