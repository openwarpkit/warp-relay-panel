package traffic

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestTrafficSaveAndLoad(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "traffic-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	dbPath := filepath.Join(tmpDir, "traffic.json")

	// Create monitor, it should load empty state
	m := New(dbPath, 1*time.Second, nil, false)

	// Add some dummy traffic directly
	m.mu.Lock()
	m.state.IPs["1.2.3.4"] = ipStats{TX: 100, RX: 200, Updated: "now"}
	m.save(m.state)
	m.mu.Unlock()

	// Check if file is written
	if _, err := os.Stat(dbPath); err != nil {
		t.Fatalf("save() did not write file: %v", err)
	}

	// Create a new monitor pointing to the same file, it should load the saved state
	m2 := New(dbPath, 1*time.Second, nil, false)
	s, _, _, ok := m2.GetIP("1.2.3.4", func(ip string) int { return 1 }, func(ip string) []int64 { return []int64{1} })
	if !ok {
		t.Fatal("expected IP 1.2.3.4 to be loaded, but it wasn't")
	}
	if s.TXBytes != 100 || s.RXBytes != 200 {
		t.Fatalf("expected TX=100 RX=200, got TX=%d RX=%d", s.TXBytes, s.RXBytes)
	}
}

func TestTrafficReset(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "traffic-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	dbPath := filepath.Join(tmpDir, "traffic.json")
	m := New(dbPath, 1*time.Second, nil, false)

	m.mu.Lock()
	m.state.IPs["1.2.3.4"] = ipStats{TX: 100, RX: 200, Updated: "now"}
	m.save(m.state)
	m.mu.Unlock()

	m.Reset()

	s, _, _, ok := m.GetIP("1.2.3.4", func(ip string) int { return 0 }, func(ip string) []int64 { return nil })
	if ok || s.TXBytes != 0 {
		t.Fatalf("expected IP 1.2.3.4 to be removed after Reset()")
	}
}

func BenchmarkTrafficAdd(b *testing.B) {
	tmpDir, _ := os.MkdirTemp("", "traffic-bench")
	defer func() { _ = os.RemoveAll(tmpDir) }()
	m := New(filepath.Join(tmpDir, "traffic.json"), 1*time.Hour, nil, false)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.mu.Lock()
		s := m.state.IPs["192.168.0.1"]
		s.TX += 1000
		s.RX += 500
		m.state.IPs["192.168.0.1"] = s
		m.mu.Unlock()
	}
}

func BenchmarkTrafficSave(b *testing.B) {
	tmpDir, _ := os.MkdirTemp("", "traffic-bench")
	defer func() { _ = os.RemoveAll(tmpDir) }()
	m := New(filepath.Join(tmpDir, "traffic.json"), 1*time.Hour, nil, false)

	// Pre-fill state with 1000 IPs
	m.mu.Lock()
	for i := 0; i < 1000; i++ {
		// Simple IP generation
		ip := "10.0.0." + string(rune(i%256))
		m.state.IPs[ip] = ipStats{TX: 1000, RX: 1000, Updated: "2026-06-01"}
	}
	m.mu.Unlock()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.mu.Lock()
		m.save(m.state)
		m.mu.Unlock()
	}
}

func FuzzTrafficLoad(f *testing.F) {
	// Add valid JSON seed
	f.Add([]byte(`{"month":"2026-06","ips":{"1.2.3.4":{"tx":1000,"rx":500,"updated":"2026-06-01T12:00:00Z"}}}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"ips":null}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		tmpFile := filepath.Join(t.TempDir(), "traffic_fuzz.json")
		_ = os.WriteFile(tmpFile, data, 0o644)

		m := New(tmpFile, 1*time.Hour, nil, false)
		// Should not panic. Check some basic methods.
		m.GetIP("1.2.3.4", func(ip string) int { return 1 }, func(ip string) []int64 { return []int64{1} })
		m.Reset()
	})
}
