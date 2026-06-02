package metrics

import (
	"testing"
	"time"
)

func TestRound2(t *testing.T) {
	if v := round2(3.14159); v != 3.14 {
		t.Errorf("expected 3.14, got %f", v)
	}
	if v := round2(3.1); v != 3.10 {
		t.Errorf("expected 3.10, got %f", v)
	}
	if v := round2(3.0); v != 3.00 {
		t.Errorf("expected 3.00, got %f", v)
	}
}

func TestParseInt64(t *testing.T) {
	tests := []struct {
		in  string
		out int64
	}{
		{"12345", 12345},
		{"123\n", 123},
		{" 456 \t", 456},
		{"789abc", 789}, // Stops at first non-digit
	}

	for _, tt := range tests {
		v, _ := parseInt64(tt.in)
		if v != tt.out {
			t.Errorf("parseInt64(%q) = %d, want %d", tt.in, v, tt.out)
		}
	}
}

func TestSnapshot(t *testing.T) {
	m := New(1*time.Second, "/tmp")

	snap := m.Snapshot()
	if snap.CPUCount <= 0 {
		t.Errorf("expected CPUCount > 0, got %d", snap.CPUCount)
	}
}
