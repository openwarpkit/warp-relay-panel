package adaptivelimit

import (
	"testing"
	"time"
)

func testConfig() Config {
	return Config{DefaultLimitMbps: 5, MinLimitMbps: 1, MonthlyBudgetTB: 30, Direction: "tx"}
}

func TestUsageBytes(t *testing.T) {
	usage := Usage{TXBytes: 10, RXBytes: 20}
	if UsageBytes(usage, "tx") != 10 || UsageBytes(usage, "rx") != 20 || UsageBytes(usage, "total") != 30 {
		t.Fatal("unexpected direction totals")
	}
}

func TestDisabledBudgetKeepsCurrentLimit(t *testing.T) {
	now := time.Date(2026, time.August, 1, 0, 0, 0, 0, zone)
	decision := Calculate(Config{DefaultLimitMbps: 5, MinLimitMbps: 1, Direction: "tx"}, 3, Usage{}, nil, now)
	if decision.Limit != 3 || decision.Status.Enabled {
		t.Fatalf("unexpected disabled decision: %+v", decision)
	}
}

func TestBudgetExhaustedUsesFloor(t *testing.T) {
	now := time.Date(2026, time.August, 20, 12, 0, 0, 0, zone)
	decision := Calculate(testConfig(), 5, Usage{Month: "2026-08", TXBytes: 31 * DecimalTB}, nil, now)
	if decision.Limit != 1 || decision.Status.RemainingTB != 0 {
		t.Fatalf("unexpected exhausted decision: %+v", decision)
	}
}

func TestThirtyTBTargetRate(t *testing.T) {
	now := time.Date(2026, time.August, 1, 0, 0, 1, 0, zone)
	decision := Calculate(testConfig(), 5, Usage{Month: "2026-08"}, nil, now)
	if decision.Status.TargetMbps < 89 || decision.Status.TargetMbps > 90 {
		t.Fatalf("unexpected 31-day TX target: %.2f Mbps", decision.Status.TargetMbps)
	}
}

func TestBudgetPressureStepsDown(t *testing.T) {
	now := time.Date(2026, time.August, 15, 12, 0, 0, 0, zone)
	used := int64(15 * DecimalTB)
	previous := &Sample{Month: "2026-08", Bytes: used - 8_000_000_000, At: now.Add(-5 * time.Minute)}
	decision := Calculate(testConfig(), 5, Usage{Month: "2026-08", TXBytes: used}, previous, now)
	if decision.Limit != 4 {
		t.Fatalf("expected 4 Mbps, got %.1f", decision.Limit)
	}
	if decision.Status.RecentMbps <= decision.Status.TargetMbps {
		t.Fatalf("expected pressure: %+v", decision.Status)
	}
}

func TestBudgetRecoveryStepsUpSlowly(t *testing.T) {
	now := time.Date(2026, time.August, 15, 12, 0, 0, 0, zone)
	used := int64(8 * DecimalTB)
	previous := &Sample{Month: "2026-08", Bytes: used - 500_000_000, At: now.Add(-5 * time.Minute)}
	decision := Calculate(testConfig(), 3, Usage{Month: "2026-08", TXBytes: used}, previous, now)
	if decision.Limit != 3.5 {
		t.Fatalf("expected 3.5 Mbps, got %.1f", decision.Limit)
	}
}

func TestBudgetReportsUnachievableAtFloor(t *testing.T) {
	now := time.Date(2026, time.August, 28, 12, 0, 0, 0, zone)
	used := int64(29 * DecimalTB)
	previous := &Sample{Month: "2026-08", Bytes: used - 10_000_000_000, At: now.Add(-5 * time.Minute)}
	decision := Calculate(testConfig(), 1, Usage{Month: "2026-08", TXBytes: used}, previous, now)
	if !decision.Status.UnachievableAtFloor {
		t.Fatal("expected unachievable_at_floor")
	}
}

func TestLimitQuantization(t *testing.T) {
	tests := map[float64]float64{0.2: 1, 1.9: 1.5, 4.9: 4.5, 8: 5}
	for input, want := range tests {
		if got := quantize(input, 1, 5); got != want {
			t.Fatalf("quantize %.1f: want %.1f, got %.1f", input, want, got)
		}
	}
}
