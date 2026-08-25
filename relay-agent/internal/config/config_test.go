package config

import (
	"os"
	"testing"
)

func TestEnvParsing(t *testing.T) {
	_ = os.Setenv("TEST_STR", "val")
	_ = os.Setenv("TEST_INT", "42")
	_ = os.Setenv("TEST_FLOAT", "3.14")
	_ = os.Setenv("TEST_INVALID_INT", "abc")

	defer func() {
		_ = os.Unsetenv("TEST_STR")
		_ = os.Unsetenv("TEST_INT")
		_ = os.Unsetenv("TEST_FLOAT")
		_ = os.Unsetenv("TEST_INVALID_INT")
	}()

	if v := env("TEST_STR", "def"); v != "val" {
		t.Errorf("expected val, got %s", v)
	}
	if v := env("MISSING", "def"); v != "def" {
		t.Errorf("expected def, got %s", v)
	}

	if v := envInt("TEST_INT", 10); v != 42 {
		t.Errorf("expected 42, got %d", v)
	}
	if v := envInt("TEST_INVALID_INT", 10); v != 10 {
		t.Errorf("expected 10, got %d", v)
	}
	if v := envInt("MISSING", 10); v != 10 {
		t.Errorf("expected 10, got %d", v)
	}

	if v := envFloat("TEST_FLOAT", 1.0); v != 3.14 {
		t.Errorf("expected 3.14, got %f", v)
	}
	if v := envFloat("TEST_INVALID_INT", 1.0); v != 1.0 {
		t.Errorf("expected 1.0, got %f", v)
	}
}

func TestParsePorts(t *testing.T) {
	ports := parsePorts("500, 1000,abc, 70000, -5")

	if len(ports) != 2 {
		t.Fatalf("expected 2 ports, got %d", len(ports))
	}
	if ports[0] != 500 || ports[1] != 1000 {
		t.Errorf("unexpected ports: %v", ports)
	}

	// Test empty string fallback to defaults
	defs := parsePorts("")
	if len(defs) == 0 {
		t.Fatal("expected default ports on empty string")
	}
}

func TestMasquePortsDoNotOverlapWarp(t *testing.T) {
	ports := excludePorts([]uint16{443, 500, 443, 4443, 1701, 8443, 8095, 4500}, DefaultWarpPorts)
	want := []uint16{443, 4443, 8443, 8095}
	if len(ports) != len(want) {
		t.Fatalf("unexpected MASQUE ports: %v", ports)
	}
	for i := range want {
		if ports[i] != want[i] {
			t.Fatalf("unexpected MASQUE ports: %v", ports)
		}
	}
}

func TestLoad(t *testing.T) {
	_ = os.Setenv("AGENT_SECRET", "supersecret")
	defer func() {
		_ = os.Unsetenv("AGENT_SECRET")
	}()

	cfg := Load()
	if cfg.AgentSecret != "supersecret" {
		t.Errorf("expected supersecret, got %s", cfg.AgentSecret)
	}
}

func TestLoadAdaptiveSharedLimitDefaults(t *testing.T) {
	t.Setenv("AGENT_SECRET", "supersecret")
	t.Setenv("SHARED_LIMIT_MBPS", "5")
	t.Setenv("SHARED_MIN_LIMIT_MBPS", "9")
	t.Setenv("SHARED_MONTHLY_BUDGET_TB", "30")
	t.Setenv("SHARED_BUDGET_DIRECTION", "invalid")
	t.Setenv("SHARED_BUDGET_INTERVAL", "10")

	cfg := Load()
	if cfg.SharedLimitMbps != 5 || cfg.SharedMinLimitMbps != 5 {
		t.Fatalf("unexpected limits: %.1f..%.1f", cfg.SharedMinLimitMbps, cfg.SharedLimitMbps)
	}
	if cfg.SharedBudgetTB != 30 || cfg.SharedBudgetMode != "tx" {
		t.Fatalf("unexpected budget: %.1f TB/%s", cfg.SharedBudgetTB, cfg.SharedBudgetMode)
	}
	if cfg.SharedBudgetInterval != 60 {
		t.Fatalf("expected minimum interval 60, got %d", cfg.SharedBudgetInterval)
	}
}
