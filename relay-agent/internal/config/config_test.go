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

func TestLoad(t *testing.T) {
	_ = os.Setenv("AGENT_SECRET", "supersecret")
	defer func() { _ = os.Unsetenv("AGENT_SECRET") }()

	cfg := Load()
	if cfg.AgentSecret != "supersecret" {
		t.Errorf("expected supersecret, got %s", cfg.AgentSecret)
	}
}
