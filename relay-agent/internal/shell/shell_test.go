package shell

import (
	"testing"
	"time"
)

func TestRun(t *testing.T) {
	rc, out, _ := Run("echo 'hello'", 1*time.Second)
	if rc != 0 {
		t.Errorf("expected rc=0, got %d", rc)
	}
	if out != "hello" {
		t.Errorf("expected hello, got %s", out)
	}

	rc, _, _ = Run("exit 42", 1*time.Second)
	if rc != 42 {
		t.Errorf("expected rc=42, got %d", rc)
	}
}

func TestRunStdin(t *testing.T) {
	rc, out, _ := RunStdin("cat", "world", 1*time.Second)
	if rc != 0 {
		t.Errorf("expected rc=0, got %d", rc)
	}
	if out != "world" {
		t.Errorf("expected world, got %s", out)
	}
}

func TestValidIPv4(t *testing.T) {
	valid := []string{"1.2.3.4", "255.255.255.255", "0.0.0.0"}
	invalid := []string{"", "abc", "256.0.0.1", "1.2.3", "1.2.3.4.5"}

	for _, ip := range valid {
		if !ValidIPv4(ip) {
			t.Errorf("expected %s to be valid", ip)
		}
	}
	for _, ip := range invalid {
		if ValidIPv4(ip) {
			t.Errorf("expected %s to be invalid", ip)
		}
	}
}

func TestFormatBytes(t *testing.T) {
	if v := FormatBytes(500); v != "500 B" {
		t.Errorf("expected 500 B, got %s", v)
	}
	if v := FormatBytes(1024); v != "1.0 KB" {
		t.Errorf("expected 1.0 KB, got %s", v)
	}
	if v := FormatBytes(1536); v != "1.5 KB" {
		t.Errorf("expected 1.5 KB, got %s", v)
	}
	if v := FormatBytes(1048576); v != "1.0 MB" {
		t.Errorf("expected 1.0 MB, got %s", v)
	}
	if v := FormatBytes(-2048); v != "-2.0 KB" {
		t.Errorf("expected -2.0 KB, got %s", v)
	}
}
