package ipsetgo

import (
	"syscall"
	"testing"
)

func TestAddInvalidIP(t *testing.T) {
	err := Add("myset", "invalid")
	if err == nil {
		t.Fatal("expected error for invalid IP")
	}
}

func TestDelInvalidIP(t *testing.T) {
	err := Del("myset", "invalid")
	if err == nil {
		t.Fatal("expected error for invalid IP")
	}
}

func TestIsEexist(t *testing.T) {
	if !isEexist(syscall.EEXIST) {
		t.Errorf("expected EEXIST to return true")
	}
	if isEexist(syscall.ENOENT) {
		t.Errorf("expected ENOENT to return false for isEexist")
	}
	if isEexist(nil) {
		t.Errorf("expected nil to return false")
	}
}

func TestIsEnoent(t *testing.T) {
	if !isEnoent(syscall.ENOENT) {
		t.Errorf("expected ENOENT to return true")
	}
	if isEnoent(syscall.EEXIST) {
		t.Errorf("expected EEXIST to return false for isEnoent")
	}
	if isEnoent(nil) {
		t.Errorf("expected nil to return false")
	}
}
