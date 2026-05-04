package syscall

import (
	"testing"
)

// ---------------------------------------------------------------------------
// ParseFilterConfig: deny fields
// ---------------------------------------------------------------------------

func TestParseFilterConfig_DenyPIDs(t *testing.T) {
	cfg, err := ParseFilterConfig(map[string]string{"pid_deny": "100,200"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.DenyPIDs) != 2 || cfg.DenyPIDs[0] != 100 || cfg.DenyPIDs[1] != 200 {
		t.Errorf("expected DenyPIDs [100 200], got %v", cfg.DenyPIDs)
	}
	if len(cfg.PIDs) != 0 {
		t.Errorf("PIDs should be empty, got %v", cfg.PIDs)
	}
}

func TestParseFilterConfig_DenyUIDs(t *testing.T) {
	cfg, err := ParseFilterConfig(map[string]string{"uid_deny": "1000"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.DenyUIDs) != 1 || cfg.DenyUIDs[0] != 1000 {
		t.Errorf("expected DenyUIDs [1000], got %v", cfg.DenyUIDs)
	}
}

func TestParseFilterConfig_DenySyscalls(t *testing.T) {
	cfg, err := ParseFilterConfig(map[string]string{"syscall_deny": "ioctl,read"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.DenySyscalls) != 2 {
		t.Fatalf("expected 2 DenySyscalls, got %d", len(cfg.DenySyscalls))
	}
	if cfg.DenySyscalls[0] != "ioctl" || cfg.DenySyscalls[1] != "read" {
		t.Errorf("expected [ioctl read], got %v", cfg.DenySyscalls)
	}
}

func TestParseFilterConfig_InvalidDenyPID(t *testing.T) {
	_, err := ParseFilterConfig(map[string]string{"pid_deny": "abc"})
	if err == nil {
		t.Fatal("expected error for non-numeric deny PID")
	}
}

func TestParseFilterConfig_InvalidDenyUID(t *testing.T) {
	_, err := ParseFilterConfig(map[string]string{"uid_deny": "root"})
	if err == nil {
		t.Fatal("expected error for non-numeric deny UID")
	}
}

func TestParseFilterConfig_OverflowDenyPID(t *testing.T) {
	_, err := ParseFilterConfig(map[string]string{"pid_deny": "4294967296"})
	if err == nil {
		t.Fatal("expected error for deny PID exceeding uint32 max")
	}
}

// ---------------------------------------------------------------------------
// ParseFilterConfig: combined allow + deny
// ---------------------------------------------------------------------------

func TestParseFilterConfig_AllowAndDenyPIDs(t *testing.T) {
	cfg, err := ParseFilterConfig(map[string]string{
		"pid":      "1234",
		"pid_deny": "5678",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.PIDs) != 1 || cfg.PIDs[0] != 1234 {
		t.Errorf("PIDs = %v, want [1234]", cfg.PIDs)
	}
	if len(cfg.DenyPIDs) != 1 || cfg.DenyPIDs[0] != 5678 {
		t.Errorf("DenyPIDs = %v, want [5678]", cfg.DenyPIDs)
	}
}

func TestParseFilterConfig_AllowAndDenyUIDs(t *testing.T) {
	cfg, err := ParseFilterConfig(map[string]string{
		"uid":      "0",
		"uid_deny": "1000",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.UIDs) != 1 || cfg.UIDs[0] != 0 {
		t.Errorf("UIDs = %v, want [0]", cfg.UIDs)
	}
	if len(cfg.DenyUIDs) != 1 || cfg.DenyUIDs[0] != 1000 {
		t.Errorf("DenyUIDs = %v, want [1000]", cfg.DenyUIDs)
	}
}

func TestParseFilterConfig_AllowAndDenySyscalls(t *testing.T) {
	cfg, err := ParseFilterConfig(map[string]string{
		"syscall":      "read,write",
		"syscall_deny": "ioctl",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.Syscalls) != 2 || cfg.Syscalls[0] != "read" {
		t.Errorf("Syscalls = %v, want [read write]", cfg.Syscalls)
	}
	if len(cfg.DenySyscalls) != 1 || cfg.DenySyscalls[0] != "ioctl" {
		t.Errorf("DenySyscalls = %v, want [ioctl]", cfg.DenySyscalls)
	}
}

func TestParseFilterConfig_FullCombination(t *testing.T) {
	cfg, err := ParseFilterConfig(map[string]string{
		"pid":          "42",
		"pid_deny":     "99",
		"uid":          "1000",
		"uid_deny":     "0",
		"syscall":      "openat",
		"syscall_deny": "ioctl,close",
		"name":         "bash",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.PIDs) != 1 || cfg.PIDs[0] != 42 {
		t.Errorf("PIDs = %v", cfg.PIDs)
	}
	if len(cfg.DenyPIDs) != 1 || cfg.DenyPIDs[0] != 99 {
		t.Errorf("DenyPIDs = %v", cfg.DenyPIDs)
	}
	if len(cfg.UIDs) != 1 || cfg.UIDs[0] != 1000 {
		t.Errorf("UIDs = %v", cfg.UIDs)
	}
	if len(cfg.DenyUIDs) != 1 || cfg.DenyUIDs[0] != 0 {
		t.Errorf("DenyUIDs = %v", cfg.DenyUIDs)
	}
	if len(cfg.Syscalls) != 1 || cfg.Syscalls[0] != "openat" {
		t.Errorf("Syscalls = %v", cfg.Syscalls)
	}
	if len(cfg.DenySyscalls) != 2 || cfg.DenySyscalls[0] != "ioctl" {
		t.Errorf("DenySyscalls = %v", cfg.DenySyscalls)
	}
	if cfg.CommName != "bash" {
		t.Errorf("CommName = %q", cfg.CommName)
	}
}

func TestParseFilterConfig_DenyPIDWithSpaces(t *testing.T) {
	cfg, err := ParseFilterConfig(map[string]string{"pid_deny": " 100 , 200 "})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.DenyPIDs) != 2 || cfg.DenyPIDs[0] != 100 || cfg.DenyPIDs[1] != 200 {
		t.Errorf("DenyPIDs = %v, want [100 200]", cfg.DenyPIDs)
	}
}

func TestParseFilterConfig_DenySyscallsWithSpaces(t *testing.T) {
	cfg, err := ParseFilterConfig(map[string]string{"syscall_deny": " ioctl , close "})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.DenySyscalls[0] != "ioctl" || cfg.DenySyscalls[1] != "close" {
		t.Errorf("DenySyscalls spaces not trimmed: %v", cfg.DenySyscalls)
	}
}

func TestParseFilterConfig_EmptyDenyFields(t *testing.T) {
	cfg, err := ParseFilterConfig(map[string]string{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.DenyPIDs) != 0 {
		t.Errorf("DenyPIDs should be empty, got %v", cfg.DenyPIDs)
	}
	if len(cfg.DenyUIDs) != 0 {
		t.Errorf("DenyUIDs should be empty, got %v", cfg.DenyUIDs)
	}
	if len(cfg.DenySyscalls) != 0 {
		t.Errorf("DenySyscalls should be empty, got %v", cfg.DenySyscalls)
	}
}
