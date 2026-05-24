package memory

import (
	"testing"
)

// ---------------------------------------------------------------------------
// Deny filter parsing (separated for consistency with syscall/files/network)
// ---------------------------------------------------------------------------

func TestDenyPIDParsing(t *testing.T) {
	cfg, err := ParseFilterConfig(map[string]string{"pid_deny": "100"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.DenyPIDs) != 1 || cfg.DenyPIDs[0] != 100 {
		t.Errorf("DenyPIDs = %v, want [100]", cfg.DenyPIDs)
	}
	if len(cfg.PIDs) != 0 {
		t.Errorf("PIDs should be empty, got %v", cfg.PIDs)
	}
}

func TestDenyUIDParsing(t *testing.T) {
	cfg, err := ParseFilterConfig(map[string]string{"uid_deny": "1000,2000"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.DenyUIDs) != 2 || cfg.DenyUIDs[0] != 1000 || cfg.DenyUIDs[1] != 2000 {
		t.Errorf("DenyUIDs = %v, want [1000 2000]", cfg.DenyUIDs)
	}
}

func TestDenyFaultMinorParsing(t *testing.T) {
	cfg, err := ParseFilterConfig(map[string]string{"fault_deny": "minor"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.DenyFaults) != 1 || cfg.DenyFaults[0] != 1 {
		t.Errorf("DenyFaults = %v, want [1]", cfg.DenyFaults)
	}
}

func TestDenyFaultMajorParsing(t *testing.T) {
	cfg, err := ParseFilterConfig(map[string]string{"fault_deny": "major"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.DenyFaults) != 1 || cfg.DenyFaults[0] != 0 {
		t.Errorf("DenyFaults = %v, want [0]", cfg.DenyFaults)
	}
}

func TestMixedAllowDenyPID(t *testing.T) {
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

func TestMixedAllowDenyFault(t *testing.T) {
	cfg, err := ParseFilterConfig(map[string]string{
		"fault":      "major",
		"fault_deny": "minor",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.FaultTypes) != 1 || cfg.FaultTypes[0] != 0 {
		t.Errorf("FaultTypes = %v, want [0]", cfg.FaultTypes)
	}
	if len(cfg.DenyFaults) != 1 || cfg.DenyFaults[0] != 1 {
		t.Errorf("DenyFaults = %v, want [1]", cfg.DenyFaults)
	}
}

func TestDenyMultiplePIDs(t *testing.T) {
	cfg, err := ParseFilterConfig(map[string]string{"pid_deny": "1,2,3"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.DenyPIDs) != 3 {
		t.Errorf("DenyPIDs = %v, want 3 entries", cfg.DenyPIDs)
	}
}

func TestDenyInvalidPID(t *testing.T) {
	_, err := ParseFilterConfig(map[string]string{"pid_deny": "xyz"})
	if err == nil {
		t.Fatal("expected error for invalid deny PID")
	}
}

func TestDenyInvalidUID(t *testing.T) {
	_, err := ParseFilterConfig(map[string]string{"uid_deny": "notanumber"})
	if err == nil {
		t.Fatal("expected error for invalid deny UID")
	}
}
