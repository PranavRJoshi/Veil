package network

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

func TestParseFilterConfig_DenyPorts(t *testing.T) {
	cfg, err := ParseFilterConfig(map[string]string{"port_deny": "22,23"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.DenyPorts) != 2 || cfg.DenyPorts[0] != 22 || cfg.DenyPorts[1] != 23 {
		t.Errorf("expected DenyPorts [22 23], got %v", cfg.DenyPorts)
	}
	if len(cfg.Ports) != 0 {
		t.Errorf("Ports should be empty, got %v", cfg.Ports)
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

func TestParseFilterConfig_InvalidDenyPort(t *testing.T) {
	_, err := ParseFilterConfig(map[string]string{"port_deny": "http"})
	if err == nil {
		t.Fatal("expected error for non-numeric deny port")
	}
}

func TestParseFilterConfig_DenyPortOverflow(t *testing.T) {
	_, err := ParseFilterConfig(map[string]string{"port_deny": "65536"})
	if err == nil {
		t.Fatal("expected error for deny port exceeding uint16 max")
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

func TestParseFilterConfig_AllowAndDenyPorts(t *testing.T) {
	cfg, err := ParseFilterConfig(map[string]string{
		"port":      "443,8080",
		"port_deny": "22",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.Ports) != 2 || cfg.Ports[0] != 443 || cfg.Ports[1] != 8080 {
		t.Errorf("Ports = %v, want [443 8080]", cfg.Ports)
	}
	if len(cfg.DenyPorts) != 1 || cfg.DenyPorts[0] != 22 {
		t.Errorf("DenyPorts = %v, want [22]", cfg.DenyPorts)
	}
}

func TestParseFilterConfig_FullCombinationWithDeny(t *testing.T) {
	cfg, err := ParseFilterConfig(map[string]string{
		"pid":       "42",
		"pid_deny":  "99",
		"uid":       "0",
		"uid_deny":  "1000",
		"port":      "443",
		"port_deny": "22",
		"name":      "curl",
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
	if len(cfg.UIDs) != 1 || cfg.UIDs[0] != 0 {
		t.Errorf("UIDs = %v", cfg.UIDs)
	}
	if len(cfg.DenyUIDs) != 1 || cfg.DenyUIDs[0] != 1000 {
		t.Errorf("DenyUIDs = %v", cfg.DenyUIDs)
	}
	if len(cfg.Ports) != 1 || cfg.Ports[0] != 443 {
		t.Errorf("Ports = %v", cfg.Ports)
	}
	if len(cfg.DenyPorts) != 1 || cfg.DenyPorts[0] != 22 {
		t.Errorf("DenyPorts = %v", cfg.DenyPorts)
	}
	if cfg.CommName != "curl" {
		t.Errorf("CommName = %q", cfg.CommName)
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
	if len(cfg.DenyPorts) != 0 {
		t.Errorf("DenyPorts should be empty, got %v", cfg.DenyPorts)
	}
}

func TestParseFilterConfig_DenyPortsWithSpaces(t *testing.T) {
	cfg, err := ParseFilterConfig(map[string]string{"port_deny": " 22 , 23 "})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.DenyPorts) != 2 || cfg.DenyPorts[0] != 22 || cfg.DenyPorts[1] != 23 {
		t.Errorf("DenyPorts = %v, want [22 23]", cfg.DenyPorts)
	}
}

func TestParseFilterConfig_DenyPIDsWithSpaces(t *testing.T) {
	cfg, err := ParseFilterConfig(map[string]string{"pid_deny": " 100 , 200 "})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.DenyPIDs) != 2 || cfg.DenyPIDs[0] != 100 || cfg.DenyPIDs[1] != 200 {
		t.Errorf("DenyPIDs = %v, want [100 200]", cfg.DenyPIDs)
	}
}
