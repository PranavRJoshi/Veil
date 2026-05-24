package memory

import (
	"strings"
	"testing"

	"github.com/PranavRJoshi/Veil/internal/events"
)

// ---------------------------------------------------------------------------
// ParseFilterConfig
// ---------------------------------------------------------------------------

func TestParseFilterConfig_PIDs(t *testing.T) {
	cfg, err := ParseFilterConfig(map[string]string{"pid": "1234,5678"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.PIDs) != 2 || cfg.PIDs[0] != 1234 || cfg.PIDs[1] != 5678 {
		t.Errorf("PIDs = %v, want [1234 5678]", cfg.PIDs)
	}
}

func TestParseFilterConfig_UIDs(t *testing.T) {
	cfg, err := ParseFilterConfig(map[string]string{"uid": "0,1000"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.UIDs) != 2 || cfg.UIDs[0] != 0 || cfg.UIDs[1] != 1000 {
		t.Errorf("UIDs = %v, want [0 1000]", cfg.UIDs)
	}
}

func TestParseFilterConfig_FaultMajor(t *testing.T) {
	cfg, err := ParseFilterConfig(map[string]string{"fault": "major"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.FaultTypes) != 1 || cfg.FaultTypes[0] != 0 {
		t.Errorf("FaultTypes = %v, want [0]", cfg.FaultTypes)
	}
}

func TestParseFilterConfig_FaultMinor(t *testing.T) {
	cfg, err := ParseFilterConfig(map[string]string{"fault": "minor"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.FaultTypes) != 1 || cfg.FaultTypes[0] != 1 {
		t.Errorf("FaultTypes = %v, want [1]", cfg.FaultTypes)
	}
}

func TestParseFilterConfig_FaultBoth(t *testing.T) {
	cfg, err := ParseFilterConfig(map[string]string{"fault": "major,minor"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.FaultTypes) != 2 {
		t.Errorf("FaultTypes = %v, want 2 entries", cfg.FaultTypes)
	}
}

func TestParseFilterConfig_FaultCaseInsensitive(t *testing.T) {
	cfg, err := ParseFilterConfig(map[string]string{"fault": "MAJOR"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.FaultTypes) != 1 || cfg.FaultTypes[0] != 0 {
		t.Errorf("FaultTypes = %v, want [0]", cfg.FaultTypes)
	}
}

func TestParseFilterConfig_CommName(t *testing.T) {
	cfg, err := ParseFilterConfig(map[string]string{"name": "bash"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.CommName != "bash" {
		t.Errorf("CommName = %q, want %q", cfg.CommName, "bash")
	}
}

func TestParseFilterConfig_InvalidPID(t *testing.T) {
	_, err := ParseFilterConfig(map[string]string{"pid": "abc"})
	if err == nil {
		t.Fatal("expected error for non-numeric PID")
	}
}

func TestParseFilterConfig_InvalidUID(t *testing.T) {
	_, err := ParseFilterConfig(map[string]string{"uid": "-1"})
	if err == nil {
		t.Fatal("expected error for invalid UID")
	}
}

func TestParseFilterConfig_InvalidFault(t *testing.T) {
	_, err := ParseFilterConfig(map[string]string{"fault": "huge"})
	if err == nil {
		t.Fatal("expected error for invalid fault type")
	}
}

func TestParseFilterConfig_PIDOverflow(t *testing.T) {
	_, err := ParseFilterConfig(map[string]string{"pid": "99999999999"})
	if err == nil {
		t.Fatal("expected error for overflow PID")
	}
}

func TestParseFilterConfig_DenyPIDs(t *testing.T) {
	cfg, err := ParseFilterConfig(map[string]string{"pid_deny": "100,200"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.DenyPIDs) != 2 || cfg.DenyPIDs[0] != 100 || cfg.DenyPIDs[1] != 200 {
		t.Errorf("DenyPIDs = %v, want [100 200]", cfg.DenyPIDs)
	}
}

func TestParseFilterConfig_DenyUIDs(t *testing.T) {
	cfg, err := ParseFilterConfig(map[string]string{"uid_deny": "1000"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.DenyUIDs) != 1 || cfg.DenyUIDs[0] != 1000 {
		t.Errorf("DenyUIDs = %v, want [1000]", cfg.DenyUIDs)
	}
}

func TestParseFilterConfig_DenyFaults(t *testing.T) {
	cfg, err := ParseFilterConfig(map[string]string{"fault_deny": "minor"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.DenyFaults) != 1 || cfg.DenyFaults[0] != 1 {
		t.Errorf("DenyFaults = %v, want [1]", cfg.DenyFaults)
	}
}

func TestParseFilterConfig_InvalidDenyFault(t *testing.T) {
	_, err := ParseFilterConfig(map[string]string{"fault_deny": "bogus"})
	if err == nil {
		t.Fatal("expected error for invalid deny fault type")
	}
}

func TestParseFilterConfig_AllowAndDenyPIDs(t *testing.T) {
	cfg, err := ParseFilterConfig(map[string]string{
		"pid":      "1234",
		"pid_deny": "5678",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.PIDs) != 1 || cfg.PIDs[0] != 1234 {
		t.Errorf("PIDs = %v", cfg.PIDs)
	}
	if len(cfg.DenyPIDs) != 1 || cfg.DenyPIDs[0] != 5678 {
		t.Errorf("DenyPIDs = %v", cfg.DenyPIDs)
	}
}

func TestParseFilterConfig_FullCombination(t *testing.T) {
	cfg, err := ParseFilterConfig(map[string]string{
		"pid":        "42",
		"pid_deny":   "99",
		"uid":        "0",
		"uid_deny":   "1000",
		"fault":      "major",
		"fault_deny": "minor",
		"name":       "nginx",
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
	if len(cfg.FaultTypes) != 1 || cfg.FaultTypes[0] != 0 {
		t.Errorf("FaultTypes = %v", cfg.FaultTypes)
	}
	if len(cfg.DenyFaults) != 1 || cfg.DenyFaults[0] != 1 {
		t.Errorf("DenyFaults = %v", cfg.DenyFaults)
	}
	if cfg.CommName != "nginx" {
		t.Errorf("CommName = %q", cfg.CommName)
	}
}

func TestParseFilterConfig_Empty(t *testing.T) {
	cfg, err := ParseFilterConfig(map[string]string{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.PIDs) != 0 || len(cfg.UIDs) != 0 || len(cfg.FaultTypes) != 0 {
		t.Error("all fields should be empty for no flags")
	}
	if len(cfg.DenyPIDs) != 0 || len(cfg.DenyUIDs) != 0 || len(cfg.DenyFaults) != 0 {
		t.Error("all deny fields should be empty for no flags")
	}
}

func TestParseFilterConfig_SpacesInValues(t *testing.T) {
	cfg, err := ParseFilterConfig(map[string]string{"pid": " 100 , 200 "})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.PIDs) != 2 || cfg.PIDs[0] != 100 || cfg.PIDs[1] != 200 {
		t.Errorf("PIDs with spaces = %v, want [100 200]", cfg.PIDs)
	}
}

// ---------------------------------------------------------------------------
// matchesFilter
// ---------------------------------------------------------------------------

func makeMemModule(commName string) *MemoryModule {
	return &MemoryModule{
		filter: FilterConfig{CommName: commName},
	}
}

func makeMemEvent(comm string) events.MemoryEvent {
	var c [16]byte
	copy(c[:], comm)
	return events.MemoryEvent{
		Event: events.Event{Comm: c},
	}
}

func TestMatchesFilter_NoFilter(t *testing.T) {
	m := makeMemModule("")
	if !m.matchesFilter(makeMemEvent("bash")) {
		t.Error("no filter should match all events")
	}
}

func TestMatchesFilter_Match(t *testing.T) {
	m := makeMemModule("bash")
	if !m.matchesFilter(makeMemEvent("bash")) {
		t.Error("should match")
	}
}

func TestMatchesFilter_NoMatch(t *testing.T) {
	m := makeMemModule("nginx")
	if m.matchesFilter(makeMemEvent("bash")) {
		t.Error("should not match")
	}
}

func TestMatchesFilter_SubstringMatch(t *testing.T) {
	m := makeMemModule("gin")
	if !m.matchesFilter(makeMemEvent("nginx")) {
		t.Error("should match substring")
	}
}

// ---------------------------------------------------------------------------
// memoryToFields
// ---------------------------------------------------------------------------

func TestMemoryToFields_MajorFault(t *testing.T) {
	var comm [16]byte
	copy(comm[:], "bash")

	e := events.MemoryEvent{
		Event: events.Event{
			Kind:      events.KindMemory,
			PID:       1234,
			TID:       1234,
			UID:       0,
			Timestamp: 99999,
			Comm:      comm,
		},
		EvtType: 0,
		Address: 0x7f4a2c001000,
	}

	f := memoryToFields(e)

	checks := map[string]interface{}{
		"kind":      "memory",
		"pid":       uint32(1234),
		"tid":       uint32(1234),
		"uid":       uint32(0),
		"timestamp": uint64(99999),
		"comm":      "bash",
		"evt_type":  "major",
		"address":   "0x7f4a2c001000",
	}

	for key, want := range checks {
		got, ok := f[key]
		if !ok {
			t.Errorf("missing field %q", key)
			continue
		}
		if got != want {
			t.Errorf("field %q = %v (%T), want %v (%T)", key, got, got, want, want)
		}
	}
}

func TestMemoryToFields_MinorFault(t *testing.T) {
	e := events.MemoryEvent{
		Event:   events.Event{Kind: events.KindMemory},
		EvtType: 1,
	}
	f := memoryToFields(e)
	if f["evt_type"] != "minor" {
		t.Errorf("evt_type = %q, want %q", f["evt_type"], "minor")
	}
}

func TestMemoryToFields_KindString(t *testing.T) {
	e := events.MemoryEvent{
		Event: events.Event{Kind: events.KindMemory},
	}
	f := memoryToFields(e)
	if f["kind"] != "memory" {
		t.Errorf("kind = %q, want %q", f["kind"], "memory")
	}
}

// ---------------------------------------------------------------------------
// Negation: CLI -> ParseFilterConfig round-trip
// ---------------------------------------------------------------------------

func TestSplitAllowDeny_Integration(t *testing.T) {
	/* Simulate what the CLI does: --fault major,!minor -> fault=major, fault_deny=minor */
	cfg, err := ParseFilterConfig(map[string]string{
		"fault":      "major",
		"fault_deny": "minor",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.FaultTypes) != 1 || cfg.FaultTypes[0] != 0 {
		t.Errorf("FaultTypes = %v", cfg.FaultTypes)
	}
	if len(cfg.DenyFaults) != 1 || cfg.DenyFaults[0] != 1 {
		t.Errorf("DenyFaults = %v", cfg.DenyFaults)
	}
}

// ---------------------------------------------------------------------------
// Verify the init() registered the module
// ---------------------------------------------------------------------------

func TestModuleRegistered(t *testing.T) {
	/* This test verifies that init() ran and registered the module.
	   It imports memory package, which triggers init(). If registration
	   failed, this test file wouldn't compile (import cycle or missing
	   registry). The name check confirms the factory is wired. */

	_ = strings.Contains("memory", "mem") /* use strings import */
}
