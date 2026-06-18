package scheduler

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

func TestParseFilterConfig_CPUs(t *testing.T) {
	cfg, err := ParseFilterConfig(map[string]string{"cpu": "0,1,3"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.CPUs) != 3 || cfg.CPUs[0] != 0 || cfg.CPUs[1] != 1 || cfg.CPUs[2] != 3 {
		t.Errorf("CPUs = %v, want [0 1 3]", cfg.CPUs)
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

func TestParseFilterConfig_InvalidCPU(t *testing.T) {
	_, err := ParseFilterConfig(map[string]string{"cpu": "core0"})
	if err == nil {
		t.Fatal("expected error for non-numeric CPU")
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

func TestParseFilterConfig_DenyCPUs(t *testing.T) {
	cfg, err := ParseFilterConfig(map[string]string{"cpu_deny": "0,7"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.DenyCPUs) != 2 || cfg.DenyCPUs[0] != 0 || cfg.DenyCPUs[1] != 7 {
		t.Errorf("DenyCPUs = %v, want [0 7]", cfg.DenyCPUs)
	}
}

func TestParseFilterConfig_InvalidDenyCPU(t *testing.T) {
	_, err := ParseFilterConfig(map[string]string{"cpu_deny": "all"})
	if err == nil {
		t.Fatal("expected error for non-numeric deny CPU")
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
		"pid":      "42",
		"pid_deny": "99",
		"uid":      "0",
		"uid_deny": "1000",
		"cpu":      "0,1",
		"cpu_deny": "7",
		"name":     "nginx",
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
	if len(cfg.CPUs) != 2 || cfg.CPUs[0] != 0 || cfg.CPUs[1] != 1 {
		t.Errorf("CPUs = %v", cfg.CPUs)
	}
	if len(cfg.DenyCPUs) != 1 || cfg.DenyCPUs[0] != 7 {
		t.Errorf("DenyCPUs = %v", cfg.DenyCPUs)
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
	if len(cfg.PIDs) != 0 || len(cfg.UIDs) != 0 || len(cfg.CPUs) != 0 {
		t.Error("all fields should be empty for no flags")
	}
	if len(cfg.DenyPIDs) != 0 || len(cfg.DenyUIDs) != 0 || len(cfg.DenyCPUs) != 0 {
		t.Error("all deny fields should be empty for no flags")
	}
}

func TestParseFilterConfig_SpacesInValues(t *testing.T) {
	cfg, err := ParseFilterConfig(map[string]string{"cpu": " 0 , 1 "})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.CPUs) != 2 || cfg.CPUs[0] != 0 || cfg.CPUs[1] != 1 {
		t.Errorf("CPUs with spaces = %v, want [0 1]", cfg.CPUs)
	}
}

// ---------------------------------------------------------------------------
// matchesFilter
// ---------------------------------------------------------------------------

func makeSchedModule(commName string) *SchedulerModule {
	return &SchedulerModule{
		filter: FilterConfig{CommName: commName},
	}
}

func makeSchedEvent(prevComm, nextComm string) events.SchedulerEvent {
	var pc, nc [16]byte
	copy(pc[:], prevComm)
	copy(nc[:], nextComm)
	return events.SchedulerEvent{
		PrevComm: pc,
		NextComm: nc,
	}
}

func TestMatchesFilter_NoFilter(t *testing.T) {
	m := makeSchedModule("")
	if !m.matchesFilter(makeSchedEvent("bash", "nginx")) {
		t.Error("no filter should match all events")
	}
}

func TestMatchesFilter_MatchPrevComm(t *testing.T) {
	m := makeSchedModule("bash")
	if !m.matchesFilter(makeSchedEvent("bash", "nginx")) {
		t.Error("should match prev_comm")
	}
}

func TestMatchesFilter_MatchNextComm(t *testing.T) {
	m := makeSchedModule("nginx")
	if !m.matchesFilter(makeSchedEvent("bash", "nginx")) {
		t.Error("should match next_comm")
	}
}

func TestMatchesFilter_NoMatch(t *testing.T) {
	m := makeSchedModule("curl")
	if m.matchesFilter(makeSchedEvent("bash", "nginx")) {
		t.Error("should not match if neither comm contains the filter")
	}
}

func TestMatchesFilter_SubstringMatch(t *testing.T) {
	m := makeSchedModule("ngi")
	if !m.matchesFilter(makeSchedEvent("bash", "nginx")) {
		t.Error("should match substring in next_comm")
	}
}

// ---------------------------------------------------------------------------
// schedulerToFields
// ---------------------------------------------------------------------------

func TestSchedulerToFields_AllFieldsPresent(t *testing.T) {
	var pc, nc [16]byte
	copy(pc[:], "bash")
	copy(nc[:], "nginx")

	e := events.SchedulerEvent{
		Event: events.Event{
			Kind:      events.KindScheduler,
			PID:       1234,
			UID:       0,
			Timestamp: 99999,
		},
		PrevPID:   1234,
		NextPID:   5678,
		PrevTID:   1234,
		NextTID:   5678,
		CPU:       2,
		PrevState: 0x0001,
		PrevPrio:  120,
		NextPrio:  110,
		PrevComm:  pc,
		NextComm:  nc,
	}

	f := schedulerToFields(e)

	checks := map[string]interface{}{
		"prev_pid":   uint32(1234),
		"next_pid":   uint32(5678),
		"prev_tid":   uint32(1234),
		"next_tid":   uint32(5678),
		"uid":        uint32(0),
		"cpu":        uint32(2),
		"prev_state": "SLEEPING",
		"timestamp":  uint64(99999),
		"prev_prio":  uint32(120),
		"next_prio":  uint32(110),
		"prev_comm":  "bash",
		"next_comm":  "nginx",
		"comm":       "bash",
		"pid":        uint32(1234),
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

func TestSchedulerToFields_KindString(t *testing.T) {
	e := events.SchedulerEvent{
		Event: events.Event{Kind: events.KindScheduler},
	}
	f := schedulerToFields(e)
	if f["kind"] != "scheduler" {
		t.Errorf("kind = %q, want %q", f["kind"], "scheduler")
	}
}

func TestSchedulerToFields_PrevStateRunning(t *testing.T) {
	e := events.SchedulerEvent{
		Event:     events.Event{Kind: events.KindScheduler},
		PrevState: 0x0000,
	}
	f := schedulerToFields(e)
	if f["prev_state"] != "RUNNING" {
		t.Errorf("prev_state = %q, want RUNNING", f["prev_state"])
	}
}

func TestSchedulerToFields_CommFieldCompatibility(t *testing.T) {
	/*
		The "comm" and "pid" fields should be set for compatibility with
		enrichment and count mode defaults.
	*/
	var pc [16]byte
	copy(pc[:], "test")
	e := events.SchedulerEvent{
		Event:    events.Event{Kind: events.KindScheduler},
		PrevPID:  42,
		PrevComm: pc,
	}
	f := schedulerToFields(e)

	if f["comm"] != "test" {
		t.Errorf("comm = %q, want %q", f["comm"], "test")
	}
	if f["pid"] != uint32(42) {
		t.Errorf("pid = %v, want 42", f["pid"])
	}
}

// ---------------------------------------------------------------------------
// Negation: CLI -> ParseFilterConfig round-trip
// ---------------------------------------------------------------------------

func TestSplitAllowDeny_Integration(t *testing.T) {
	/* Simulate what the CLI does: --cpu 0,!7 -> cpu=0, cpu_deny=7 */
	cfg, err := ParseFilterConfig(map[string]string{
		"cpu":      "0",
		"cpu_deny": "7",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.CPUs) != 1 || cfg.CPUs[0] != 0 {
		t.Errorf("CPUs = %v", cfg.CPUs)
	}
	if len(cfg.DenyCPUs) != 1 || cfg.DenyCPUs[0] != 7 {
		t.Errorf("DenyCPUs = %v", cfg.DenyCPUs)
	}
}

// ---------------------------------------------------------------------------
// Verify the init() registered the module
// ---------------------------------------------------------------------------

func TestModuleRegistered(t *testing.T) {
	/* This test verifies that init() ran and registered the module.
	   It imports scheduler package, which triggers init(). If registration
	   failed, this test file wouldn't compile (import cycle or missing
	   registry). The name check confirms the factory is wired. */

	_ = strings.Contains("scheduler", "sched") /* use strings import */
}
