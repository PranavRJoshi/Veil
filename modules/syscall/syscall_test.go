package syscall

import (
	"testing"

	"github.com/PranavRJoshi/Veil/internal/events"
)

// ---------------------------------------------------------------------------
// ParseFilterConfig
// ---------------------------------------------------------------------------

func TestParseFilterConfig_SinglePID(t *testing.T) {
	cfg, err := ParseFilterConfig(map[string]string{"pid": "1234"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.PIDs) != 1 || cfg.PIDs[0] != 1234 {
		t.Errorf("expected [1234], got %v", cfg.PIDs)
	}
}

func TestParseFilterConfig_MultiplePIDs(t *testing.T) {
	cfg, err := ParseFilterConfig(map[string]string{"pid": "1,2,3"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.PIDs) != 3 {
		t.Fatalf("expected 3 PIDs, got %d", len(cfg.PIDs))
	}
	if cfg.PIDs[0] != 1 || cfg.PIDs[1] != 2 || cfg.PIDs[2] != 3 {
		t.Errorf("expected [1 2 3], got %v", cfg.PIDs)
	}
}

func TestParseFilterConfig_PIDWithSpaces(t *testing.T) {
	cfg, err := ParseFilterConfig(map[string]string{"pid": " 100 , 200 "})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.PIDs) != 2 || cfg.PIDs[0] != 100 || cfg.PIDs[1] != 200 {
		t.Errorf("expected [100 200], got %v", cfg.PIDs)
	}
}

func TestParseFilterConfig_InvalidPID(t *testing.T) {
	_, err := ParseFilterConfig(map[string]string{"pid": "abc"})
	if err == nil {
		t.Fatal("expected error for non-numeric PID")
	}
}

func TestParseFilterConfig_NegativePID(t *testing.T) {
	_, err := ParseFilterConfig(map[string]string{"pid": "-1"})
	if err == nil {
		t.Fatal("expected error for negative PID")
	}
}

func TestParseFilterConfig_OverflowPID(t *testing.T) {
	_, err := ParseFilterConfig(map[string]string{"pid": "4294967296"})
	if err == nil {
		t.Fatal("expected error for PID exceeding uint32 max")
	}
}

func TestParseFilterConfig_UIDs(t *testing.T) {
	cfg, err := ParseFilterConfig(map[string]string{"uid": "0,1000"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.UIDs) != 2 || cfg.UIDs[0] != 0 || cfg.UIDs[1] != 1000 {
		t.Errorf("expected [0 1000], got %v", cfg.UIDs)
	}
}

func TestParseFilterConfig_InvalidUID(t *testing.T) {
	_, err := ParseFilterConfig(map[string]string{"uid": "root"})
	if err == nil {
		t.Fatal("expected error for non-numeric UID")
	}
}

func TestParseFilterConfig_Syscalls(t *testing.T) {
	cfg, err := ParseFilterConfig(map[string]string{"syscall": "openat,read,write"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.Syscalls) != 3 {
		t.Fatalf("expected 3 syscalls, got %d", len(cfg.Syscalls))
	}
	if cfg.Syscalls[0] != "openat" || cfg.Syscalls[1] != "read" || cfg.Syscalls[2] != "write" {
		t.Errorf("expected [openat read write], got %v", cfg.Syscalls)
	}
}

func TestParseFilterConfig_SyscallsWithSpaces(t *testing.T) {
	cfg, err := ParseFilterConfig(map[string]string{"syscall": " openat , close "})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Syscalls[0] != "openat" || cfg.Syscalls[1] != "close" {
		t.Errorf("spaces not trimmed: got %v", cfg.Syscalls)
	}
}

func TestParseFilterConfig_CommName(t *testing.T) {
	cfg, err := ParseFilterConfig(map[string]string{"name": "nginx"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.CommName != "nginx" {
		t.Errorf("expected CommName 'nginx', got %q", cfg.CommName)
	}
}

func TestParseFilterConfig_EmptyFlags(t *testing.T) {
	cfg, err := ParseFilterConfig(map[string]string{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.PIDs) != 0 || len(cfg.UIDs) != 0 || len(cfg.Syscalls) != 0 || cfg.CommName != "" {
		t.Errorf("expected empty config, got %+v", cfg)
	}
}

func TestParseFilterConfig_CombinedFlags(t *testing.T) {
	cfg, err := ParseFilterConfig(map[string]string{
		"pid":     "42",
		"uid":     "1000",
		"syscall": "read",
		"name":    "cat",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.PIDs) != 1 || cfg.PIDs[0] != 42 {
		t.Errorf("PID: %v", cfg.PIDs)
	}
	if len(cfg.UIDs) != 1 || cfg.UIDs[0] != 1000 {
		t.Errorf("UID: %v", cfg.UIDs)
	}
	if len(cfg.Syscalls) != 1 || cfg.Syscalls[0] != "read" {
		t.Errorf("Syscalls: %v", cfg.Syscalls)
	}
	if cfg.CommName != "cat" {
		t.Errorf("CommName: %q", cfg.CommName)
	}
}

// ---------------------------------------------------------------------------
// matchesFilter
// ---------------------------------------------------------------------------

func makeEvent(comm string) events.SyscallEvent {
	var e events.SyscallEvent
	copy(e.Comm[:], comm)
	return e
}

func TestMatchesFilter_NoFilter(t *testing.T) {
	mod := &TracerModule{filter: FilterConfig{}}
	if !mod.matchesFilter(makeEvent("anything")) {
		t.Error("empty filter should match all events")
	}
}

func TestMatchesFilter_CommMatch(t *testing.T) {
	mod := &TracerModule{filter: FilterConfig{CommName: "bash"}}
	if !mod.matchesFilter(makeEvent("bash")) {
		t.Error("exact match should pass")
	}
}

func TestMatchesFilter_CommSubstring(t *testing.T) {
	mod := &TracerModule{filter: FilterConfig{CommName: "sh"}}
	if !mod.matchesFilter(makeEvent("bash")) {
		t.Error("substring match should pass")
	}
}

func TestMatchesFilter_CommNoMatch(t *testing.T) {
	mod := &TracerModule{filter: FilterConfig{CommName: "nginx"}}
	if mod.matchesFilter(makeEvent("bash")) {
		t.Error("non-matching comm should be filtered out")
	}
}

func TestMatchesFilter_CommEmptyProcess(t *testing.T) {
	mod := &TracerModule{filter: FilterConfig{CommName: "bash"}}
	if mod.matchesFilter(makeEvent("")) {
		t.Error("empty comm should not match a filter")
	}
}

// ---------------------------------------------------------------------------
// toFields
// ---------------------------------------------------------------------------

func TestToFields_AllFieldsPresent(t *testing.T) {
	var e events.SyscallEvent
	e.Kind = events.KindSyscall
	e.PID = 1234
	e.TID = 1235
	e.UID = 1000
	e.GID = 1000
	e.Timestamp = 99999
	e.SyscallNr = 257
	copy(e.Comm[:], "bash")

	f := syscallToFields(e)

	requiredKeys := []string{"kind", "pid", "tid", "uid", "gid", "timestamp", "syscall_nr", "syscall", "comm"}
	for _, k := range requiredKeys {
		if _, ok := f[k]; !ok {
			t.Errorf("missing key %q in toFields output", k)
		}
	}

	if f["pid"] != uint32(1234) {
		t.Errorf("pid = %v, want 1234", f["pid"])
	}
	if f["comm"] != "bash" {
		t.Errorf("comm = %v, want 'bash'", f["comm"])
	}
	if f["kind"] != "syscall" {
		t.Errorf("kind = %v, want 'syscall'", f["kind"])
	}
}
