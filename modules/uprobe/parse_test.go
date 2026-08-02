package uprobe

import (
	"encoding/binary"
	"testing"

	"github.com/PranavRJoshi/Veil/internal/events"
)

func buildRawUprobeEvent(pid, tid, uid uint32, timestamp, durationNs uint64, comm string) []byte {
	buf := make([]byte, uprobeEventSize)

	binary.LittleEndian.PutUint32(buf[0:4], pid)
	binary.LittleEndian.PutUint32(buf[4:8], tid)
	binary.LittleEndian.PutUint32(buf[8:12], uid)
	binary.LittleEndian.PutUint64(buf[16:24], timestamp)
	binary.LittleEndian.PutUint64(buf[24:32], durationNs)
	copy(buf[32:48], comm)

	return buf
}

func TestParseEvent_RoundTrip(t *testing.T) {
	raw := buildRawUprobeEvent(1234, 5678, 1000, 99999, 4200, "bash")

	e, err := parseEvent(raw)
	if err != nil {
		t.Fatalf("parseEvent: %v", err)
	}

	if e.PID != 1234 {
		t.Errorf("PID = %d, want 1234", e.PID)
	}
	if e.TID != 5678 {
		t.Errorf("TID = %d, want 5678", e.TID)
	}
	if e.UID != 1000 {
		t.Errorf("UID = %d, want 1000", e.UID)
	}
	if e.Timestamp != 99999 {
		t.Errorf("Timestamp = %d, want 99999", e.Timestamp)
	}
	if e.DurationNs != 4200 {
		t.Errorf("DurationNs = %d, want 4200", e.DurationNs)
	}
	if e.ProcessName() != "bash" {
		t.Errorf("ProcessName = %q, want %q", e.ProcessName(), "bash")
	}
	if e.Kind != events.KindUprobe {
		t.Errorf("Kind = %v, want KindUprobe", e.Kind)
	}
}

func TestParseEvent_EntryOnlyZeroDuration(t *testing.T) {
	raw := buildRawUprobeEvent(1, 1, 0, 10, 0, "x")
	e, err := parseEvent(raw)
	if err != nil {
		t.Fatalf("parseEvent: %v", err)
	}
	if e.DurationNs != 0 {
		t.Errorf("DurationNs = %d, want 0 for entry-only", e.DurationNs)
	}
}

func TestParseEvent_ShortRead(t *testing.T) {
	_, err := parseEvent(make([]byte, 10))
	if err == nil {
		t.Fatal("expected error for short read")
	}
}

func TestParseEvent_ExactMinimumSize(t *testing.T) {
	raw := buildRawUprobeEvent(1, 1, 0, 0, 0, "a")
	if _, err := parseEvent(raw); err != nil {
		t.Fatalf("exact size should work: %v", err)
	}
}

func TestParseEvent_ExtraBytes(t *testing.T) {
	raw := append(buildRawUprobeEvent(7, 7, 0, 0, 0, "a"), 0xFF, 0xFF)
	e, err := parseEvent(raw)
	if err != nil {
		t.Fatalf("extra bytes should be ignored: %v", err)
	}
	if e.PID != 7 {
		t.Errorf("PID = %d, want 7", e.PID)
	}
}

func TestParseTarget(t *testing.T) {
	cases := []struct {
		raw        string
		wantPath   string
		wantSymbol string
		wantErr    bool
	}{
		{"/usr/bin/bash:readline", "/usr/bin/bash", "readline", false},
		{"/lib/libc.so.6:malloc", "/lib/libc.so.6", "malloc", false},
		{" /bin/ls : main ", "/bin/ls", "main", false},
		{"noseparator", "", "", true},
		{"/path:", "", "", true},
		{":symbol", "", "", true},
	}

	for _, tc := range cases {
		got, err := parseTarget(tc.raw)
		if tc.wantErr {
			if err == nil {
				t.Errorf("parseTarget(%q) = %+v, want error", tc.raw, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseTarget(%q): %v", tc.raw, err)
			continue
		}
		if got.Path != tc.wantPath || got.Symbol != tc.wantSymbol {
			t.Errorf("parseTarget(%q) = %q:%q, want %q:%q",
				tc.raw, got.Path, got.Symbol, tc.wantPath, tc.wantSymbol)
		}
	}
}

func TestParseFilterConfig_RequiresTarget(t *testing.T) {
	if _, err := ParseFilterConfig(map[string]string{}); err == nil {
		t.Fatal("expected error when --uprobe is absent")
	}
}

func TestParseFilterConfig_LatencyAndFilters(t *testing.T) {
	cfg, err := ParseFilterConfig(map[string]string{
		"uprobe":  "/bin/sh:main",
		"latency": "true",
		"pid":     "1,2",
		"uid":     "1000",
	})
	if err != nil {
		t.Fatalf("ParseFilterConfig: %v", err)
	}
	if !cfg.Latency {
		t.Error("Latency = false, want true")
	}
	if cfg.Target.Symbol != "main" {
		t.Errorf("Target.Symbol = %q, want main", cfg.Target.Symbol)
	}
	if len(cfg.PIDs) != 2 || len(cfg.UIDs) != 1 {
		t.Errorf("PIDs=%v UIDs=%v, want 2 pids and 1 uid", cfg.PIDs, cfg.UIDs)
	}
}
