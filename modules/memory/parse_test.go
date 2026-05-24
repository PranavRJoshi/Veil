package memory

import (
	"encoding/binary"
	"testing"

	"github.com/PranavRJoshi/Veil/internal/events"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func buildRawMemEvent(pid, tid, uid uint32, evtType uint8,
	timestamp, address uint64, comm string) []byte {

	buf := make([]byte, memEventSize)

	binary.LittleEndian.PutUint32(buf[0:4], pid)
	binary.LittleEndian.PutUint32(buf[4:8], tid)
	binary.LittleEndian.PutUint32(buf[8:12], uid)
	buf[12] = evtType
	/* buf[13:16] = pad (zero) */
	binary.LittleEndian.PutUint64(buf[16:24], timestamp)
	binary.LittleEndian.PutUint64(buf[24:32], address)

	copy(buf[32:48], comm)

	return buf
}

// ---------------------------------------------------------------------------
// parseEvent
// ---------------------------------------------------------------------------

func TestParseEvent_RoundTrip(t *testing.T) {
	raw := buildRawMemEvent(
		1234, 1234, 0, /* pid, tid, uid */
		0,             /* evt_type: major */
		99999,         /* timestamp */
		0x7f4a2c001000, /* address */
		"bash",
	)

	e, err := parseEvent(raw)
	if err != nil {
		t.Fatalf("parseEvent: %v", err)
	}

	if e.PID != 1234 {
		t.Errorf("PID = %d, want 1234", e.PID)
	}
	if e.TID != 1234 {
		t.Errorf("TID = %d, want 1234", e.TID)
	}
	if e.UID != 0 {
		t.Errorf("UID = %d, want 0", e.UID)
	}
	if e.EvtType != 0 {
		t.Errorf("EvtType = %d, want 0 (major)", e.EvtType)
	}
	if e.Timestamp != 99999 {
		t.Errorf("Timestamp = %d, want 99999", e.Timestamp)
	}
	if e.Address != 0x7f4a2c001000 {
		t.Errorf("Address = 0x%x, want 0x7f4a2c001000", e.Address)
	}
	if e.Kind != events.KindMemory {
		t.Errorf("Kind = %v, want KindMemory", e.Kind)
	}
}

func TestParseEvent_MinorFault(t *testing.T) {
	raw := buildRawMemEvent(5678, 5679, 1000, 1, 12345, 0xdead0000, "nginx")
	e, err := parseEvent(raw)
	if err != nil {
		t.Fatalf("parseEvent: %v", err)
	}
	if e.EvtType != 1 {
		t.Errorf("EvtType = %d, want 1 (minor)", e.EvtType)
	}
	if e.ProcessName() != "nginx" {
		t.Errorf("comm = %q, want %q", e.ProcessName(), "nginx")
	}
}

func TestParseEvent_ShortRead(t *testing.T) {
	_, err := parseEvent(make([]byte, 10))
	if err == nil {
		t.Fatal("expected error for short read")
	}
}

func TestParseEvent_ExactMinimumSize(t *testing.T) {
	raw := buildRawMemEvent(1, 1, 0, 0, 0, 0x1000, "a")
	_, err := parseEvent(raw)
	if err != nil {
		t.Fatalf("exact size should work: %v", err)
	}
}

func TestParseEvent_ExtraBytes(t *testing.T) {
	raw := buildRawMemEvent(1, 1, 0, 0, 1, 0x1000, "test")
	raw = append(raw, 0xFF, 0xFF)
	e, err := parseEvent(raw)
	if err != nil {
		t.Fatalf("extra bytes should be ignored: %v", err)
	}
	if e.PID != 1 {
		t.Errorf("PID = %d, want 1", e.PID)
	}
}

func TestParseEvent_FullComm(t *testing.T) {
	/* 16-byte comm field, no null terminator */
	raw := buildRawMemEvent(1, 1, 0, 0, 1, 0x1000, "0123456789abcdef")
	e, err := parseEvent(raw)
	if err != nil {
		t.Fatalf("parseEvent: %v", err)
	}
	if len(e.ProcessName()) != 16 {
		t.Errorf("comm length = %d, want 16", len(e.ProcessName()))
	}
}

// ---------------------------------------------------------------------------
// faultTypeName
// ---------------------------------------------------------------------------

func TestFaultTypeName(t *testing.T) {
	cases := []struct {
		code uint8
		want string
	}{
		{0, "major"},
		{1, "minor"},
		{99, "unknown(99)"},
	}

	for _, tc := range cases {
		got := faultTypeName(tc.code)
		if got != tc.want {
			t.Errorf("faultTypeName(%d) = %q, want %q", tc.code, got, tc.want)
		}
	}
}
