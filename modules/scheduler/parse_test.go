package scheduler

import (
	"encoding/binary"
	"testing"

	"github.com/PranavRJoshi/Veil/internal/events"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func buildRawSchedEvent(prevPID, nextPID, prevTID, nextTID, uid, cpu uint32,
	prevState, timestamp uint64, prevPrio, nextPrio uint32,
	prevComm, nextComm string) []byte {

	buf := make([]byte, schedEventSize)

	binary.LittleEndian.PutUint32(buf[0:4], prevPID)
	binary.LittleEndian.PutUint32(buf[4:8], nextPID)
	binary.LittleEndian.PutUint32(buf[8:12], prevTID)
	binary.LittleEndian.PutUint32(buf[12:16], nextTID)
	binary.LittleEndian.PutUint32(buf[16:20], uid)
	binary.LittleEndian.PutUint32(buf[20:24], cpu)
	binary.LittleEndian.PutUint64(buf[24:32], prevState)
	binary.LittleEndian.PutUint64(buf[32:40], timestamp)
	binary.LittleEndian.PutUint32(buf[40:44], prevPrio)
	binary.LittleEndian.PutUint32(buf[44:48], nextPrio)

	copy(buf[48:64], prevComm)
	copy(buf[64:80], nextComm)

	return buf
}

// ---------------------------------------------------------------------------
// parseEvent
// ---------------------------------------------------------------------------

func TestParseEvent_RoundTrip(t *testing.T) {
	raw := buildRawSchedEvent(
		1234, 5678, /* prev_pid, next_pid */
		1234, 5678, /* prev_tid, next_tid */
		0, 2, /* uid, cpu */
		0x0001, 99999, /* prev_state (SLEEPING), timestamp */
		120, 110, /* prev_prio, next_prio */
		"bash", "nginx",
	)

	e, err := parseEvent(raw)
	if err != nil {
		t.Fatalf("parseEvent: %v", err)
	}

	if e.PrevPID != 1234 {
		t.Errorf("PrevPID = %d, want 1234", e.PrevPID)
	}
	if e.NextPID != 5678 {
		t.Errorf("NextPID = %d, want 5678", e.NextPID)
	}
	if e.PrevTID != 1234 {
		t.Errorf("PrevTID = %d, want 1234", e.PrevTID)
	}
	if e.NextTID != 5678 {
		t.Errorf("NextTID = %d, want 5678", e.NextTID)
	}
	if e.UID != 0 {
		t.Errorf("UID = %d, want 0", e.UID)
	}
	if e.CPU != 2 {
		t.Errorf("CPU = %d, want 2", e.CPU)
	}
	if e.PrevState != 0x0001 {
		t.Errorf("PrevState = %d, want 1", e.PrevState)
	}
	if e.Timestamp != 99999 {
		t.Errorf("Timestamp = %d, want 99999", e.Timestamp)
	}
	if e.PrevPrio != 120 {
		t.Errorf("PrevPrio = %d, want 120", e.PrevPrio)
	}
	if e.NextPrio != 110 {
		t.Errorf("NextPrio = %d, want 110", e.NextPrio)
	}
	if e.Kind != events.KindScheduler {
		t.Errorf("Kind = %v, want KindScheduler", e.Kind)
	}
}

func TestParseEvent_ShortRead(t *testing.T) {
	_, err := parseEvent(make([]byte, 10))
	if err == nil {
		t.Fatal("expected error for short read")
	}
}

func TestParseEvent_ExactMinimumSize(t *testing.T) {
	raw := buildRawSchedEvent(1, 2, 1, 2, 0, 0, 0, 0, 120, 120, "a", "b")
	_, err := parseEvent(raw)
	if err != nil {
		t.Fatalf("exact size should work: %v", err)
	}
}

func TestParseEvent_ExtraBytes(t *testing.T) {
	raw := buildRawSchedEvent(1, 2, 1, 2, 0, 0, 0, 0, 120, 120, "a", "b")
	raw = append(raw, 0xFF, 0xFF)
	e, err := parseEvent(raw)
	if err != nil {
		t.Fatalf("extra bytes should be ignored: %v", err)
	}
	if e.PrevPID != 1 {
		t.Errorf("PrevPID = %d, want 1", e.PrevPID)
	}
}

// ---------------------------------------------------------------------------
// commString
// ---------------------------------------------------------------------------

func TestCommString_Normal(t *testing.T) {
	var b [16]byte
	copy(b[:], "bash")
	if commString(b) != "bash" {
		t.Errorf("got %q, want %q", commString(b), "bash")
	}
}

func TestCommString_Full(t *testing.T) {
	var b [16]byte
	copy(b[:], "12345678")
	if commString(b) != "12345678" {
		t.Errorf("got %q, want %q", commString(b), "12345678")
	}
}

func TestCommString_Empty(t *testing.T) {
	var b [16]byte
	if commString(b) != "" {
		t.Errorf("got %q, want empty", commString(b))
	}
}

// ---------------------------------------------------------------------------
// prevStateName
// ---------------------------------------------------------------------------

func TestPrevStateName(t *testing.T) {
	cases := []struct {
		state uint64
		want  string
	}{
		{0x0000, "RUNNING"},
		{0x0001, "SLEEPING"},
		{0x0002, "DISK_SLEEP"},
		{0x0004, "STOPPED"},
		{0x0008, "TRACED"},
		{0x0010, "EXIT_DEAD"},
		{0x0020, "ZOMBIE"},
		{0x0040, "PARKED"},
		{0x0080, "DEAD"},
		{0x0800, "NEW"},
		{0x1234, "0x1234"},
	}

	for _, tc := range cases {
		got := prevStateName(tc.state)
		if got != tc.want {
			t.Errorf("prevStateName(0x%x) = %q, want %q", tc.state, got, tc.want)
		}
	}
}
