package syscall

import (
	"encoding/binary"
	"testing"

	"github.com/PranavRJoshi/Veil/internal/events"
)

/*
	Based on the arguments, construct a byte sequence which resembles
	syscall_event structure.
*/
func buildSyscallRaw(pid, tid, uid, gid uint32, ts, nr uint64, comm string) []byte {
	buf := make([]byte, 48)
	binary.LittleEndian.PutUint32(buf[0:4], pid)
	binary.LittleEndian.PutUint32(buf[4:8], tid)
	binary.LittleEndian.PutUint32(buf[8:12], uid)
	binary.LittleEndian.PutUint32(buf[12:16], gid)
	binary.LittleEndian.PutUint64(buf[16:24], ts)
	binary.LittleEndian.PutUint64(buf[24:32], nr)
	copy(buf[32:48], comm)
	return buf
}

/*
	TestParseEventBasic verifies that a well-formed 48-byte buffer
	is parsed correctly into a SyscallEvent with all fields matching.
*/
func TestParseEventBasic(t *testing.T) {
	raw := buildSyscallRaw(1234, 1235, 1000, 1000, 9999, 257, "bash")

	e, err := parseEvent(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if e.Kind != events.KindSyscall {
		t.Errorf("expected KindSyscall, got %v", e.Kind)
	}
	if e.PID != 1234 {
		t.Errorf("expected PID 1234, got %d", e.PID)
	}
	if e.TID != 1235 {
		t.Errorf("expected TID 1235, got %d", e.TID)
	}
	if e.UID != 1000 {
		t.Errorf("expected UID 1000, got %d", e.UID)
	}
	if e.GID != 1000 {
		t.Errorf("expected GID 1000, got %d", e.GID)
	}
	if e.Timestamp != 9999 {
		t.Errorf("expected Timestamp 9999, got %d", e.Timestamp)
	}
	if e.SyscallNr != 257 {
		t.Errorf("expected SyscallNr 257, got %d", e.SyscallNr)
	}
	if e.ProcessName() != "bash" {
		t.Errorf("expected comm 'bash', got %q", e.ProcessName())
	}
}

/*
	TestParseEventShortRead verifies that buffers shorter than 48
	bytes are rejected.
*/
func TestParseEventShortRead(t *testing.T) {
	_, err := parseEvent(make([]byte, 47))
	if err == nil {
		t.Fatal("expected error for short buffer, got nil")
	}
}

/*
	TestParseEventNullComm verifies correct handling of a comm field
	filled entirely with NUL bytes (empty process name).
*/
func TestParseEventNullComm(t *testing.T) {
	raw := buildSyscallRaw(1, 1, 0, 0, 0, 0, "")

	e, err := parseEvent(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if e.ProcessName() != "" {
		t.Errorf("expected empty comm, got %q", e.ProcessName())
	}
}

/*
	TestParseEventFullComm verifies a 16-byte comm field with no
	NUL terminator (truncated process name from kernel).
*/
func TestParseEventFullComm(t *testing.T) {
	raw := buildSyscallRaw(1, 1, 0, 0, 0, 0, "0123456789abcdef")

	e, err := parseEvent(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if e.ProcessName() != "0123456789abcdef" {
		t.Errorf("expected full 16-char comm, got %q", e.ProcessName())
	}
}
