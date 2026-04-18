package files

import (
	"encoding/binary"
	"testing"

	"github.com/PranavRJoshi/Veil/internal/events"
)

/*
	Given the information required for the file_event structure passed
	as argument to this function, construct a byte-array that holds
	the information. Note that indexing is crucial here since we're
	not returning a structure but an array of bytes.
*/
func buildFileRaw(pid, tid, uid, gid uint32, ts uint64, comm, file string, op uint8) []byte {

	buf := make([]byte, 297)
	binary.LittleEndian.PutUint32(buf[0:4], pid)
	binary.LittleEndian.PutUint32(buf[4:8], tid)
	binary.LittleEndian.PutUint32(buf[8:12], uid)
	binary.LittleEndian.PutUint32(buf[12:16], gid)
	binary.LittleEndian.PutUint64(buf[16:24], ts)
	copy(buf[24:40], comm)
	copy(buf[40:296], file)
	buf[296] = op

	return buf
}

/*
	TestParseFileEventBasic verifies that a well-formed 297-byte
	buffer is parsed correctly with filename substring.
*/
func TestParseFileEventBasic(t *testing.T) {
	/* Construct a sequence of bytes that will be passed to parseEvent */
	raw := buildFileRaw(5678, 5679, 1000, 1000, 12345, "nginx", "nginx.conf", 0)

	/* initializes Kind to KindFileAccess, along with other fields  */
	e, err := parseEvent(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	/* open, read, or write */
	if e.Kind != events.KindFileAccess {
		t.Errorf("expected KindFileAccess, got %v", e.Kind)
	}
	if e.PID != 5678 {
		t.Errorf("expected PID 5678, got %d", e.PID)
	}
	if e.TID != 5679 {
		t.Errorf("expected TID 5679, got %d", e.TID)
	}
	if e.UID != 1000 {
		t.Errorf("expected UID 1000, got %d", e.UID)
	}
	if e.GID != 1000 {
		t.Errorf("expected GID 1000, got %d", e.GID)
	}
	if e.Timestamp != 12345 {
		t.Errorf("expected Timestamp 12345, got %d", e.Timestamp)
	}
	if e.ProcessName() != "nginx" {
		t.Errorf("expected comm 'nginx', got %q", e.ProcessName())
	}
	if e.FileName != "nginx.conf" {
		t.Errorf("expected file 'nginx.conf', got %q", e.FileName)
	}
	if e.Op != "open" {
		t.Errorf("expected op 'open', got %q", e.Op)
	}
}

/*
	TestParseFileEventOps verifies all three operation codes.
*/
func TestParseFileEventOps(t *testing.T) {
	cases := []struct {
		op       uint8
		expected string
	}{
		{0, "open"},
		{1, "read"},
		{2, "write"},
		{99, "op_99"},		/* check opName function defined in parse.go */
	}

	for _, c := range cases {
		raw := buildFileRaw(1, 1, 0, 0, 0, "test", "x", c.op)
		e, err := parseEvent(raw)
		if err != nil {
			t.Fatalf("unexpected error for op %d: %v", c.op, err)
		}
		if e.Op != c.expected {
			t.Errorf("op %d: expected %q, got %q", c.op, c.expected, e.Op)
		}
	}
}

/*
	TestParseFileEventShortRead verifies that buffers shorter than
	297 bytes are rejected.
*/
func TestParseFileEventShortRead(t *testing.T) {
	_, err := parseEvent(make([]byte, 296))
	if err == nil {
		t.Fatal("expected error for short buffer, got nil")
	}
}
