package files

import (
	"encoding/binary"
	"testing"

	"github.com/PranavRJoshi/Veil/internal/events"
)

/*
	buildFileRaw constructs a raw byte buffer matching the file_event struct
	layout from file_access.bpf.c.

	components is a slice of path component strings in leaf-first order
	(components[0] = filename, components[1] = parent dir, etc.). Each is
	written into a 64-byte null-padded slot starting at offset 44.
*/
func buildFileRaw(pid, tid, uid, gid uint32, ts uint64, comm string, op uint8, components []string) []byte {
	buf := make([]byte, 812)
	binary.LittleEndian.PutUint32(buf[0:4], pid)
	binary.LittleEndian.PutUint32(buf[4:8], tid)
	binary.LittleEndian.PutUint32(buf[8:12], uid)
	binary.LittleEndian.PutUint32(buf[12:16], gid)
	binary.LittleEndian.PutUint64(buf[16:24], ts)
	copy(buf[24:40], comm)
	buf[40] = op
	/* buf[41:44] = explicit padding, already zero */
	for i, comp := range components {
		if i >= 12 {
			break
		}
		copy(buf[44+i*64:44+(i+1)*64], comp)
	}
	return buf
}

/*
	TestParseFileEventBasic verifies that a well-formed 812-byte buffer is
	parsed correctly and that the path is assembled from components in
	reverse (ancestor-first) order.
*/
func TestParseFileEventBasic(t *testing.T) {
	/* components: leaf="nginx.conf", parent="etc" -> assembled as /etc/nginx.conf */
	raw := buildFileRaw(5678, 5679, 1000, 1000, 12345, "nginx", 0, []string{"nginx.conf", "etc"})

	e, err := parseEvent(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

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
	if e.FileName != "/etc/nginx.conf" {
		t.Errorf("expected file '/etc/nginx.conf', got %q", e.FileName)
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
		{99, "op_99"},
	}

	for _, c := range cases {
		raw := buildFileRaw(1, 1, 0, 0, 0, "test", c.op, []string{"x"})
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
	TestParseFileEventNoComponents verifies that an event with no components
	produces "/" as the filename.
*/
func TestParseFileEventNoComponents(t *testing.T) {
	raw := buildFileRaw(1, 1, 0, 0, 0, "test", 0, nil)
	e, err := parseEvent(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if e.FileName != "/" {
		t.Errorf("expected '/', got %q", e.FileName)
	}
}

/*
	TestParseFileEventShortRead verifies that buffers shorter than 812 bytes
	are rejected.
*/
func TestParseFileEventShortRead(t *testing.T) {
	_, err := parseEvent(make([]byte, 811))
	if err == nil {
		t.Fatal("expected error for short buffer, got nil")
	}
}
