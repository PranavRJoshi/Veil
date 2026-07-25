package syscall

import (
	"strings"
	"testing"
)

func TestTextFormat_RoundTrip(t *testing.T) {
	fields := map[string]interface{}{
		"kind":       "syscall",
		"pid":        uint32(1234),
		"uid":        uint32(0),
		"comm":       "bash",
		"syscall":    "openat",
		"syscall_nr": uint64(257),
	}

	got := textFormat("syscall", fields)

	if !strings.Contains(got, "PID=1234") {
		t.Errorf("missing pid: %q", got)
	}
	if !strings.Contains(got, "UID=0") {
		t.Errorf("missing uid: %q", got)
	}
	if !strings.Contains(got, "bash") {
		t.Errorf("missing comm: %q", got)
	}
	if !strings.Contains(got, "syscall=openat") {
		t.Errorf("missing syscall name: %q", got)
	}
}

func TestTextFormat_WithEnrichment(t *testing.T) {
	fields := map[string]interface{}{
		"kind": "syscall", "pid": uint32(1234), "tid": uint32(1234),
		"uid": uint32(0), "gid": uint32(0), "comm": "bash",
		"syscall": "openat", "syscall_nr": uint64(257),
		"time": "14:32:05.123", "username": "root", "proc_name": "bash",
	}

	got := textFormat("syscall", fields)

	if !strings.HasPrefix(got, "[14:32:05.123] ") {
		t.Errorf("expected time prefix, got %q", got)
	}
	if !strings.Contains(got, "user=root") {
		t.Errorf("expected user=root, got %q", got)
	}
	if !strings.Contains(got, "proc=bash") {
		t.Errorf("expected proc=bash, got %q", got)
	}
}

func TestTextFormat_WithoutEnrichment(t *testing.T) {
	fields := map[string]interface{}{
		"kind": "syscall", "pid": uint32(1234), "tid": uint32(1234),
		"uid": uint32(0), "gid": uint32(0), "comm": "bash",
		"syscall": "openat", "syscall_nr": uint64(257),
	}

	got := textFormat("syscall", fields)

	if strings.Contains(got, "[") {
		t.Errorf("should not have time prefix without enrichment: %q", got)
	}
	if strings.Contains(got, "user=") {
		t.Errorf("should not have user= without enrichment: %q", got)
	}
	if strings.Contains(got, "proc=") {
		t.Errorf("should not have proc= without enrichment: %q", got)
	}
}
