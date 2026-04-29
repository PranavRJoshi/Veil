package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Round-trip: known fields -> text formatter -> verify output string
// ---------------------------------------------------------------------------

func TestSyscallTextFormat_RoundTrip(t *testing.T) {
	fields := map[string]interface{}{
		"kind":       "syscall",
		"pid":        uint32(1234),
		"uid":        uint32(0),
		"comm":       "bash",
		"syscall":    "openat",
		"syscall_nr": uint64(257),
	}

	got := SyscallTextFormat("syscall", fields)

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

func TestFilesTextFormat_RoundTrip(t *testing.T) {
	fields := map[string]interface{}{
		"kind":     "file access",
		"pid":      uint32(5678),
		"uid":      uint32(1000),
		"comm":     "nginx",
		"op":       "read",
		"filename": "nginx.conf",
	}

	got := FilesTextFormat("files", fields)

	if !strings.Contains(got, "PID=5678") {
		t.Errorf("missing pid: %q", got)
	}
	if !strings.Contains(got, "op=read") {
		t.Errorf("missing op: %q", got)
	}
	if !strings.Contains(got, "filename=nginx.conf") {
		t.Errorf("missing filename: %q", got)
	}
}

func TestNetworkTextFormat_RoundTrip(t *testing.T) {
	fields := map[string]interface{}{
		"kind":     "network",
		"pid":      uint32(1234),
		"uid":      uint32(0),
		"comm":     "curl",
		"evt_type": "CONNECT",
		"saddr":    "127.0.0.1",
		"sport":    uint16(54268),
		"daddr":    "93.184.216.34",
		"dport":    uint16(80),
		"oldstate": "CLOSE",
		"newstate": "SYN_SENT",
	}

	got := NetworkTextFormat("network", fields)

	if !strings.Contains(got, "CONNECT") {
		t.Errorf("missing evt_type: %q", got)
	}
	if !strings.Contains(got, "127.0.0.1") {
		t.Errorf("missing saddr: %q", got)
	}
	if !strings.Contains(got, "93.184.216.34") {
		t.Errorf("missing daddr: %q", got)
	}
	if !strings.Contains(got, "[CLOSE->SYN_SENT]") {
		t.Errorf("missing state transition with parens: %q", got)
	}
}

// ---------------------------------------------------------------------------
// DispatchTextFormat: dispatches to correct module formatter
// ---------------------------------------------------------------------------

func TestDispatchTextFormat_KnownModule(t *testing.T) {
	dispatch := DispatchTextFormat()
	fields := map[string]interface{}{
		"kind": "syscall", "pid": uint32(1), "uid": uint32(0),
		"comm": "x", "syscall": "read",
	}

	got := dispatch("syscall", fields)
	if !strings.Contains(got, "syscall") {
		t.Errorf("dispatch to syscall formatter failed: %q", got)
	}
}

func TestDispatchTextFormat_UnknownModule(t *testing.T) {
	dispatch := DispatchTextFormat()
	fields := map[string]interface{}{"foo": "bar"}

	got := dispatch("scheduler", fields)
	if !strings.Contains(got, "[scheduler]") {
		t.Errorf("fallback should use generic format: %q", got)
	}
}

// ---------------------------------------------------------------------------
// Full pipeline: fields -> TextSink -> buffer -> verify
// ---------------------------------------------------------------------------

func TestTextSink_FullPipeline_Syscall(t *testing.T) {
	var buf bytes.Buffer
	sink := NewTextSink(&buf, DispatchTextFormat())

	fields := map[string]interface{}{
		"kind": "syscall", "pid": uint32(42), "uid": uint32(0),
		"comm": "ls", "syscall": "stat",
	}

	if err := sink.Emit("syscall", fields); err != nil {
		t.Fatalf("Emit: %v", err)
	}

	line := buf.String()
	if !strings.Contains(line, "PID=42") {
		t.Errorf("full pipeline output missing pid: %q", line)
	}
	if !strings.Contains(line, "syscall=stat") {
		t.Errorf("full pipeline output missing syscall: %q", line)
	}
}

// ---------------------------------------------------------------------------
// Full pipeline: fields -> JSONSink -> buffer -> verify JSON structure
// ---------------------------------------------------------------------------

func TestJSONSink_FullPipeline(t *testing.T) {
	var buf bytes.Buffer
	sink := NewJSONSink(&buf)

	fields := map[string]interface{}{
		"kind": "network", "pid": uint32(100),
		"saddr": "10.0.0.1", "dport": uint16(443),
	}

	if err := sink.Emit("network", fields); err != nil {
		t.Fatalf("Emit: %v", err)
	}

	var obj map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &obj); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if obj["module"] != "network" {
		t.Errorf("module = %v, want 'network'", obj["module"])
	}
	if obj["saddr"] != "10.0.0.1" {
		t.Errorf("saddr = %v, want '10.0.0.1'", obj["saddr"])
	}
}

// ---------------------------------------------------------------------------
// Concurrent Emit safety
// ---------------------------------------------------------------------------

func TestTextSink_ConcurrentEmit(t *testing.T) {
	var buf bytes.Buffer
	sink := NewTextSink(&buf, nil)

	done := make(chan struct{})
	emit := func(module string) {
		defer func() { done <- struct{}{} }()
		for i := 0; i < 100; i++ {
			sink.Emit(module, map[string]interface{}{"i": i})
		}
	}

	go emit("a")
	go emit("b")
	<-done
	<-done

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 200 {
		t.Errorf("expected 200 lines from concurrent emit, got %d", len(lines))
	}
}

func TestJSONSink_ConcurrentEmit(t *testing.T) {
	var buf bytes.Buffer
	sink := NewJSONSink(&buf)

	done := make(chan struct{})
	emit := func(module string) {
		defer func() { done <- struct{}{} }()
		for i := 0; i < 100; i++ {
			sink.Emit(module, map[string]interface{}{"i": i})
		}
	}

	go emit("x")
	go emit("y")
	<-done
	<-done

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 200 {
		t.Errorf("expected 200 JSON lines from concurrent emit, got %d", len(lines))
	}

	/* Verify each line is valid JSON */
	for i, line := range lines {
		var obj map[string]interface{}
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			t.Errorf("line %d invalid JSON: %v", i, err)
			break
		}
	}
}
