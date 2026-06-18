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

func TestSchedulerTextFormat_RoundTrip(t *testing.T) {
	fields := map[string]interface{}{
		"cpu":        uint32(2),
		"prev_comm":  "nginx",
		"prev_pid":   uint32(1001),
		"prev_prio":  uint32(120),
		"next_comm":  "kworker",
		"next_pid":   uint32(50),
		"next_prio":  uint32(100),
		"prev_state": "TASK_RUNNING",
	}

	got := SchedulerTextFormat("scheduler", fields)

	checks := []struct {
		label  string
		substr string
	}{
		{"cpu", "CPU=2"},
		{"prev_comm", "nginx"},
		{"prev_pid", "PID=1001"},
		{"prev_prio", "prio=120"},
		{"next_comm", "kworker"},
		{"next_pid", "PID=50"},
		{"next_prio", "prio=100"},
		{"prev_state", "TASK_RUNNING"},
	}

	for _, c := range checks {
		if !strings.Contains(got, c.substr) {
			t.Errorf("missing %s (%q) in output: %q", c.label, c.substr, got)
		}
	}
}

func TestMemoryTextFormat_RoundTrip(t *testing.T) {
	fields := map[string]interface{}{
		"comm":     "python3",
		"pid":      uint32(3456),
		"tid":      uint32(3456),
		"uid":      uint32(1000),
		"evt_type": "minor",
		"address":  "0x7f8b3c000000",
	}

	got := MemoryTextFormat("memory", fields)

	checks := []struct {
		label  string
		substr string
	}{
		{"comm", "python3"},
		{"pid", "PID=3456"},
		{"tid", "TID=3456"},
		{"uid", "UID=1000"},
		{"evt_type", "fault=minor"},
		{"address", "addr=0x7f8b3c000000"},
	}

	for _, c := range checks {
		if !strings.Contains(got, c.substr) {
			t.Errorf("missing %s (%q) in output: %q", c.label, c.substr, got)
		}
	}
}

// ---------------------------------------------------------------------------
// Enriched field formatting: verify time, username, proc_name in output
// ---------------------------------------------------------------------------

func TestSyscallTextFormat_WithEnrichment(t *testing.T) {
	fields := map[string]interface{}{
		"kind": "syscall", "pid": uint32(1234), "tid": uint32(1234),
		"uid": uint32(0), "gid": uint32(0), "comm": "bash",
		"syscall": "openat", "syscall_nr": uint64(257),
		"time": "14:32:05.123", "username": "root", "proc_name": "bash",
	}

	got := SyscallTextFormat("syscall", fields)

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

func TestSyscallTextFormat_WithoutEnrichment(t *testing.T) {
	fields := map[string]interface{}{
		"kind": "syscall", "pid": uint32(1234), "tid": uint32(1234),
		"uid": uint32(0), "gid": uint32(0), "comm": "bash",
		"syscall": "openat", "syscall_nr": uint64(257),
	}

	got := SyscallTextFormat("syscall", fields)

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

func TestFilesTextFormat_WithEnrichment(t *testing.T) {
	fields := map[string]interface{}{
		"kind": "file access", "pid": uint32(5678), "uid": uint32(1000),
		"comm": "nginx", "op": "read", "filename": "nginx.conf",
		"time": "10:00:00.000", "username": "www-data",
	}

	got := FilesTextFormat("files", fields)

	if !strings.HasPrefix(got, "[10:00:00.000] ") {
		t.Errorf("expected time prefix, got %q", got)
	}
	if !strings.Contains(got, "user=www-data") {
		t.Errorf("expected user=www-data, got %q", got)
	}
}

func TestNetworkTextFormat_WithEnrichment(t *testing.T) {
	fields := map[string]interface{}{
		"kind": "network", "pid": uint32(100), "uid": uint32(0),
		"comm": "curl", "evt_type": "CONNECT",
		"saddr": "127.0.0.1", "sport": uint16(54268),
		"daddr": "93.184.216.34", "dport": uint16(80),
		"oldstate": "CLOSE", "newstate": "SYN_SENT",
		"time": "09:15:30.456", "proc_name": "curl",
	}

	got := NetworkTextFormat("network", fields)

	if !strings.HasPrefix(got, "[09:15:30.456] ") {
		t.Errorf("expected time prefix, got %q", got)
	}
	if !strings.Contains(got, "proc=curl") {
		t.Errorf("expected proc=curl, got %q", got)
	}
}

func TestSchedulerTextFormat_WithEnrichment(t *testing.T) {
	fields := map[string]interface{}{
		"cpu":        uint32(0),
		"prev_comm":  "bash",
		"prev_pid":   uint32(200),
		"prev_prio":  uint32(120),
		"next_comm":  "cat",
		"next_pid":   uint32(201),
		"next_prio":  uint32(120),
		"prev_state": "TASK_INTERRUPTIBLE",
		"time":       "12:00:00.000",
		"username":   "root",
		"proc_name":  "bash",
	}

	got := SchedulerTextFormat("scheduler", fields)

	if !strings.HasPrefix(got, "[12:00:00.000] ") {
		t.Errorf("expected time prefix, got %q", got)
	}
	if !strings.Contains(got, "user=root") {
		t.Errorf("expected user=root in output: %q", got)
	}
	if !strings.Contains(got, "proc=bash") {
		t.Errorf("expected proc=bash in output: %q", got)
	}
}

func TestSchedulerTextFormat_WithoutEnrichment(t *testing.T) {
	fields := map[string]interface{}{
		"cpu":        uint32(1),
		"prev_comm":  "sleep",
		"prev_pid":   uint32(999),
		"prev_prio":  uint32(120),
		"next_comm":  "swapper",
		"next_pid":   uint32(0),
		"next_prio":  uint32(120),
		"prev_state": "TASK_DEAD",
	}

	got := SchedulerTextFormat("scheduler", fields)

	if strings.Contains(got, "user=") {
		t.Errorf("should not have user= without enrichment: %q", got)
	}
	if strings.Contains(got, "proc=") {
		t.Errorf("should not have proc= without enrichment: %q", got)
	}
}

func TestMemoryTextFormat_WithEnrichment(t *testing.T) {
	fields := map[string]interface{}{
		"comm":      "node",
		"pid":       uint32(4000),
		"tid":       uint32(4000),
		"uid":       uint32(1000),
		"evt_type":  "minor",
		"address":   "0x55a000100000",
		"time":      "08:30:15.789",
		"username":  "deploy",
		"proc_name": "node",
	}

	got := MemoryTextFormat("memory", fields)

	if !strings.HasPrefix(got, "[08:30:15.789] ") {
		t.Errorf("expected time prefix, got %q", got)
	}
	if !strings.Contains(got, "user=deploy") {
		t.Errorf("expected user=deploy in output: %q", got)
	}
	if !strings.Contains(got, "proc=node") {
		t.Errorf("expected proc=node in output: %q", got)
	}
}

func TestMemoryTextFormat_WithoutEnrichment(t *testing.T) {
	fields := map[string]interface{}{
		"comm":     "stress",
		"pid":      uint32(7777),
		"tid":      uint32(7777),
		"uid":      uint32(0),
		"evt_type": "minor",
		"address":  "0x1000",
	}

	got := MemoryTextFormat("memory", fields)

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

	got := dispatch("unknownmodule", fields)
	if !strings.Contains(got, "[unknownmodule]") {
		t.Errorf("fallback should use generic format: %q", got)
	}
}

func TestDispatchTextFormat_Scheduler(t *testing.T) {
	dispatch := DispatchTextFormat()
	fields := map[string]interface{}{
		"cpu":        uint32(0),
		"prev_comm":  "a",
		"prev_pid":   uint32(1),
		"prev_prio":  uint32(120),
		"next_comm":  "b",
		"next_pid":   uint32(2),
		"next_prio":  uint32(120),
		"prev_state": "S",
	}

	got := dispatch("scheduler", fields)

	/*
		If dispatch falls through to the generic formatter, the output
		starts with "[scheduler]". The scheduler-specific formatter does
		not include that prefix, so its absence confirms correct routing.
	*/
	if strings.HasPrefix(got, "[scheduler]") {
		t.Errorf("dispatch used generic format instead of scheduler formatter: %q", got)
	}
	if !strings.Contains(got, "CPU=0") {
		t.Errorf("scheduler dispatch missing CPU field: %q", got)
	}
}

func TestDispatchTextFormat_Memory(t *testing.T) {
	dispatch := DispatchTextFormat()
	fields := map[string]interface{}{
		"comm":     "test",
		"pid":      uint32(1),
		"tid":      uint32(1),
		"uid":      uint32(0),
		"evt_type": "minor",
		"address":  "0x1000",
	}

	got := dispatch("memory", fields)

	if strings.HasPrefix(got, "[memory]") {
		t.Errorf("dispatch used generic format instead of memory formatter: %q", got)
	}
	if !strings.Contains(got, "fault=minor") {
		t.Errorf("memory dispatch missing fault field: %q", got)
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
// Full pipeline: scheduler and memory events through TextSink
// ---------------------------------------------------------------------------

func TestTextSink_FullPipeline_Scheduler(t *testing.T) {
	var buf strings.Builder
	sink := NewTextSink(&buf, DispatchTextFormat())

	fields := map[string]interface{}{
		"cpu":        uint32(3),
		"prev_comm":  "httpd",
		"prev_pid":   uint32(500),
		"prev_prio":  uint32(120),
		"next_comm":  "idle",
		"next_pid":   uint32(0),
		"next_prio":  uint32(120),
		"prev_state": "TASK_INTERRUPTIBLE",
	}

	if err := sink.Emit("scheduler", fields); err != nil {
		t.Fatalf("Emit: %v", err)
	}

	line := buf.String()
	if !strings.Contains(line, "CPU=3") {
		t.Errorf("pipeline output missing CPU: %q", line)
	}
	if !strings.Contains(line, "httpd") {
		t.Errorf("pipeline output missing prev_comm: %q", line)
	}
}

func TestTextSink_FullPipeline_Memory(t *testing.T) {
	var buf strings.Builder
	sink := NewTextSink(&buf, DispatchTextFormat())

	fields := map[string]interface{}{
		"comm":     "redis",
		"pid":      uint32(600),
		"tid":      uint32(600),
		"uid":      uint32(999),
		"evt_type": "major",
		"address":  "0xdead0000",
	}

	if err := sink.Emit("memory", fields); err != nil {
		t.Fatalf("Emit: %v", err)
	}

	line := buf.String()
	if !strings.Contains(line, "fault=major") {
		t.Errorf("pipeline output missing fault type: %q", line)
	}
	if !strings.Contains(line, "addr=0xdead0000") {
		t.Errorf("pipeline output missing address: %q", line)
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

func TestMemoryTextFormat_MajorFault(t *testing.T) {
	fields := map[string]interface{}{
		"comm":     "gcc",
		"pid":      uint32(8000),
		"tid":      uint32(8001),
		"uid":      uint32(0),
		"evt_type": "major",
		"address":  "0xffffa00012340000",
	}

	got := MemoryTextFormat("memory", fields)

	if !strings.Contains(got, "fault=major") {
		t.Errorf("expected fault=major in output: %q", got)
	}
}
