package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Enrichment helpers
// ---------------------------------------------------------------------------

func TestTimePrefix(t *testing.T) {
	if got := TimePrefix(map[string]interface{}{"time": "14:32:05.123"}); got != "[14:32:05.123] " {
		t.Errorf("TimePrefix = %q, want %q", got, "[14:32:05.123] ")
	}
	if got := TimePrefix(map[string]interface{}{}); got != "" {
		t.Errorf("TimePrefix without time = %q, want empty", got)
	}
}

func TestEnrichSuffix(t *testing.T) {
	got := EnrichSuffix(map[string]interface{}{"username": "root", "proc_name": "bash"})
	if !strings.Contains(got, "user=root") || !strings.Contains(got, "proc=bash") {
		t.Errorf("EnrichSuffix = %q, want user and proc", got)
	}
	if got := EnrichSuffix(map[string]interface{}{}); got != "" {
		t.Errorf("EnrichSuffix without fields = %q, want empty", got)
	}
}

// ---------------------------------------------------------------------------
// DispatchTextFormat: routes by module name, generic fallback otherwise
// ---------------------------------------------------------------------------

/*
	stubFormat is a per-module formatter for the dispatch tests. The real
	module formatters live in their own packages now, which this package
	cannot import, so dispatch is exercised with a stub.
*/
func stubFormat(module string, f map[string]interface{}) string {
	return "STUB:" + module
}

func TestDispatchTextFormat_KnownModule(t *testing.T) {
	dispatch := DispatchTextFormat(map[string]TextFormatFunc{"syscall": stubFormat})

	got := dispatch("syscall", map[string]interface{}{})
	if got != "STUB:syscall" {
		t.Errorf("dispatch to stub formatter = %q, want STUB:syscall", got)
	}
}

func TestDispatchTextFormat_UnknownModule(t *testing.T) {
	dispatch := DispatchTextFormat(map[string]TextFormatFunc{"syscall": stubFormat})

	got := dispatch("unknownmodule", map[string]interface{}{"foo": "bar"})
	if !strings.HasPrefix(got, "[unknownmodule]") {
		t.Errorf("fallback should use generic format: %q", got)
	}
}

func TestDispatchTextFormat_EmptyMap(t *testing.T) {
	dispatch := DispatchTextFormat(nil)

	got := dispatch("syscall", map[string]interface{}{})
	if !strings.HasPrefix(got, "[syscall]") {
		t.Errorf("nil map should fall through to generic: %q", got)
	}
}

// ---------------------------------------------------------------------------
// Full pipeline: fields -> TextSink -> buffer
// ---------------------------------------------------------------------------

func TestTextSink_FullPipeline_Dispatch(t *testing.T) {
	var buf bytes.Buffer
	sink := NewTextSink(&buf, DispatchTextFormat(map[string]TextFormatFunc{"syscall": stubFormat}))

	if err := sink.Emit("syscall", map[string]interface{}{"pid": uint32(42)}); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if got := strings.TrimSpace(buf.String()); got != "STUB:syscall" {
		t.Errorf("pipeline output = %q, want STUB:syscall", got)
	}
}

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

	for i, line := range lines {
		var obj map[string]interface{}
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			t.Errorf("line %d invalid JSON: %v", i, err)
			break
		}
	}
}
