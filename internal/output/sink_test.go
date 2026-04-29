package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func sampleFields() map[string]interface{} {
	return map[string]interface{}{
		"pid":  uint32(1234),
		"comm": "curl",
	}
}

// ---------------------------------------------------------------------------
// TextSink
// ---------------------------------------------------------------------------

func TestTextSink_GenericFormat(t *testing.T) {
	var buf bytes.Buffer
	sink := NewTextSink(&buf, nil)
	if err := sink.Emit("network", sampleFields()); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	line := strings.TrimSpace(buf.String())
	if !strings.HasPrefix(line, "[network]") {
		t.Errorf("expected [network] prefix, got %q", line)
	}
}

func TestTextSink_CustomFormat(t *testing.T) {
	var buf bytes.Buffer
	custom := func(mod string, f map[string]interface{}) string {
		return mod + ":ok"
	}
	sink := NewTextSink(&buf, custom)
	if err := sink.Emit("syscall", sampleFields()); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if got := strings.TrimSpace(buf.String()); got != "syscall:ok" {
		t.Errorf("expected %q, got %q", "syscall:ok", got)
	}
}

// ---------------------------------------------------------------------------
// JSONSink
// ---------------------------------------------------------------------------

func TestJSONSink_OutputFormat(t *testing.T) {
	var buf bytes.Buffer
	sink := NewJSONSink(&buf)
	if err := sink.Emit("files", sampleFields()); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	var obj map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &obj); err != nil {
		t.Fatalf("invalid JSON: %v\nraw: %s", err, buf.String())
	}
	if obj["module"] != "files" {
		t.Errorf("module field: got %v, want %q", obj["module"], "files")
	}
	if obj["comm"] != "curl" {
		t.Errorf("comm field: got %v, want %q", obj["comm"], "curl")
	}
}

func TestJSONSink_DoesNotMutateInput(t *testing.T) {
	var buf bytes.Buffer
	sink := NewJSONSink(&buf)
	fields := sampleFields()
	_ = sink.Emit("test", fields)
	if _, ok := fields["module"]; ok {
		t.Error("Emit mutated the caller's map by injecting 'module' key")
	}
}

// ---------------------------------------------------------------------------
// FanOutSink
// ---------------------------------------------------------------------------

func TestFanOutSink_BroadcastsToAll(t *testing.T) {
	var buf1, buf2 bytes.Buffer
	s1 := NewTextSink(&buf1, nil)
	s2 := NewJSONSink(&buf2)
	fan := NewFanOutSink(s1, s2)
	if err := fan.Emit("net", sampleFields()); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if buf1.Len() == 0 {
		t.Error("text sink received nothing")
	}
	if buf2.Len() == 0 {
		t.Error("json sink received nothing")
	}
}

// ---------------------------------------------------------------------------
// FilterSink
// ---------------------------------------------------------------------------

func TestFilterSink_Drops(t *testing.T) {
	var buf bytes.Buffer
	inner := NewTextSink(&buf, nil)
	// Only pass "syscall" events
	filtered := NewFilterSink(inner, func(mod string, _ map[string]interface{}) bool {
		return mod == "syscall"
	})
	_ = filtered.Emit("network", sampleFields()) // should be dropped
	_ = filtered.Emit("syscall", sampleFields())  // should pass
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 1 {
		t.Errorf("expected 1 line, got %d: %v", len(lines), lines)
	}
	if !strings.HasPrefix(lines[0], "[syscall]") {
		t.Errorf("wrong line passed through: %q", lines[0])
	}
}

// ---------------------------------------------------------------------------
// PausableSink
// ---------------------------------------------------------------------------
 
func TestPausableSink_ForwardsByDefault(t *testing.T) {
	var buf bytes.Buffer
	inner := NewTextSink(&buf, nil)
	p := NewPausableSink(inner)
 
	_ = p.Emit("test", sampleFields())
	if buf.Len() == 0 {
		t.Error("expected output when not paused")
	}
}

func TestPausableSink_DropsWhenPaused(t *testing.T) {
	var buf bytes.Buffer
	inner := NewTextSink(&buf, nil)
	p := NewPausableSink(inner)
 
	p.Pause()
	_ = p.Emit("test", sampleFields())
	_ = p.Emit("test", sampleFields())
	_ = p.Emit("test", sampleFields())
 
	if buf.Len() != 0 {
		t.Error("expected no output when paused")
	}
}

func TestPausableSink_ResumeReturnsDropCount(t *testing.T) {
	var buf bytes.Buffer
	inner := NewTextSink(&buf, nil)
	p := NewPausableSink(inner)
 
	p.Pause()
	_ = p.Emit("a", sampleFields())
	_ = p.Emit("b", sampleFields())
	_ = p.Emit("c", sampleFields())
 
	dropped := p.Resume()
	if dropped != 3 {
		t.Errorf("expected 3 dropped, got %d", dropped)
	}
 
	// After resume, events should flow again
	_ = p.Emit("d", sampleFields())
	if buf.Len() == 0 {
		t.Error("expected output after resume")
	}
}

func TestPausableSink_ResumeResetsCounter(t *testing.T) {
	var buf bytes.Buffer
	inner := NewTextSink(&buf, nil)
	p := NewPausableSink(inner)
 
	p.Pause()
	_ = p.Emit("a", sampleFields())
	p.Resume()
 
	// Second pause/resume cycle
	p.Pause()
	dropped := p.Resume()
	if dropped != 0 {
		t.Errorf("expected 0 dropped on fresh pause, got %d", dropped)
	}
}

func TestPausableSink_ConcurrentPauseResume(t *testing.T) {
	var buf bytes.Buffer
	inner := NewTextSink(&buf, nil)
	p := NewPausableSink(inner)
 
	done := make(chan struct{})
 
	// Writer goroutine: emit continuously
	go func() {
		defer func() { done <- struct{}{} }()
		for i := 0; i < 500; i++ {
			p.Emit("test", map[string]interface{}{"i": i})
		}
	}()
 
	// Controller goroutine: pause and resume rapidly
	go func() {
		defer func() { done <- struct{}{} }()
		for i := 0; i < 50; i++ {
			p.Pause()
			p.Resume()
		}
	}()
 
	<-done
	<-done
	// If there's a race condition, -race will catch it.
	// We just verify no panic occurred.
}
