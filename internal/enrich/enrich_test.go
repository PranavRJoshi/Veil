package enrich

import (
	"testing"
)

// ---------------------------------------------------------------------------
// captureSink: test double that records Emit calls
// ---------------------------------------------------------------------------

type captureSink struct {
	events []capturedEvent
}

type capturedEvent struct {
	module string
	fields map[string]interface{}
}

func (s *captureSink) Emit(module string, fields map[string]interface{}) error {
	// Deep-copy fields to avoid mutation issues.
	cp := make(map[string]interface{}, len(fields))
	for k, v := range fields {
		cp[k] = v
	}
	s.events = append(s.events, capturedEvent{module, cp})
	return nil
}

func (s *captureSink) Close() error { return nil }

// ---------------------------------------------------------------------------
// extractUint32 / extractUint64 helpers
// ---------------------------------------------------------------------------

func TestExtractUint32(t *testing.T) {
	tests := []struct {
		name string
		val  interface{}
		want uint32
		ok   bool
	}{
		{"uint32", uint32(42), 42, true},
		{"int", int(100), 100, true},
		{"int64", int64(200), 200, true},
		{"float64", float64(300), 300, true},
		{"string", "nope", 0, false},
		{"nil", nil, 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fields := map[string]interface{}{"pid": tt.val}
			got, ok := extractUint32(fields, "pid")
			if ok != tt.ok || got != tt.want {
				t.Errorf("extractUint32(%v) = (%d, %v), want (%d, %v)",
					tt.val, got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestExtractUint32_Missing(t *testing.T) {
	fields := map[string]interface{}{"uid": uint32(1)}
	_, ok := extractUint32(fields, "pid")
	if ok {
		t.Error("expected false for missing key")
	}
}

func TestExtractUint64(t *testing.T) {
	fields := map[string]interface{}{"timestamp": uint64(123456789)}
	got, ok := extractUint64(fields, "timestamp")
	if !ok || got != 123456789 {
		t.Errorf("got (%d, %v), want (123456789, true)", got, ok)
	}
}

// ---------------------------------------------------------------------------
// EnrichSink
// ---------------------------------------------------------------------------

func TestEnrichSink_AppliesEnrichers(t *testing.T) {
	capture := &captureSink{}
	addFoo := func(module string, fields map[string]interface{}) {
		fields["foo"] = "bar"
	}
	addBaz := func(module string, fields map[string]interface{}) {
		fields["baz"] = 42
	}
	sink := NewEnrichSink(capture, addFoo, addBaz)

	fields := map[string]interface{}{"pid": uint32(1)}
	if err := sink.Emit("test", fields); err != nil {
		t.Fatalf("Emit: %v", err)
	}

	if len(capture.events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(capture.events))
	}
	evt := capture.events[0]
	if evt.fields["foo"] != "bar" {
		t.Errorf("foo = %v, want bar", evt.fields["foo"])
	}
	if evt.fields["baz"] != 42 {
		t.Errorf("baz = %v, want 42", evt.fields["baz"])
	}
}

// ---------------------------------------------------------------------------
// Chain
// ---------------------------------------------------------------------------

func TestChain_API(t *testing.T) {
	capture := &captureSink{}
	addTag := func() EnricherOption {
		return func() Enricher {
			return func(module string, fields map[string]interface{}) {
				fields["tagged"] = true
			}
		}
	}
	sink := Chain(capture, addTag())
	if err := sink.Emit("test", map[string]interface{}{}); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if len(capture.events) != 1 {
		t.Fatalf("expected 1 event")
	}
	if capture.events[0].fields["tagged"] != true {
		t.Error("enricher not applied via Chain")
	}
}

// ---------------------------------------------------------------------------
// WithUserName: unit test with real /etc/passwd
// ---------------------------------------------------------------------------

func TestWithUserName_ResolvesRoot(t *testing.T) {
	capture := &captureSink{}
	enricher := WithUserName()()
	sink := NewEnrichSink(capture, enricher)

	fields := map[string]interface{}{"uid": uint32(0)}
	if err := sink.Emit("test", fields); err != nil {
		t.Fatalf("Emit: %v", err)
	}

	if len(capture.events) != 1 {
		t.Fatalf("expected 1 event")
	}
	username := capture.events[0].fields["username"]
	if username != "root" {
		t.Errorf("username for uid 0 = %v, want root", username)
	}
}

func TestWithUserName_UnknownUID(t *testing.T) {
	capture := &captureSink{}
	enricher := WithUserName()()
	sink := NewEnrichSink(capture, enricher)

	fields := map[string]interface{}{"uid": uint32(99999)}
	if err := sink.Emit("test", fields); err != nil {
		t.Fatalf("Emit: %v", err)
	}

	if _, hasUsername := capture.events[0].fields["username"]; hasUsername {
		t.Error("should not have added username for unknown UID")
	}
}

// ---------------------------------------------------------------------------
// WithProcName: can test against PID 1 (init/systemd) if running
// ---------------------------------------------------------------------------

func TestWithProcName_PID1(t *testing.T) {
	// PID 1 should always exist on a running Linux system.
	capture := &captureSink{}
	enricher := WithProcName()()
	sink := NewEnrichSink(capture, enricher)

	fields := map[string]interface{}{"pid": uint32(1)}
	if err := sink.Emit("test", fields); err != nil {
		t.Fatalf("Emit: %v", err)
	}

	procName, ok := capture.events[0].fields["proc_name"]
	if !ok {
		t.Skip("could not resolve PID 1; may not have /proc access")
	}
	if procName == "" {
		t.Error("proc_name is empty for PID 1")
	}
}

func TestWithProcName_PIDZeroSkipped(t *testing.T) {
	capture := &captureSink{}
	enricher := WithProcName()()
	sink := NewEnrichSink(capture, enricher)

	fields := map[string]interface{}{"pid": uint32(0)}
	_ = sink.Emit("test", fields)

	if _, has := capture.events[0].fields["proc_name"]; has {
		t.Error("should skip enrichment for pid=0")
	}
}

// ---------------------------------------------------------------------------
// WithTimestamp
// ---------------------------------------------------------------------------

func TestWithTimestamp_AddsTimeField(t *testing.T) {
	capture := &captureSink{}
	enricher := WithTimestamp()()
	sink := NewEnrichSink(capture, enricher)

	// Simulate a recent kernel timestamp (say, 1 second ago in boot-relative ns).
	fields := map[string]interface{}{"timestamp": uint64(1_000_000_000)}
	_ = sink.Emit("test", fields)

	timeVal, ok := capture.events[0].fields["time"]
	if !ok {
		t.Skip("timestamp enrichment failed; may not have /proc/uptime")
	}
	timeStr, ok := timeVal.(string)
	if !ok {
		t.Fatalf("time field is not a string: %T", timeVal)
	}
	if timeStr == "" {
		t.Error("time field is empty")
	}
	/* Verify format matches "HH:MM:SS.mmm" (e.g. "14:32:05.123") */
	if len(timeStr) != 12 {
		t.Errorf("time format length = %d, want 12 (HH:MM:SS.mmm), got %q", len(timeStr), timeStr)
	}
	if timeStr[2] != ':' || timeStr[5] != ':' || timeStr[8] != '.' {
		t.Errorf("time format does not match HH:MM:SS.mmm: got %q", timeStr)
	}
}

func TestWithTimestamp_ZeroSkipped(t *testing.T) {
	capture := &captureSink{}
	enricher := WithTimestamp()()
	sink := NewEnrichSink(capture, enricher)

	fields := map[string]interface{}{"timestamp": uint64(0)}
	_ = sink.Emit("test", fields)

	if _, has := capture.events[0].fields["time"]; has {
		t.Error("should skip enrichment for timestamp=0")
	}
}
