// Package output provides a composable event sink pipeline for Veil modules.
//
// Instead of each module calling fmt.Printf directly, modules push events
// through an EventSink interface. Sinks can be chained (filtering, enrichment)
// or swapped (text vs JSON) without changing module code.
package output

import (
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
)

// EventSink receives structured events from modules. Implementations
// must be safe for concurrent use.
type EventSink interface {
	Emit(module string, fields map[string]interface{}) error
	Close() error
}

// TextFormatFunc converts a module name and fields into a display line
// (without trailing newline).
type TextFormatFunc func(module string, fields map[string]interface{}) string

// TextSink writes formatted text lines to an io.Writer.
type TextSink struct {
	mu       sync.Mutex
	w        io.Writer
	format   TextFormatFunc
	colorize func(module, line string) string // nil: no coloring
}

// NewTextSink creates a sink that writes formatted text to w.
// If format is nil, a generic key=value formatter is used.
func NewTextSink(w io.Writer, format TextFormatFunc) *TextSink {
	if format == nil {
		format = genericTextFormat
	}
	return &TextSink{w: w, format: format}
}

// WithColorize sets a function that tints each formatted line by module, used
// to give each module a distinct color in multi-module output. A nil function
// leaves lines uncolored. Returns the sink for chaining.
func (s *TextSink) WithColorize(fn func(module, line string) string) *TextSink {
	s.colorize = fn
	return s
}

func (s *TextSink) Emit(module string, fields map[string]interface{}) error {
	line := s.format(module, fields)
	if s.colorize != nil {
		line = s.colorize(module, line)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := fmt.Fprintln(s.w, line)
	return err
}

func (s *TextSink) Close() error { return nil }

func genericTextFormat(module string, fields map[string]interface{}) string {
	return fmt.Sprintf("[%s] %v", module, fields)
}

// JSONSink writes one JSON object per line (NDJSON).
type JSONSink struct {
	mu     sync.Mutex
	enc    *json.Encoder
	w      io.Writer
	fields []string // allowlist; nil means all fields plus "module"
}

// NewJSONSink creates a sink that writes JSON-lines to w.
func NewJSONSink(w io.Writer) *JSONSink {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return &JSONSink{enc: enc, w: w}
}

// WithFields restricts output to the given field keys. "module" is included
// only if it is among them. An empty list leaves the sink unrestricted.
func (s *JSONSink) WithFields(fields []string) *JSONSink {
	s.fields = fields
	return s
}

func (s *JSONSink) Emit(module string, fields map[string]interface{}) error {
	var out map[string]interface{}
	if len(s.fields) == 0 {
		out = make(map[string]interface{}, len(fields)+1)
		for k, v := range fields {
			out[k] = v
		}
		out["module"] = module
	} else {
		out = make(map[string]interface{}, len(s.fields))
		for _, k := range s.fields {
			if k == "module" {
				out[k] = module
			} else if v, ok := fields[k]; ok {
				out[k] = v
			}
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	return s.enc.Encode(out)
}

func (s *JSONSink) Close() error { return nil }

// FanOutSink broadcasts every event to multiple downstream sinks.
type FanOutSink struct {
	sinks []EventSink
}

// NewFanOutSink creates a sink that fans out to all provided sinks.
func NewFanOutSink(sinks ...EventSink) *FanOutSink {
	return &FanOutSink{sinks: sinks}
}

func (s *FanOutSink) Emit(module string, fields map[string]interface{}) error {
	var firstErr error
	for _, sink := range s.sinks {
		if err := sink.Emit(module, fields); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (s *FanOutSink) Close() error {
	var firstErr error
	for _, sink := range s.sinks {
		if err := sink.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// FilterFunc returns true if the event should be forwarded downstream.
type FilterFunc func(module string, fields map[string]interface{}) bool

// FilterSink forwards only events that pass the predicate.
type FilterSink struct {
	next   EventSink
	accept FilterFunc
}

// NewFilterSink creates a filtering middleware in front of next.
func NewFilterSink(next EventSink, accept FilterFunc) *FilterSink {
	return &FilterSink{next: next, accept: accept}
}

func (s *FilterSink) Emit(module string, fields map[string]interface{}) error {
	if !s.accept(module, fields) {
		return nil
	}
	return s.next.Emit(module, fields)
}

func (s *FilterSink) Close() error {
	return s.next.Close()
}

// PausableSink wraps a downstream sink with pause/resume capability.
// While paused, Emit calls are silently dropped and counted. This
// enables the interactive control mode where event output is suspended
// while the user modifies filters.
//
// mu is a RWMutex: Emit holds a read lock across the entire call
// (including next.Emit), while Pause and Resume hold the write lock.
// This guarantees that when Pause returns, every in-progress Emit has
// completed and no further events will reach next.Emit.
//
// dropped is accessed with sync/atomic so concurrent read-lock holders
// can increment it without serialising through the write lock.
type PausableSink struct {
	mu      sync.RWMutex
	next    EventSink
	paused  bool
	dropped uint64
}

func NewPausableSink(next EventSink) *PausableSink {
	return &PausableSink{next: next}
}

func (s *PausableSink) Emit(module string, fields map[string]interface{}) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.paused {
		atomic.AddUint64(&s.dropped, 1)
		return nil
	}
	return s.next.Emit(module, fields)
}

func (s *PausableSink) Close() error { return s.next.Close() }

// Pause stops forwarding events. It blocks until every Emit call that
// started before Pause was called has fully completed, so no event can
// appear on the output stream after Pause returns.
func (s *PausableSink) Pause() {
	s.mu.Lock()
	s.paused = true
	atomic.StoreUint64(&s.dropped, 0)
	s.mu.Unlock()
}

// DroppedCount returns the number of events dropped since the last Pause
// without modifying the paused state. Read the count before Resume so the
// banner can be printed before events start flowing again.
func (s *PausableSink) DroppedCount() uint64 {
	return atomic.LoadUint64(&s.dropped)
}

// Resume resumes forwarding and returns the number of events dropped
// while paused.
func (s *PausableSink) Resume() uint64 {
	s.mu.Lock()
	d := atomic.LoadUint64(&s.dropped)
	atomic.StoreUint64(&s.dropped, 0)
	s.paused = false
	s.mu.Unlock()
	return d
}
