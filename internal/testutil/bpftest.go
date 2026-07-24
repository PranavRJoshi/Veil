// Package testutil provides shared helpers for Veil integration tests.
//
// Integration tests load real BPF programs into the kernel, so they need
// root and a Linux host. Every integration test file carries the
// "integration" build tag and calls RequireBPF first.
//
// This package itself is untagged: a package whose files are all excluded
// by a build constraint breaks "go build ./...". Nothing here imports
// cilium/ebpf, so it compiles on the Mac host too.
package testutil

import (
	"fmt"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/PranavRJoshi/Veil/internal/output"
	"github.com/PranavRJoshi/Veil/internal/runner"
)

/*
	DefaultTimeout is how long to wait for an expected event.
	NegativeTimeout is the window for asserting an event does NOT appear;
	it is short because the triggering workload has already completed by
	the time a negative check runs.
*/
const (
	DefaultTimeout  = 5 * time.Second
	NegativeTimeout = 500 * time.Millisecond
)

/*
	RequireBPF skips the test unless BPF programs can actually be loaded.
	Call it as the first statement of every integration test.
*/
func RequireBPF(t *testing.T) {
	t.Helper()

	if runtime.GOOS != "linux" {
		t.Skipf("integration tests require Linux (running on %s)", runtime.GOOS)
	}
	if os.Geteuid() != 0 {
		t.Skip("integration tests require root (try: make test-integration)")
	}
}

/*
	Captured is a single event recorded by CaptureSink.
*/
type Captured struct {
	Module string
	Fields map[string]interface{}
}

/*
	Field returns a field rendered with %v, matching how the text and count
	sinks stringify values, plus whether it was present.
*/
func (c Captured) Field(name string) (string, bool) {
	v, ok := c.Fields[name]
	if !ok {
		return "", false
	}
	return fmt.Sprintf("%v", v), true
}

/*
	CaptureSink is an output.EventSink that records events instead of
	formatting them. Safe for concurrent use: the module emits from its Run
	goroutine while the test goroutine waits and inspects.
*/
type CaptureSink struct {
	mu     sync.Mutex
	events []Captured
	notify chan struct{}
}

var _ output.EventSink = (*CaptureSink)(nil)

func NewCaptureSink() *CaptureSink {
	return &CaptureSink{notify: make(chan struct{}, 1)}
}

func (s *CaptureSink) Emit(module string, fields map[string]interface{}) error {
	/* Copy so a captured event never aliases state the module may reuse. */
	cp := make(map[string]interface{}, len(fields))
	for k, v := range fields {
		cp[k] = v
	}

	s.mu.Lock()
	s.events = append(s.events, Captured{Module: module, Fields: cp})
	s.mu.Unlock()

	/*
		Buffered to depth one so Emit never blocks. If a notification is
		already pending the waiter has not consumed it yet and will rescan
		anyway.
	*/
	select {
	case s.notify <- struct{}{}:
	default:
	}

	return nil
}

func (s *CaptureSink) Close() error { return nil }

func (s *CaptureSink) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.events)
}

/*
	Snapshot returns a copy of every event captured so far, for assertions
	over the whole stream.
*/
func (s *CaptureSink) Snapshot() []Captured {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Captured, len(s.events))
	copy(out, s.events)
	return out
}

/*
	WaitFor blocks until an event satisfying pred is captured, failing the
	test if none arrives within timeout.
*/
func (s *CaptureSink) WaitFor(t *testing.T, timeout time.Duration, pred func(Captured) bool) Captured {
	t.Helper()

	c, ok := s.TryWaitFor(timeout, pred)
	if !ok {
		t.Fatalf("timed out after %s waiting for a matching event (%d events captured)",
			timeout, s.Len())
	}
	return c
}

/*
	TryWaitFor is WaitFor without the fatal: it reports whether a matching
	event arrived before the timeout. Use it for negative assertions.
*/
func (s *CaptureSink) TryWaitFor(timeout time.Duration, pred func(Captured) bool) (Captured, bool) {
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()

	/* High-water mark, so the stream is not re-scanned on every wake-up. */
	scanned := 0
	for {
		s.mu.Lock()
		for scanned < len(s.events) {
			c := s.events[scanned]
			scanned++
			if pred(c) {
				s.mu.Unlock()
				return c, true
			}
		}
		s.mu.Unlock()

		select {
		case <-s.notify:
		case <-deadline.C:
			return Captured{}, false
		}
	}
}

/*
	StartModule loads a module, starts its Run loop, and registers cleanup.
	It returns a stop function for tests that need to shut down early;
	calling it twice is safe.

	Shutdown order matters: Close first, then close(done). Close closes the
	ringbuf reader, which makes poll return and close the Events channel,
	which ends Run. Closing done first would stop Run from draining while
	poll could still be parked on a send into a full Events buffer, and
	closing the reader does not wake a goroutine blocked on a channel send.
*/
func StartModule(t *testing.T, mod runner.Module) func() {
	t.Helper()

	if err := mod.Load(); err != nil {
		t.Fatalf("load module %s: %v", mod.Name(), err)
	}

	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		mod.Run(done)
	}()

	var once sync.Once
	stop := func() {
		once.Do(func() {
			if err := mod.Close(); err != nil {
				t.Errorf("close module %s: %v", mod.Name(), err)
			}
			close(done)
			wg.Wait()
		})
	}

	t.Cleanup(stop)
	return stop
}
