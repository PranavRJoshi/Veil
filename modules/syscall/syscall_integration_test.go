//go:build integration && linux

package syscall

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/PranavRJoshi/Veil/internal/testutil"
)

/*
	Integration tests for the syscall module. These target the kernel-side
	filter semantics, which unit tests cannot reach: that an allow filter
	excludes as well as includes, that deny beats allow, and that removing
	the last key of a filter clears its bit rather than silencing the
	stream.

	Every test filters on its own PID so the assertions hold against
	system-wide syscall traffic.
*/

func selfPID() uint32 { return uint32(os.Getpid()) }

/*
	syscallNr resolves a name via the generated table, skipping the test if
	this architecture does not have it.
*/
func syscallNr(t *testing.T, name string) uint64 {
	t.Helper()

	nr, ok := SyscallNumber(name)
	if !ok {
		t.Skipf("syscall %q not present in the table for this architecture", name)
	}
	return nr
}

/*
	isSyscall matches an event for the named syscall.
*/
func isSyscall(name string) func(testutil.Captured) bool {
	return func(c testutil.Captured) bool {
		if c.Module != "syscall" {
			return false
		}
		got, ok := c.Field("syscall")
		return ok && got == name
	}
}

/*
	notSyscall matches any syscall event other than the named one.
*/
func notSyscall(name string) func(testutil.Captured) bool {
	return func(c testutil.Captured) bool {
		if c.Module != "syscall" {
			return false
		}
		got, ok := c.Field("syscall")
		return ok && got != name
	}
}

/*
	anySyscallFromSelf matches any syscall event from this process, without
	reference to which call it was.

	Tests that only need to know the pipeline is alive must use this rather
	than waiting on a name: a table built for the wrong architecture still
	labels events, so a name-based wait is satisfied by a mislabelled event
	and the test passes while the bug it would have caught goes unnoticed.
*/
func anySyscallFromSelf() func(testutil.Captured) bool {
	want := strconv.FormatUint(uint64(selfPID()), 10)
	return func(c testutil.Captured) bool {
		if c.Module != "syscall" {
			return false
		}
		pid, ok := c.Field("pid")
		return ok && pid == want
	}
}

/*
	openTempFile performs a handful of openat calls. Repeated because a
	single call can be lost if the ring buffer consumer has not yet been
	scheduled.
*/
func openTempFile(t *testing.T) {
	t.Helper()

	path := filepath.Join(t.TempDir(), "veil-itest-open.txt")
	if err := os.WriteFile(path, []byte("x"), 0644); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	for i := 0; i < 5; i++ {
		f, err := os.Open(path)
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		f.Close()
	}
}

/*
	An allow filter must exclude as well as include. Filtering on openat
	must yield openat events and nothing else, even though this process
	makes many other syscalls while the test runs.
*/
func TestIntegrationSyscallAllowFilterIsExclusive(t *testing.T) {
	testutil.RequireBPF(t)
	syscallNr(t, "openat") /* skip early if unavailable */

	sink := testutil.NewCaptureSink()
	mod := New(FilterConfig{
		PIDs:     []uint32{selfPID()},
		Syscalls: []string{"openat"},
	}, sink)
	testutil.StartModule(t, mod)

	openTempFile(t)
	got := sink.WaitFor(t, testutil.DefaultTimeout, isSyscall("openat"))

	/*
		Check the raw number against this architecture's ABI, not just the
		label. A table built for the wrong architecture is internally
		consistent -- it would filter on some other call and then label
		that call "openat" -- so asserting on the name alone proves
		nothing about which syscall was actually traced.
	*/
	want := strconv.FormatUint(anchorNr(t, "openat"), 10)
	if nr, _ := got.Field("syscall_nr"); nr != want {
		t.Errorf("event labelled openat carries syscall_nr %s, want %s on this arch", nr, want)
	}

	/*
		The interesting assertion: nothing but openat got through. A
		filter that only ever added events would pass a "we saw openat"
		check while silently leaking everything else.
	*/
	for _, c := range sink.Snapshot() {
		got, _ := c.Field("syscall")
		if got != "openat" {
			t.Errorf("allow filter leaked a non-openat event: syscall=%s fields=%v", got, c.Fields)
		}
	}
}

/*
	Deny takes precedence over allow. With openat in both lists and write
	in the allow list only, write must arrive and openat must not.

	The write event doubles as a positive control: it proves the pipeline
	is live, so the absence of openat means "denied" rather than "nothing
	was traced". That also avoids paying a negative timeout -- os.WriteFile
	issues its openat before its write, so if openat were leaking it would
	already be in the snapshot by the time write arrives.
*/
func TestIntegrationSyscallDenyBeatsAllow(t *testing.T) {
	testutil.RequireBPF(t)
	syscallNr(t, "openat")
	syscallNr(t, "write")

	sink := testutil.NewCaptureSink()
	mod := New(FilterConfig{
		PIDs:         []uint32{selfPID()},
		Syscalls:     []string{"openat", "write"},
		DenySyscalls: []string{"openat"},
	}, sink)
	testutil.StartModule(t, mod)

	path := filepath.Join(t.TempDir(), "veil-itest-deny.txt")
	for i := 0; i < 5; i++ {
		if err := os.WriteFile(path, []byte("payload\n"), 0644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}

	sink.WaitFor(t, testutil.DefaultTimeout, isSyscall("write"))

	for _, c := range sink.Snapshot() {
		if got, _ := c.Field("syscall"); got == "openat" {
			t.Errorf("openat was in both allow and deny lists but still emitted: %v", c.Fields)
		}
	}
}

/*
	Removing the last key of a filter must clear its filter_cfg bit.

	The BPF program drops every event when a bit is set but its map is
	empty, so a DelFilter that removed the key without clearing the bit
	would silently silence the whole stream -- the failure mode the
	filter_cfg invariant exists to prevent.
*/
func TestIntegrationSyscallDelFilterClearsBitWhenMapEmpties(t *testing.T) {
	testutil.RequireBPF(t)
	openatNr := syscallNr(t, "openat")

	sink := testutil.NewCaptureSink()
	mod := New(FilterConfig{
		PIDs:     []uint32{selfPID()},
		Syscalls: []string{"openat"},
	}, sink)
	testutil.StartModule(t, mod)

	openTempFile(t)
	sink.WaitFor(t, testutil.DefaultTimeout, isSyscall("openat"))

	/* Drop the only syscall key; the bit must come down with it. */
	if err := mod.DelFilter("syscall", openatNr); err != nil {
		t.Fatalf("DelFilter openat: %v", err)
	}

	keys, err := mod.ListFilters("syscall")
	if err != nil {
		t.Fatalf("ListFilters: %v", err)
	}
	if len(keys) != 0 {
		t.Fatalf("expected syscall map to be empty after DelFilter, got %v", keys)
	}

	/*
		With the bit cleared, syscalls other than openat must flow again.
		If the bit were left set over an empty map, nothing would arrive
		and this would time out.
	*/
	openTempFile(t)
	sink.WaitFor(t, testutil.DefaultTimeout, notSyscall("openat"))
}

/*
	MapUpdater operations against real BPF maps. The existing unit tests
	exercise the control layer against fakes, so nothing verifies that
	these actually reach the kernel.
*/
func TestIntegrationSyscallMapUpdaterRoundTrip(t *testing.T) {
	testutil.RequireBPF(t)
	openatNr := syscallNr(t, "openat")
	writeNr := syscallNr(t, "write")

	sink := testutil.NewCaptureSink()
	mod := New(FilterConfig{PIDs: []uint32{selfPID()}}, sink)
	testutil.StartModule(t, mod)

	contains := func(keys []uint64, want uint64) bool {
		for _, k := range keys {
			if k == want {
				return true
			}
		}
		return false
	}

	mustList := func(step string) []uint64 {
		t.Helper()
		keys, err := mod.ListFilters("syscall")
		if err != nil {
			t.Fatalf("%s: ListFilters: %v", step, err)
		}
		return keys
	}

	if keys := mustList("initial"); len(keys) != 0 {
		t.Fatalf("expected no syscall filters at start, got %v", keys)
	}

	if err := mod.AddFilter("syscall", openatNr); err != nil {
		t.Fatalf("AddFilter openat: %v", err)
	}
	if err := mod.AddFilter("syscall", writeNr); err != nil {
		t.Fatalf("AddFilter write: %v", err)
	}

	keys := mustList("after adds")
	if len(keys) != 2 || !contains(keys, openatNr) || !contains(keys, writeNr) {
		t.Fatalf("expected openat(%d) and write(%d), got %v", openatNr, writeNr, keys)
	}

	if err := mod.DelFilter("syscall", openatNr); err != nil {
		t.Fatalf("DelFilter openat: %v", err)
	}
	keys = mustList("after delete")
	if len(keys) != 1 || !contains(keys, writeNr) {
		t.Fatalf("expected only write(%d) to remain, got %v", writeNr, keys)
	}

	/* Deleting a key that is not present must report an error, not succeed. */
	if err := mod.DelFilter("syscall", openatNr); err == nil {
		t.Error("DelFilter on an absent key returned nil, expected an error")
	}

	if err := mod.ClearFilters("syscall"); err != nil {
		t.Fatalf("ClearFilters: %v", err)
	}
	if keys := mustList("after clear"); len(keys) != 0 {
		t.Fatalf("expected empty map after ClearFilters, got %v", keys)
	}

	/* An unknown map name must be rejected rather than silently ignored. */
	if err := mod.AddFilter("nonexistent", 1); err == nil {
		t.Error("AddFilter on an unknown map returned nil, expected an error")
	}
}

/*
	Guard against a module that reports itself loaded before its state is
	usable, and against Close being callable twice.
*/
func TestIntegrationSyscallLifecycle(t *testing.T) {
	testutil.RequireBPF(t)

	sink := testutil.NewCaptureSink()
	mod := New(FilterConfig{PIDs: []uint32{selfPID()}}, sink)

	if err := mod.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}

	if got := mod.State().String(); got != "loaded" {
		t.Errorf("expected state \"loaded\" after Load, got %q", got)
	}

	done := make(chan struct{})
	go mod.Run(done)

	openTempFile(t)
	sink.WaitFor(t, testutil.DefaultTimeout, anySyscallFromSelf())

	if err := mod.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	close(done)

	if got := mod.State().String(); got != "closed" {
		t.Errorf("expected state \"closed\" after Close, got %q", got)
	}

	/* A second Close must be rejected by the state guard, not panic. */
	if err := mod.Close(); err == nil {
		t.Error("second Close returned nil, expected a state error")
	}

	/*
		poll() closes Events on its way out. Reading from a closed channel
		must not block; if this times out, the goroutine leaked.
	*/
	deadline := time.After(testutil.DefaultTimeout)
	for {
		select {
		case _, ok := <-mod.Events:
			if !ok {
				return
			}
		case <-deadline:
			t.Fatal("Events channel was not closed after Close; poll() leaked")
		}
	}
}
