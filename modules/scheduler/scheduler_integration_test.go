//go:build integration && linux

package scheduler

import (
	"runtime"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/PranavRJoshi/Veil/internal/testutil"
)

/*
	Integration tests for the scheduler module.

	A note on identifiers. The sched_switch tracepoint reports the kernel's
	task->pid in prev_pid and next_pid, which is a thread id, not the thread
	group id that os.Getpid returns. Filtering on Getpid would therefore
	only ever match the main thread. These tests lock a goroutine to its OS
	thread and filter on that thread's real tid instead.
*/

/*
	lockedTID pins the calling goroutine to its OS thread for the duration
	of the test and returns that thread's id.
*/
func lockedTID(t *testing.T) uint32 {
	t.Helper()

	runtime.LockOSThread()
	t.Cleanup(runtime.UnlockOSThread)

	return uint32(syscall.Gettid())
}

/*
	yieldRepeatedly sleeps a few times, forcing the calling thread off and
	back onto a CPU so sched_switch fires with it as prev and then as next.
*/
func yieldRepeatedly() {
	for i := 0; i < 5; i++ {
		time.Sleep(10 * time.Millisecond)
	}
}

func isScheduler(c testutil.Captured) bool { return c.Module == "scheduler" }

/*
	fieldsEqual reports whether two fields of an event render identically.
*/
func fieldsEqual(c testutil.Captured, a, b string) bool {
	x, okA := c.Field(a)
	y, okB := c.Field(b)
	return okA && okB && x == y
}

/*
	The PID filter matches when the id appears as either side of the
	switch. Both halves matter: matching only prev would silently drop
	every event where the traced thread is being scheduled in.
*/
func TestIntegrationSchedulerPIDFilterMatchesPrevOrNext(t *testing.T) {
	testutil.RequireBPF(t)

	tid := lockedTID(t)
	sink := testutil.NewCaptureSink()
	mod := New(FilterConfig{PIDs: []uint32{tid}}, sink)
	stop := testutil.StartModule(t, mod)

	yieldRepeatedly()

	want := strconv.FormatUint(uint64(tid), 10)
	matches := func(c testutil.Captured) bool {
		if !isScheduler(c) {
			return false
		}
		prev, _ := c.Field("prev_pid")
		next, _ := c.Field("next_pid")
		return prev == want || next == want
	}
	sink.WaitFor(t, testutil.DefaultTimeout, matches)

	stop()

	/*
		Every event must involve the filtered thread on one side or the
		other. A filter that let anything else through would still pass
		the wait above.
	*/
	var sawPrev, sawNext bool
	for _, c := range sink.Snapshot() {
		prev, _ := c.Field("prev_pid")
		next, _ := c.Field("next_pid")
		if prev != want && next != want {
			t.Errorf("pid filter leaked an event for neither prev nor next %s: %v", want, c.Fields)
		}
		if prev == want {
			sawPrev = true
		}
		if next == want {
			sawNext = true
		}
	}

	/*
		Both directions should occur across several sleeps: the thread is
		switched out to sleep and switched back in on wake. If only one
		side ever appears, the or-semantics are not actually working.
	*/
	if !sawPrev || !sawNext {
		t.Errorf("expected the thread as both prev and next across %d events; prev=%v next=%v",
			sink.Len(), sawPrev, sawNext)
	}
}

/*
	A CPU allow filter must exclude every other CPU, not merely admit the
	one requested.
*/
func TestIntegrationSchedulerCPUFilterIsExclusive(t *testing.T) {
	testutil.RequireBPF(t)

	sink := testutil.NewCaptureSink()
	mod := New(FilterConfig{CPUs: []uint32{0}}, sink)
	stop := testutil.StartModule(t, mod)

	yieldRepeatedly()
	sink.WaitFor(t, testutil.DefaultTimeout, isScheduler)

	/*
		Traced system-wide, so stop before inspecting: sched_switch is a
		firehose and the snapshot needs to be a fixed set.
	*/
	stop()

	for _, c := range sink.Snapshot() {
		if cpu, _ := c.Field("cpu"); cpu != "0" {
			t.Errorf("cpu filter admitted an event from cpu %s: %v", cpu, c.Fields)
		}
	}
}

/*
	Deny takes precedence over allow for CPUs, matching the other modules.
*/
func TestIntegrationSchedulerDenyCPUBeatsAllow(t *testing.T) {
	testutil.RequireBPF(t)

	if runtime.NumCPU() < 2 {
		t.Skip("needs at least two CPUs to distinguish allow from deny")
	}

	sink := testutil.NewCaptureSink()
	mod := New(FilterConfig{
		CPUs:     []uint32{0, 1},
		DenyCPUs: []uint32{0},
	}, sink)
	stop := testutil.StartModule(t, mod)

	yieldRepeatedly()

	/*
		Wait for a CPU 1 event first. It is the positive control: it shows
		the pipeline is live, so the absence of CPU 0 below means denied
		rather than nothing traced.
	*/
	onCPU1 := func(c testutil.Captured) bool {
		if !isScheduler(c) {
			return false
		}
		cpu, ok := c.Field("cpu")
		return ok && cpu == "1"
	}
	sink.WaitFor(t, testutil.DefaultTimeout, onCPU1)

	stop()

	for _, c := range sink.Snapshot() {
		if cpu, _ := c.Field("cpu"); cpu == "0" {
			t.Errorf("cpu 0 was in both allow and deny but still emitted: %v", c.Fields)
		}
	}
}

/*
	The scheduler has no single "the" pid or comm, so toFields aliases the
	generic keys onto the prev side. Enrichment and count mode read those
	generic keys and would silently fall back to "(unknown)" without them.
*/
func TestIntegrationSchedulerGenericFieldAliases(t *testing.T) {
	testutil.RequireBPF(t)

	tid := lockedTID(t)
	sink := testutil.NewCaptureSink()
	mod := New(FilterConfig{PIDs: []uint32{tid}}, sink)
	testutil.StartModule(t, mod)

	yieldRepeatedly()
	c := sink.WaitFor(t, testutil.DefaultTimeout, isScheduler)

	if !fieldsEqual(c, "pid", "prev_pid") {
		pid, _ := c.Field("pid")
		prev, _ := c.Field("prev_pid")
		t.Errorf("pid alias = %s, want prev_pid %s", pid, prev)
	}
	if !fieldsEqual(c, "comm", "prev_comm") {
		comm, _ := c.Field("comm")
		prev, _ := c.Field("prev_comm")
		t.Errorf("comm alias = %q, want prev_comm %q", comm, prev)
	}

	/*
		prev_state must be decoded, not passed through as a raw number.
		The hex fallback in prevStateName means an unmapped value is
		reported as 0x..., which is the signal that a state is missing
		from the table.
	*/
	if state, ok := c.Field("prev_state"); !ok || state == "" {
		t.Error("prev_state is absent or empty")
	}
}
