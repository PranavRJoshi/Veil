//go:build integration && linux

package memory

import (
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/PranavRJoshi/Veil/internal/testutil"
)

/*
	Integration tests for the memory module.

	This is the only module built from a kprobe/kretprobe pair. pid, comm
	and the faulting address are captured on entry and stashed in the
	fault_scratch map; the major/minor classification comes from the return
	value on the way out. An event carrying both halves is the evidence
	that the correlation worked, so the tests assert on entry-side data
	rather than only on the fault type.

	Only minor faults are exercised. A major fault requires the page to
	come from disk, which cannot be forced reliably from a test without
	dropping caches system-wide.
*/

const (
	faultMajor uint32 = 0
	faultMinor uint32 = 1
)

func selfPID() uint32 { return uint32(os.Getpid()) }

/*
	selfComm returns this process's comm as the kernel records it, already
	truncated to the 15 characters that fit in TASK_COMM_LEN.
*/
func selfComm(t *testing.T) string {
	t.Helper()

	raw, err := os.ReadFile("/proc/self/comm")
	if err != nil {
		t.Fatalf("read /proc/self/comm: %v", err)
	}
	return strings.TrimSpace(string(raw))
}

/*
	touchPages allocates the given number of megabytes and writes one byte
	per page, forcing the kernel to fault in each freshly mapped page.
	Large enough that the runtime must map new memory rather than reuse an
	already-faulted heap.

	The stride is the real page size rather than a hardcoded 4096: arm64
	kernels can be built with 16K or 64K pages, where a fixed 4096 stride
	would touch each page several times over and produce a fraction of the
	expected faults.
*/
func touchPages(mb int) {
	pageSize := os.Getpagesize()
	buf := make([]byte, mb<<20)
	for i := 0; i < len(buf); i += pageSize {
		buf[i] = byte(i)
	}
	runtime.KeepAlive(buf)
}

func isMinorFault(c testutil.Captured) bool {
	if c.Module != "memory" {
		return false
	}
	ft, ok := c.Field("evt_type")
	return ok && ft == "minor"
}

/*
	The entry-side data must survive to the emitted event. A correlation
	that lost the scratch entry would still be able to classify the fault,
	so asserting only on major/minor would not notice.
*/
func TestIntegrationMemoryFaultsCarryEntryData(t *testing.T) {
	testutil.RequireBPF(t)

	sink := testutil.NewCaptureSink()
	mod := New(FilterConfig{PIDs: []uint32{selfPID()}}, sink)
	testutil.StartModule(t, mod)

	touchPages(32)
	c := sink.WaitFor(t, testutil.DefaultTimeout, isMinorFault)

	wantPID := strconv.FormatUint(uint64(selfPID()), 10)
	if pid, _ := c.Field("pid"); pid != wantPID {
		t.Errorf("pid = %s, want %s", pid, wantPID)
	}

	/*
		comm is captured by the kprobe on entry. Matching it against
		/proc/self/comm shows the scratch entry belonged to this task and
		not to whatever else faulted on the same CPU.
	*/
	if comm, _ := c.Field("comm"); comm != selfComm(t) {
		t.Errorf("comm = %q, want %q", comm, selfComm(t))
	}

	/*
		The faulting address is the second argument to handle_mm_fault,
		read on entry. A zero address means the scratch entry was missing
		or never populated.
	*/
	addr, ok := c.Field("address")
	if !ok {
		t.Fatal("event has no address field")
	}
	if addr == "0x0" {
		t.Error("address is zero; entry data did not reach the return probe")
	}
	if !strings.HasPrefix(addr, "0x") {
		t.Errorf("address = %q, want 0x-prefixed", addr)
	}
}

/*
	A fault-type allow filter must exclude the other type, not merely
	admit the one requested.
*/
func TestIntegrationMemoryFaultFilterIsExclusive(t *testing.T) {
	testutil.RequireBPF(t)

	sink := testutil.NewCaptureSink()
	mod := New(FilterConfig{
		PIDs:       []uint32{selfPID()},
		FaultTypes: []uint32{faultMinor},
	}, sink)
	stop := testutil.StartModule(t, mod)

	touchPages(32)
	sink.WaitFor(t, testutil.DefaultTimeout, isMinorFault)
	stop()

	for _, c := range sink.Snapshot() {
		if ft, _ := c.Field("evt_type"); ft != "minor" {
			t.Errorf("minor-only filter admitted a %s fault: %v", ft, c.Fields)
		}
	}
}

/*
	Deny takes precedence over allow.

	Major faults cannot be generated on demand, so the usual trick of
	using the other type as a positive control is unavailable. Instead the
	same workload runs twice: once permitting minor faults, to establish
	that it produces events at all, then again with minor additionally
	denied. The first run is the control for the second.
*/
func TestIntegrationMemoryDenyFaultBeatsAllow(t *testing.T) {
	testutil.RequireBPF(t)

	allowed := testutil.NewCaptureSink()
	allowMod := New(FilterConfig{
		PIDs:       []uint32{selfPID()},
		FaultTypes: []uint32{faultMinor},
	}, allowed)
	stopAllow := testutil.StartModule(t, allowMod)

	touchPages(32)
	allowed.WaitFor(t, testutil.DefaultTimeout, isMinorFault)
	stopAllow()

	if allowed.Len() == 0 {
		t.Fatal("control run produced no events; the deny assertion below would be vacuous")
	}

	denied := testutil.NewCaptureSink()
	denyMod := New(FilterConfig{
		PIDs:       []uint32{selfPID()},
		FaultTypes: []uint32{faultMajor, faultMinor},
		DenyFaults: []uint32{faultMinor},
	}, denied)
	stopDeny := testutil.StartModule(t, denyMod)

	touchPages(32)
	if c, ok := denied.TryWaitFor(testutil.NegativeTimeout, isMinorFault); ok {
		t.Errorf("minor was in both allow and deny but still emitted: %v", c.Fields)
	}
	stopDeny()
}
