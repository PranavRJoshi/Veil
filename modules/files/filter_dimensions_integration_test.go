//go:build integration && linux

package files

import (
	"os"
	"strconv"
	"testing"

	"github.com/PranavRJoshi/Veil/internal/testutil"
)

/*
	The uid, pid-deny and uid-deny filter dimensions had no integration
	coverage in any module. They are exercised here on the files module,
	the simplest to drive: every event carries both a pid and a uid, and a
	single WriteFile produces events.

	These dimensions are the same bitmask bits (1, 3, 4) reimplemented in
	every module's populateFilters, so a wrong bit is a per-module risk.
	Consolidating that into bpfutil is the durable guard; this proves the
	mechanism works end to end.
*/

func selfUID() uint32 { return uint32(os.Getuid()) }

/*
	A uid allow filter must exclude other uids, not merely admit this one.
*/
func TestIntegrationFilesUIDFilterIsExclusive(t *testing.T) {
	testutil.RequireBPF(t)

	sink := testutil.NewCaptureSink()
	mod := New(FilterConfig{UIDs: []uint32{selfUID()}}, sink)
	stop := testutil.StartModule(t, mod)

	path, name := uniqueFile(t)
	if err := os.WriteFile(path, []byte("uid filter\n"), 0644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	sink.WaitFor(t, testutil.DefaultTimeout, matchFile(name, "open"))
	stop()

	want := strconv.FormatUint(uint64(selfUID()), 10)
	for _, c := range sink.Snapshot() {
		if uid, _ := c.Field("uid"); uid != want {
			t.Errorf("uid filter admitted an event from uid %s: %v", uid, c.Fields)
		}
	}
}

/*
	A pid deny filter must drop this process's events. The permitting run
	is the control: it shows the same workload does produce events, so the
	empty result under deny means filtered rather than nothing traced.
*/
func TestIntegrationFilesPIDDenyDropsSelf(t *testing.T) {
	testutil.RequireBPF(t)

	control := testutil.NewCaptureSink()
	controlMod := New(FilterConfig{PIDs: []uint32{selfPID()}}, control)
	stopControl := testutil.StartModule(t, controlMod)

	pathC, nameC := uniqueFile(t)
	if err := os.WriteFile(pathC, []byte("control\n"), 0644); err != nil {
		t.Fatalf("write %s: %v", pathC, err)
	}
	control.WaitFor(t, testutil.DefaultTimeout, matchFile(nameC, "open"))
	stopControl()

	denied := testutil.NewCaptureSink()
	denyMod := New(FilterConfig{DenyPIDs: []uint32{selfPID()}}, denied)
	stopDeny := testutil.StartModule(t, denyMod)

	pathD, nameD := uniqueFile(t)
	if err := os.WriteFile(pathD, []byte("denied\n"), 0644); err != nil {
		t.Fatalf("write %s: %v", pathD, err)
	}
	if c, ok := denied.TryWaitFor(testutil.NegativeTimeout, matchFile(nameD, "open")); ok {
		t.Errorf("pid deny still emitted a self event: %v", c.Fields)
	}
	stopDeny()
}

/*
	A uid deny filter must drop every event from this process's uid, on the
	same control-then-deny basis.
*/
func TestIntegrationFilesUIDDenyDropsSelf(t *testing.T) {
	testutil.RequireBPF(t)

	control := testutil.NewCaptureSink()
	controlMod := New(FilterConfig{UIDs: []uint32{selfUID()}}, control)
	stopControl := testutil.StartModule(t, controlMod)

	pathC, nameC := uniqueFile(t)
	if err := os.WriteFile(pathC, []byte("control\n"), 0644); err != nil {
		t.Fatalf("write %s: %v", pathC, err)
	}
	control.WaitFor(t, testutil.DefaultTimeout, matchFile(nameC, "open"))
	stopControl()

	denied := testutil.NewCaptureSink()
	denyMod := New(FilterConfig{DenyUIDs: []uint32{selfUID()}}, denied)
	stopDeny := testutil.StartModule(t, denyMod)

	pathD, nameD := uniqueFile(t)
	if err := os.WriteFile(pathD, []byte("denied\n"), 0644); err != nil {
		t.Fatalf("write %s: %v", pathD, err)
	}
	if c, ok := denied.TryWaitFor(testutil.NegativeTimeout, matchFile(nameD, "open")); ok {
		t.Errorf("uid deny still emitted a self event: %v", c.Fields)
	}
	stopDeny()
}
