//go:build integration && linux

package files

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/PranavRJoshi/Veil/internal/testutil"
)

/*
	Integration tests for the files module: load the real BPF program,
	attach the vfs_open/vfs_read/vfs_write kprobes, drive a real file
	workload, and assert on the emitted events.

	Every test filters on its own PID. That keeps assertions deterministic
	against the rest of the system's file activity, and exercises the
	kernel-side pid_filter map at the same time.
*/

/*
	uniqueFile returns a path in the test's temp dir and its basename. The
	basename embeds pid and a timestamp so it cannot collide with anything
	else the system touches while the test runs.
*/
func uniqueFile(t *testing.T) (path, name string) {
	t.Helper()

	name = fmt.Sprintf("veil-itest-%d-%d.txt", os.Getpid(), time.Now().UnixNano())
	return filepath.Join(t.TempDir(), name), name
}

/*
	matchFile builds a predicate for an event of the given op referring to
	the given file.

	The basename is matched as a substring rather than comparing the whole
	path: the dentry walk stops at the filesystem root, so a file on a
	separate mount (t.TempDir() when /tmp is a tmpfs) reports a path
	relative to that mount. The unique basename identifies the file either
	way.
*/
func matchFile(name, op string) func(testutil.Captured) bool {
	return func(c testutil.Captured) bool {
		if c.Module != "files" {
			return false
		}
		if gotOp, ok := c.Field("op"); !ok || gotOp != op {
			return false
		}
		fn, ok := c.Field("filename")
		return ok && strings.Contains(fn, name)
	}
}

func selfPID() uint32 { return uint32(os.Getpid()) }

/*
	selfComm returns this process's comm as the kernel records it, already
	truncated to what fits in TASK_COMM_LEN.
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
	uniqueNameIn builds a unique basename and its full path inside dir,
	for tests that need several files in one directory.
*/
func uniqueNameIn(dir string) (path, name string) {
	name = fmt.Sprintf("veil-itest-%d-%d.txt", os.Getpid(), time.Now().UnixNano())
	return filepath.Join(dir, name), name
}

/*
	The module must observe an open, a read, and a write for a file this
	process touches.
*/
func TestIntegrationFilesOpenReadWrite(t *testing.T) {
	testutil.RequireBPF(t)

	sink := testutil.NewCaptureSink()
	mod := New(FilterConfig{PIDs: []uint32{selfPID()}}, sink)
	testutil.StartModule(t, mod)

	path, name := uniqueFile(t)

	if err := os.WriteFile(path, []byte("veil integration payload\n"), 0644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	if _, err := os.ReadFile(path); err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	want := strconv.FormatUint(uint64(selfPID()), 10)
	for _, op := range []string{"open", "read", "write"} {
		got := sink.WaitFor(t, testutil.DefaultTimeout, matchFile(name, op))
		if pid, _ := got.Field("pid"); pid != want {
			t.Errorf("op %s: expected pid %s, got %s", op, want, pid)
		}
	}
}

/*
	With a kernel-side PID filter set, no event from any other process may
	reach userspace.
*/
func TestIntegrationFilesPIDFilter(t *testing.T) {
	testutil.RequireBPF(t)

	sink := testutil.NewCaptureSink()
	mod := New(FilterConfig{PIDs: []uint32{selfPID()}}, sink)
	testutil.StartModule(t, mod)

	path, name := uniqueFile(t)
	if err := os.WriteFile(path, []byte("filtered\n"), 0644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}

	/* Wait for our own event first, so the stream is known to be live. */
	sink.WaitFor(t, testutil.DefaultTimeout, matchFile(name, "open"))

	want := strconv.FormatUint(uint64(selfPID()), 10)
	for _, c := range sink.Snapshot() {
		pid, ok := c.Field("pid")
		if !ok {
			t.Errorf("event without a pid field: %v", c.Fields)
			continue
		}
		if pid != want {
			t.Errorf("pid filter leaked an event from pid %s: %v", pid, c.Fields)
		}
	}
}

/*
	--op open attaches only the vfs_open kprobe, so reads and writes to the
	same file must produce no events at all.
*/
func TestIntegrationFilesOpFilterSelectiveAttach(t *testing.T) {
	testutil.RequireBPF(t)

	sink := testutil.NewCaptureSink()
	mod := New(FilterConfig{
		PIDs: []uint32{selfPID()},
		Ops:  []string{"open"},
	}, sink)
	testutil.StartModule(t, mod)

	path, name := uniqueFile(t)

	if err := os.WriteFile(path, []byte("open only\n"), 0644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	if _, err := os.ReadFile(path); err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	sink.WaitFor(t, testutil.DefaultTimeout, matchFile(name, "open"))

	for _, op := range []string{"read", "write"} {
		if c, ok := sink.TryWaitFor(testutil.NegativeTimeout, matchFile(name, op)); ok {
			t.Errorf("op filter \"open\" still produced a %s event: %v", op, c.Fields)
		}
	}
}

/*
	--name is a userspace filter applied in matchesFilter after the event
	has been parsed, not a BPF map lookup. It is a separate code path from
	every kernel-side filter, so a break in it would go unnoticed by the
	other tests.
*/
func TestIntegrationFilesCommNameFilter(t *testing.T) {
	testutil.RequireBPF(t)

	comm := selfComm(t)

	/* A matching comm must let this process's file events through. */
	matched := testutil.NewCaptureSink()
	matchMod := New(FilterConfig{
		PIDs:     []uint32{selfPID()},
		CommName: comm,
	}, matched)
	stopMatch := testutil.StartModule(t, matchMod)

	path, name := uniqueFile(t)
	if err := os.WriteFile(path, []byte("comm filter\n"), 0644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	matched.WaitFor(t, testutil.DefaultTimeout, matchFile(name, "open"))
	stopMatch()

	/*
		A comm that cannot occur must exclude them. The run above is the
		control: it proves the same workload does produce events, so an
		empty result here means filtered rather than nothing traced.
	*/
	excluded := testutil.NewCaptureSink()
	excludeMod := New(FilterConfig{
		PIDs:     []uint32{selfPID()},
		CommName: "veil-no-such-comm",
	}, excluded)
	stopExclude := testutil.StartModule(t, excludeMod)

	path2, name2 := uniqueFile(t)
	if err := os.WriteFile(path2, []byte("comm filter\n"), 0644); err != nil {
		t.Fatalf("write %s: %v", path2, err)
	}
	if c, ok := excluded.TryWaitFor(testutil.NegativeTimeout, matchFile(name2, "open")); ok {
		t.Errorf("non-matching comm filter still emitted an event: %v", c.Fields)
	}
	stopExclude()
}

/*
	--file matching runs against the path the BPF program assembles from
	the dentry chain, which the unit tests can only approximate with
	synthetic strings.

	The reported path is discovered first rather than assumed: the dentry
	walk stops at the filesystem root, so a file under a tmpfs /tmp is
	reported relative to that mount and its absolute prefix is not
	predictable from userspace. Phase two then proves the directory-prefix
	form matches the very path the module reported.
*/
func TestIntegrationFilesPathFilterMatchesReportedPath(t *testing.T) {
	testutil.RequireBPF(t)

	dir := t.TempDir()

	/* Phase 1: learn what path this module reports for a file in dir. */
	discover := testutil.NewCaptureSink()
	discoverMod := New(FilterConfig{PIDs: []uint32{selfPID()}}, discover)
	stopDiscover := testutil.StartModule(t, discoverMod)

	probePath, probeName := uniqueNameIn(dir)
	if err := os.WriteFile(probePath, []byte("probe\n"), 0644); err != nil {
		t.Fatalf("write %s: %v", probePath, err)
	}
	c := discover.WaitFor(t, testutil.DefaultTimeout, matchFile(probeName, "open"))
	stopDiscover()

	reported, ok := c.Field("filename")
	if !ok {
		t.Fatal("discovery event has no filename field")
	}
	prefix := filepath.Dir(reported) + "/"
	if !strings.HasPrefix(prefix, "/") {
		t.Fatalf("reported path %q has no absolute directory to filter on", reported)
	}

	/* Phase 2: the directory-prefix form must match that same path. */
	filtered := testutil.NewCaptureSink()
	filterMod := New(FilterConfig{
		PIDs:     []uint32{selfPID()},
		FileName: prefix,
	}, filtered)
	stopFiltered := testutil.StartModule(t, filterMod)

	insidePath, insideName := uniqueNameIn(dir)
	if err := os.WriteFile(insidePath, []byte("inside\n"), 0644); err != nil {
		t.Fatalf("write %s: %v", insidePath, err)
	}
	got := filtered.WaitFor(t, testutil.DefaultTimeout, matchFile(insideName, "open"))

	if fn, _ := got.Field("filename"); !strings.HasPrefix(fn, prefix) {
		t.Errorf("event path %q does not start with the filter prefix %q", fn, prefix)
	}

	/* Everything admitted must live under the filtered directory. */
	for _, c := range filtered.Snapshot() {
		fn, _ := c.Field("filename")
		if !strings.HasPrefix(fn, prefix) {
			t.Errorf("path filter %q admitted %q", prefix, fn)
		}
	}
	stopFiltered()
}
