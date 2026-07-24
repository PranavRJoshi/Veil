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
