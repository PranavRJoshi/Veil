package syscall

import (
	"runtime"
	"testing"
)

/*
	archAnchors holds syscall numbers that are part of each architecture's
	stable ABI and can never change. They exist to catch the wrong
	architecture's table being compiled in, which is otherwise invisible:
	the table stays internally consistent, so every lookup agrees with
	every other one while all of them are wrong.

	openat and clone are the sharpest pair. They swap roles across the two
	architectures -- 56 is openat on arm64 and clone on x86_64 -- so a
	table built for the wrong arch fails here immediately.
*/
var archAnchors = map[string]map[string]uint64{
	"amd64": {"read": 0, "write": 1, "close": 3, "clone": 56, "openat": 257},
	"arm64": {"openat": 56, "close": 57, "read": 63, "write": 64, "clone": 220},
}

/*
	anchorNr returns the known-correct number for a syscall on the current
	architecture, skipping the test where no anchors are recorded.
*/
func anchorNr(t *testing.T, name string) uint64 {
	t.Helper()

	want, ok := archAnchors[runtime.GOARCH]
	if !ok {
		t.Skipf("no syscall anchors recorded for GOARCH %s", runtime.GOARCH)
	}
	nr, ok := want[name]
	if !ok {
		t.Fatalf("no anchor recorded for %q on %s", name, runtime.GOARCH)
	}
	return nr
}

func TestSyscallTableMatchesGOARCH(t *testing.T) {
	want, ok := archAnchors[runtime.GOARCH]
	if !ok {
		t.Skipf("no syscall anchors recorded for GOARCH %s", runtime.GOARCH)
	}

	for name, nr := range want {
		got, ok := SyscallNumber(name)
		if !ok {
			t.Errorf("SyscallNumber(%q) not found; wrong table compiled in for %s?",
				name, runtime.GOARCH)
			continue
		}
		if got != nr {
			t.Errorf("SyscallNumber(%q) = %d, want %d on %s",
				name, got, nr, runtime.GOARCH)
		}
		if back := SyscallName(nr); back != name {
			t.Errorf("SyscallName(%d) = %q, want %q on %s",
				nr, back, name, runtime.GOARCH)
		}
	}
}

/*
	The __NR3264_ forms in asm-generic/unistd.h carry real syscall numbers.
	Dropping them once left these out of the table entirely, so they could
	not be filtered by name and were reported as syscall_<nr>.
*/
func TestSyscallTableHasDualABICalls(t *testing.T) {
	for _, name := range []string{
		"lseek", "fstat", "mmap", "fcntl", "truncate", "sendfile", "statfs",
	} {
		nr, ok := SyscallNumber(name)
		if !ok {
			t.Errorf("SyscallNumber(%q) not found", name)
			continue
		}
		if got := SyscallName(nr); got != name {
			t.Errorf("SyscallName(%d) = %q, want %q", nr, got, name)
		}
	}
}

/*
	Every name must map back to the number it came from. A duplicate number
	claimed by two names would make filtering ambiguous.
*/
func TestSyscallTableRoundTrips(t *testing.T) {
	if len(syscallNames) == 0 {
		t.Fatal("syscall table is empty")
	}

	for nr, name := range syscallNames {
		got, ok := syscallNumbers[name]
		if !ok {
			t.Errorf("name %q (nr %d) missing from the reverse map", name, nr)
			continue
		}
		if got != nr {
			t.Errorf("round trip failed: %d -> %q -> %d", nr, name, got)
		}
	}
}

func TestSyscallNameUnknownIsTotal(t *testing.T) {
	if got := SyscallName(1 << 40); got != "syscall_1099511627776" {
		t.Errorf("SyscallName on an unknown number = %q, want the syscall_<nr> form", got)
	}
}
