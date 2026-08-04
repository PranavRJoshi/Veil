package suggest

import (
	"reflect"
	"testing"
)

var syscalls = []string{
	"epoll_create1", "epoll_ctl", "epoll_pwait", "epoll_pwait2",
	"open", "openat", "openat2", "read", "readv", "write", "close",
	"ioctl", "settimeofday", "setuid", "setgid",
}

func TestClosest(t *testing.T) {
	tests := []struct {
		name    string
		target  string
		max     int
		wantTop string   // first suggestion; "" means expect none
		must    []string // suggestions that must be present
	}{
		{"one edit insertion", "opena", 5, "openat", []string{"openat", "open"}},
		{"epoll family via prefix", "epoll_wait", 5, "epoll_pwait", []string{"epoll_pwait", "epoll_pwait2"}},
		{"long prefix miss", "settime", 5, "settimeofday", []string{"settimeofday"}},
		{"nothing close", "zzzzz", 5, "", nil},
		{"exact is excluded", "read", 5, "readv", []string{"readv"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Closest(tc.target, syscalls, tc.max)
			if tc.wantTop == "" {
				if got != nil {
					t.Fatalf("want no suggestions, got %v", got)
				}
				return
			}
			if len(got) == 0 || got[0] != tc.wantTop {
				t.Fatalf("top = %v, want %q first", got, tc.wantTop)
			}
			for _, m := range tc.must {
				if !contains(got, m) {
					t.Errorf("want %q in suggestions, got %v", m, got)
				}
			}
		})
	}
}

func TestClosestCaseInsensitive(t *testing.T) {
	if got := Closest("EPOLL_WAIT", syscalls, 3); len(got) == 0 || got[0] != "epoll_pwait" {
		t.Fatalf("case folding failed: %v", got)
	}
}

func TestClosestRespectsMax(t *testing.T) {
	if got := Closest("epoll_wait", syscalls, 2); len(got) > 2 {
		t.Fatalf("max not honored: %v", got)
	}
}

func TestClosestDeterministic(t *testing.T) {
	// Result order must not depend on candidate order.
	reversed := make([]string, len(syscalls))
	for i, s := range syscalls {
		reversed[len(syscalls)-1-i] = s
	}
	a := Closest("epoll_wait", syscalls, 5)
	b := Closest("epoll_wait", reversed, 5)
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("order differs: %v vs %v", a, b)
	}
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
