package syscall

import (
	"strings"
	"testing"
)

func TestValidateFilter_UnknownSyscallWarns(t *testing.T) {
	m := &TracerModule{}
	/* A number that cannot be in any architecture's table. */
	warn, err := m.ValidateFilter("syscall", 1<<40)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(warn, "not in table") {
		t.Errorf("warn = %q, want a not-in-table warning", warn)
	}
}

func TestValidateFilter_KnownSyscallNoWarn(t *testing.T) {
	nr, ok := SyscallNumber("read")
	if !ok {
		t.Skip("read not in table for this architecture")
	}
	m := &TracerModule{}
	if warn, err := m.ValidateFilter("syscall", nr); err != nil || warn != "" {
		t.Errorf("known syscall: warn=%q err=%v, want no warning", warn, err)
	}
}

func TestValidateFilter_NonSyscallMapNoWarn(t *testing.T) {
	m := &TracerModule{}
	if warn, _ := m.ValidateFilter("pid", 1<<40); warn != "" {
		t.Errorf("pid map should not warn, got %q", warn)
	}
}
