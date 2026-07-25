package scheduler

import (
	"runtime"
	"strings"
	"testing"
)

func TestValidateFilter_CPUBeyondCountWarns(t *testing.T) {
	m := &SchedulerModule{}
	beyond := uint64(runtime.NumCPU()) + 100
	warn, err := m.ValidateFilter("cpu", beyond)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(warn, "exceeds system CPU count") {
		t.Errorf("warn = %q, want a cpu-count warning", warn)
	}
}

func TestValidateFilter_CPUValidNoWarn(t *testing.T) {
	m := &SchedulerModule{}
	/* CPU 0 exists on every machine. */
	if warn, err := m.ValidateFilter("cpu", 0); err != nil || warn != "" {
		t.Errorf("cpu 0: warn=%q err=%v, want none", warn, err)
	}
}

func TestValidateFilter_NonCPUMapNoWarn(t *testing.T) {
	m := &SchedulerModule{}
	if warn, _ := m.ValidateFilter("pid", 99999); warn != "" {
		t.Errorf("pid map should not warn, got %q", warn)
	}
}
