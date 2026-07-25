package scheduler

import (
	"strings"
	"testing"
)

func TestTextFormat_RoundTrip(t *testing.T) {
	fields := map[string]interface{}{
		"cpu":        uint32(2),
		"prev_comm":  "nginx",
		"prev_pid":   uint32(1001),
		"prev_prio":  uint32(120),
		"next_comm":  "kworker",
		"next_pid":   uint32(50),
		"next_prio":  uint32(100),
		"prev_state": "TASK_RUNNING",
	}

	got := textFormat("scheduler", fields)

	checks := []struct {
		label  string
		substr string
	}{
		{"cpu", "CPU=2"},
		{"prev_comm", "nginx"},
		{"prev_pid", "PID=1001"},
		{"prev_prio", "prio=120"},
		{"next_comm", "kworker"},
		{"next_pid", "PID=50"},
		{"next_prio", "prio=100"},
		{"prev_state", "TASK_RUNNING"},
	}

	for _, c := range checks {
		if !strings.Contains(got, c.substr) {
			t.Errorf("missing %s (%q) in output: %q", c.label, c.substr, got)
		}
	}
}

func TestTextFormat_WithEnrichment(t *testing.T) {
	fields := map[string]interface{}{
		"cpu":        uint32(0),
		"prev_comm":  "bash",
		"prev_pid":   uint32(200),
		"prev_prio":  uint32(120),
		"next_comm":  "cat",
		"next_pid":   uint32(201),
		"next_prio":  uint32(120),
		"prev_state": "TASK_INTERRUPTIBLE",
		"time":       "12:00:00.000",
		"username":   "root",
		"proc_name":  "bash",
	}

	got := textFormat("scheduler", fields)

	if !strings.HasPrefix(got, "[12:00:00.000] ") {
		t.Errorf("expected time prefix, got %q", got)
	}
	if !strings.Contains(got, "user=root") {
		t.Errorf("expected user=root in output: %q", got)
	}
	if !strings.Contains(got, "proc=bash") {
		t.Errorf("expected proc=bash in output: %q", got)
	}
}

func TestTextFormat_WithoutEnrichment(t *testing.T) {
	fields := map[string]interface{}{
		"cpu":        uint32(1),
		"prev_comm":  "sleep",
		"prev_pid":   uint32(999),
		"prev_prio":  uint32(120),
		"next_comm":  "swapper",
		"next_pid":   uint32(0),
		"next_prio":  uint32(120),
		"prev_state": "TASK_DEAD",
	}

	got := textFormat("scheduler", fields)

	if strings.Contains(got, "user=") {
		t.Errorf("should not have user= without enrichment: %q", got)
	}
	if strings.Contains(got, "proc=") {
		t.Errorf("should not have proc= without enrichment: %q", got)
	}
}
