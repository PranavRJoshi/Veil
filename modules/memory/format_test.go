package memory

import (
	"strings"
	"testing"
)

func TestTextFormat_RoundTrip(t *testing.T) {
	fields := map[string]interface{}{
		"comm":     "python3",
		"pid":      uint32(3456),
		"tid":      uint32(3456),
		"uid":      uint32(1000),
		"evt_type": "minor",
		"address":  "0x7f8b3c000000",
	}

	got := textFormat("memory", fields)

	checks := []struct {
		label  string
		substr string
	}{
		{"comm", "python3"},
		{"pid", "PID=3456"},
		{"tid", "TID=3456"},
		{"uid", "UID=1000"},
		{"evt_type", "fault=minor"},
		{"address", "addr=0x7f8b3c000000"},
	}

	for _, c := range checks {
		if !strings.Contains(got, c.substr) {
			t.Errorf("missing %s (%q) in output: %q", c.label, c.substr, got)
		}
	}
}

func TestTextFormat_WithEnrichment(t *testing.T) {
	fields := map[string]interface{}{
		"comm":      "node",
		"pid":       uint32(4000),
		"tid":       uint32(4000),
		"uid":       uint32(1000),
		"evt_type":  "minor",
		"address":   "0x55a000100000",
		"time":      "08:30:15.789",
		"username":  "deploy",
		"proc_name": "node",
	}

	got := textFormat("memory", fields)

	if !strings.HasPrefix(got, "[08:30:15.789] ") {
		t.Errorf("expected time prefix, got %q", got)
	}
	if !strings.Contains(got, "user=deploy") {
		t.Errorf("expected user=deploy in output: %q", got)
	}
	if !strings.Contains(got, "proc=node") {
		t.Errorf("expected proc=node in output: %q", got)
	}
}

func TestTextFormat_WithoutEnrichment(t *testing.T) {
	fields := map[string]interface{}{
		"comm":     "stress",
		"pid":      uint32(7777),
		"tid":      uint32(7777),
		"uid":      uint32(0),
		"evt_type": "minor",
		"address":  "0x1000",
	}

	got := textFormat("memory", fields)

	if strings.Contains(got, "[") {
		t.Errorf("should not have time prefix without enrichment: %q", got)
	}
	if strings.Contains(got, "user=") {
		t.Errorf("should not have user= without enrichment: %q", got)
	}
	if strings.Contains(got, "proc=") {
		t.Errorf("should not have proc= without enrichment: %q", got)
	}
}

func TestTextFormat_MajorFault(t *testing.T) {
	fields := map[string]interface{}{
		"comm":     "gcc",
		"pid":      uint32(8000),
		"tid":      uint32(8001),
		"uid":      uint32(0),
		"evt_type": "major",
		"address":  "0xffffa00012340000",
	}

	got := textFormat("memory", fields)

	if !strings.Contains(got, "fault=major") {
		t.Errorf("expected fault=major in output: %q", got)
	}
}
