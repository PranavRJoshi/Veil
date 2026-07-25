package network

import (
	"strings"
	"testing"
)

func TestTextFormat_RoundTrip(t *testing.T) {
	fields := map[string]interface{}{
		"kind":     "network",
		"pid":      uint32(1234),
		"uid":      uint32(0),
		"comm":     "curl",
		"evt_type": "CONNECT",
		"saddr":    "127.0.0.1",
		"sport":    uint16(54268),
		"daddr":    "93.184.216.34",
		"dport":    uint16(80),
		"oldstate": "CLOSE",
		"newstate": "SYN_SENT",
	}

	got := textFormat("network", fields)

	if !strings.Contains(got, "CONNECT") {
		t.Errorf("missing evt_type: %q", got)
	}
	if !strings.Contains(got, "127.0.0.1") {
		t.Errorf("missing saddr: %q", got)
	}
	if !strings.Contains(got, "93.184.216.34") {
		t.Errorf("missing daddr: %q", got)
	}
	if !strings.Contains(got, "[CLOSE->SYN_SENT]") {
		t.Errorf("missing state transition with parens: %q", got)
	}
}

func TestTextFormat_WithEnrichment(t *testing.T) {
	fields := map[string]interface{}{
		"kind": "network", "pid": uint32(100), "uid": uint32(0),
		"comm": "curl", "evt_type": "CONNECT",
		"saddr": "127.0.0.1", "sport": uint16(54268),
		"daddr": "93.184.216.34", "dport": uint16(80),
		"oldstate": "CLOSE", "newstate": "SYN_SENT",
		"time": "09:15:30.456", "proc_name": "curl",
	}

	got := textFormat("network", fields)

	if !strings.HasPrefix(got, "[09:15:30.456] ") {
		t.Errorf("expected time prefix, got %q", got)
	}
	if !strings.Contains(got, "proc=curl") {
		t.Errorf("expected proc=curl, got %q", got)
	}
}
