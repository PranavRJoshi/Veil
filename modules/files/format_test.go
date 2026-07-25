package files

import (
	"strings"
	"testing"
)

func TestTextFormat_RoundTrip(t *testing.T) {
	fields := map[string]interface{}{
		"kind":     "file access",
		"pid":      uint32(5678),
		"uid":      uint32(1000),
		"comm":     "nginx",
		"op":       "read",
		"filename": "nginx.conf",
	}

	got := textFormat("files", fields)

	if !strings.Contains(got, "PID=5678") {
		t.Errorf("missing pid: %q", got)
	}
	if !strings.Contains(got, "op=read") {
		t.Errorf("missing op: %q", got)
	}
	if !strings.Contains(got, "filename=nginx.conf") {
		t.Errorf("missing filename: %q", got)
	}
}

func TestTextFormat_WithEnrichment(t *testing.T) {
	fields := map[string]interface{}{
		"kind": "file access", "pid": uint32(5678), "uid": uint32(1000),
		"comm": "nginx", "op": "read", "filename": "nginx.conf",
		"time": "10:00:00.000", "username": "www-data",
	}

	got := textFormat("files", fields)

	if !strings.HasPrefix(got, "[10:00:00.000] ") {
		t.Errorf("expected time prefix, got %q", got)
	}
	if !strings.Contains(got, "user=www-data") {
		t.Errorf("expected user=www-data, got %q", got)
	}
}
