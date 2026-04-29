package files

import (
	"testing"

	"github.com/PranavRJoshi/Veil/internal/events"
)

// ---------------------------------------------------------------------------
// ParseFilterConfig
// ---------------------------------------------------------------------------

func TestParseFilterConfig_PIDs(t *testing.T) {
	cfg, err := ParseFilterConfig(map[string]string{"pid": "100,200"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.PIDs) != 2 || cfg.PIDs[0] != 100 || cfg.PIDs[1] != 200 {
		t.Errorf("expected [100 200], got %v", cfg.PIDs)
	}
}

func TestParseFilterConfig_InvalidPID(t *testing.T) {
	_, err := ParseFilterConfig(map[string]string{"pid": "abc"})
	if err == nil {
		t.Fatal("expected error for non-numeric PID")
	}
}

func TestParseFilterConfig_UIDs(t *testing.T) {
	cfg, err := ParseFilterConfig(map[string]string{"uid": "0"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.UIDs) != 1 || cfg.UIDs[0] != 0 {
		t.Errorf("expected [0], got %v", cfg.UIDs)
	}
}

func TestParseFilterConfig_ValidOps(t *testing.T) {
	cfg, err := ParseFilterConfig(map[string]string{"op": "open,read,write"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.Ops) != 3 {
		t.Fatalf("expected 3 ops, got %d", len(cfg.Ops))
	}
}

func TestParseFilterConfig_InvalidOp(t *testing.T) {
	_, err := ParseFilterConfig(map[string]string{"op": "delete"})
	if err == nil {
		t.Fatal("expected error for unknown operation 'delete'")
	}
}

func TestParseFilterConfig_OpWithSpaces(t *testing.T) {
	cfg, err := ParseFilterConfig(map[string]string{"op": " read , write "})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.Ops) != 2 || cfg.Ops[0] != "read" || cfg.Ops[1] != "write" {
		t.Errorf("spaces not trimmed: got %v", cfg.Ops)
	}
}

func TestParseFilterConfig_FileName(t *testing.T) {
	cfg, err := ParseFilterConfig(map[string]string{"file": "passwd"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.FileName != "passwd" {
		t.Errorf("expected FileName 'passwd', got %q", cfg.FileName)
	}
}

func TestParseFilterConfig_CommName(t *testing.T) {
	cfg, err := ParseFilterConfig(map[string]string{"name": "nginx"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.CommName != "nginx" {
		t.Errorf("expected CommName 'nginx', got %q", cfg.CommName)
	}
}

func TestParseFilterConfig_EmptyFlags(t *testing.T) {
	cfg, err := ParseFilterConfig(map[string]string{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.PIDs) != 0 || len(cfg.UIDs) != 0 || len(cfg.Ops) != 0 ||
		cfg.CommName != "" || cfg.FileName != "" {
		t.Errorf("expected empty config, got %+v", cfg)
	}
}

func TestParseFilterConfig_OverflowPID(t *testing.T) {
	_, err := ParseFilterConfig(map[string]string{"pid": "4294967296"})
	if err == nil {
		t.Fatal("expected error for PID exceeding uint32 max")
	}
}

// ---------------------------------------------------------------------------
// wantOp
// ---------------------------------------------------------------------------

func TestWantOp_NoFilter(t *testing.T) {
	cfg := FilterConfig{}
	if !cfg.wantOp("read") {
		t.Error("no filter should match all ops")
	}
	if !cfg.wantOp("write") {
		t.Error("no filter should match all ops")
	}
}

func TestWantOp_FilterMatch(t *testing.T) {
	cfg := FilterConfig{Ops: []string{"read"}}
	if !cfg.wantOp("read") {
		t.Error("should match filtered op")
	}
}

func TestWantOp_FilterNoMatch(t *testing.T) {
	cfg := FilterConfig{Ops: []string{"read"}}
	if cfg.wantOp("write") {
		t.Error("should not match unfiltered op")
	}
}

func TestWantOp_MultipleOps(t *testing.T) {
	cfg := FilterConfig{Ops: []string{"open", "write"}}
	if !cfg.wantOp("open") {
		t.Error("should match 'open'")
	}
	if !cfg.wantOp("write") {
		t.Error("should match 'write'")
	}
	if cfg.wantOp("read") {
		t.Error("should not match 'read'")
	}
}

// ---------------------------------------------------------------------------
// matchesFilter
// ---------------------------------------------------------------------------

func makeFileEvent(comm, filename string) events.FileEvent {
	var e events.FileEvent
	copy(e.Comm[:], comm)
	e.FileName = filename
	return e
}

func TestMatchesFilter_NoFilter(t *testing.T) {
	mod := &FilesModule{filter: FilterConfig{}}
	if !mod.matchesFilter(makeFileEvent("cat", "passwd")) {
		t.Error("empty filter should match all events")
	}
}

func TestMatchesFilter_CommMatch(t *testing.T) {
	mod := &FilesModule{filter: FilterConfig{CommName: "nginx"}}
	if !mod.matchesFilter(makeFileEvent("nginx", "x")) {
		t.Error("matching comm should pass")
	}
}

func TestMatchesFilter_CommNoMatch(t *testing.T) {
	mod := &FilesModule{filter: FilterConfig{CommName: "nginx"}}
	if mod.matchesFilter(makeFileEvent("bash", "x")) {
		t.Error("non-matching comm should be filtered")
	}
}

func TestMatchesFilter_FileMatch(t *testing.T) {
	mod := &FilesModule{filter: FilterConfig{FileName: "passwd"}}
	if !mod.matchesFilter(makeFileEvent("cat", "/etc/passwd")) {
		t.Error("substring filename match should pass")
	}
}

func TestMatchesFilter_FileNoMatch(t *testing.T) {
	mod := &FilesModule{filter: FilterConfig{FileName: "shadow"}}
	if mod.matchesFilter(makeFileEvent("cat", "/etc/passwd")) {
		t.Error("non-matching filename should be filtered")
	}
}

func TestMatchesFilter_BothFilters(t *testing.T) {
	mod := &FilesModule{filter: FilterConfig{CommName: "cat", FileName: "passwd"}}

	if !mod.matchesFilter(makeFileEvent("cat", "passwd")) {
		t.Error("both matching should pass")
	}
	if mod.matchesFilter(makeFileEvent("cat", "shadow")) {
		t.Error("file mismatch should filter")
	}
	if mod.matchesFilter(makeFileEvent("bash", "passwd")) {
		t.Error("comm mismatch should filter")
	}
}

// ---------------------------------------------------------------------------
// filesToFields
// ---------------------------------------------------------------------------

func TestFilesToFields_AllFieldsPresent(t *testing.T) {
	var e events.FileEvent
	e.Kind = events.KindFileAccess
	e.PID = 5678
	e.TID = 5679
	e.UID = 1000
	e.GID = 1000
	e.Timestamp = 12345
	copy(e.Comm[:], "nginx")
	e.FileName = "nginx.conf"
	e.Op = "open"

	f := filesToFields(e)

	requiredKeys := []string{"kind", "pid", "tid", "uid", "gid", "timestamp", "comm", "op", "filename"}
	for _, k := range requiredKeys {
		if _, ok := f[k]; !ok {
			t.Errorf("missing key %q in filesToFields output", k)
		}
	}

	if f["pid"] != uint32(5678) {
		t.Errorf("pid = %v, want 5678", f["pid"])
	}
	if f["op"] != "open" {
		t.Errorf("op = %v, want 'open'", f["op"])
	}
	if f["filename"] != "nginx.conf" {
		t.Errorf("filename = %v, want 'nginx.conf'", f["filename"])
	}
	if f["kind"] != "file access" {
		t.Errorf("kind = %v, want 'file access'", f["kind"])
	}
}
