package count

import (
	"bytes"
	"strings"
	"sync"
	"testing"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func syscallFields(name string) map[string]interface{} {
	return map[string]interface{}{
		"pid":        uint32(1234),
		"comm":       "bash",
		"syscall":    name,
		"syscall_nr": uint64(257),
	}
}

func fileFields(filename, op string) map[string]interface{} {
	return map[string]interface{}{
		"pid":      uint32(5678),
		"comm":     "cat",
		"filename": filename,
		"op":       op,
	}
}

func networkFields(dport uint16) map[string]interface{} {
	return map[string]interface{}{
		"pid":   uint32(42),
		"comm":  "curl",
		"dport": dport,
		"sport": uint16(54321),
	}
}

// ---------------------------------------------------------------------------
// Basic aggregation
// ---------------------------------------------------------------------------

func TestCountSink_SingleModule(t *testing.T) {
	var buf bytes.Buffer
	cs := NewCountSink(&buf, 10)

	cs.Emit("syscall", syscallFields("openat"))
	cs.Emit("syscall", syscallFields("openat"))
	cs.Emit("syscall", syscallFields("read"))
	cs.Emit("syscall", syscallFields("openat"))
	cs.Emit("syscall", syscallFields("write"))

	snap := cs.Snapshot("syscall")
	if snap["openat"] != 3 {
		t.Errorf("openat count = %d, want 3", snap["openat"])
	}
	if snap["read"] != 1 {
		t.Errorf("read count = %d, want 1", snap["read"])
	}
	if snap["write"] != 1 {
		t.Errorf("write count = %d, want 1", snap["write"])
	}

	total := cs.Total("syscall")
	if total != 5 {
		t.Errorf("total = %d, want 5", total)
	}
}

func TestCountSink_MultipleModules(t *testing.T) {
	var buf bytes.Buffer
	cs := NewCountSink(&buf, 10)

	cs.Emit("syscall", syscallFields("read"))
	cs.Emit("syscall", syscallFields("read"))
	cs.Emit("files", fileFields("/etc/passwd", "read"))
	cs.Emit("network", networkFields(443))
	cs.Emit("network", networkFields(80))
	cs.Emit("network", networkFields(443))

	if cs.Total("syscall") != 2 {
		t.Errorf("syscall total = %d, want 2", cs.Total("syscall"))
	}
	if cs.Total("files") != 1 {
		t.Errorf("files total = %d, want 1", cs.Total("files"))
	}
	if cs.Total("network") != 3 {
		t.Errorf("network total = %d, want 3", cs.Total("network"))
	}

	netSnap := cs.Snapshot("network")
	if netSnap["443"] != 2 {
		t.Errorf("port 443 count = %d, want 2", netSnap["443"])
	}
	if netSnap["80"] != 1 {
		t.Errorf("port 80 count = %d, want 1", netSnap["80"])
	}
}

// ---------------------------------------------------------------------------
// Close output formatting
// ---------------------------------------------------------------------------

func TestCountSink_CloseOutput(t *testing.T) {
	var buf bytes.Buffer
	cs := NewCountSink(&buf, 10)

	cs.Emit("syscall", syscallFields("openat"))
	cs.Emit("syscall", syscallFields("openat"))
	cs.Emit("syscall", syscallFields("read"))

	cs.Close()

	output := buf.String()
	if !strings.Contains(output, "Veil Event Summary") {
		t.Error("output should contain header")
	}
	if !strings.Contains(output, "[syscall]") {
		t.Error("output should contain module name")
	}
	if !strings.Contains(output, "3 events") {
		t.Error("output should contain total count")
	}
	if !strings.Contains(output, "openat") {
		t.Error("output should contain top key 'openat'")
	}
	if !strings.Contains(output, "read") {
		t.Error("output should contain key 'read'")
	}
}

func TestCountSink_CloseOutputSorted(t *testing.T) {
	var buf bytes.Buffer
	cs := NewCountSink(&buf, 10)

	/* openat should be first (3), read second (2), write third (1) */
	cs.Emit("syscall", syscallFields("write"))
	cs.Emit("syscall", syscallFields("read"))
	cs.Emit("syscall", syscallFields("openat"))
	cs.Emit("syscall", syscallFields("read"))
	cs.Emit("syscall", syscallFields("openat"))
	cs.Emit("syscall", syscallFields("openat"))

	cs.Close()

	output := buf.String()
	openatIdx := strings.Index(output, "openat")
	readIdx := strings.Index(output, "read")
	writeIdx := strings.Index(output, "write")

	if openatIdx < 0 || readIdx < 0 || writeIdx < 0 {
		t.Fatalf("missing entries in output: %q", output)
	}

	if openatIdx > readIdx {
		t.Error("openat (3) should appear before read (2)")
	}
	if readIdx > writeIdx {
		t.Error("read (2) should appear before write (1)")
	}
}

// ---------------------------------------------------------------------------
// Top-N limiting
// ---------------------------------------------------------------------------

func TestCountSink_TopNLimit(t *testing.T) {
	var buf bytes.Buffer
	cs := NewCountSink(&buf, 2)

	cs.Emit("syscall", syscallFields("openat"))
	cs.Emit("syscall", syscallFields("openat"))
	cs.Emit("syscall", syscallFields("openat"))
	cs.Emit("syscall", syscallFields("read"))
	cs.Emit("syscall", syscallFields("read"))
	cs.Emit("syscall", syscallFields("write"))
	cs.Emit("syscall", syscallFields("close"))
	cs.Emit("syscall", syscallFields("mmap"))

	cs.Close()

	output := buf.String()
	/* Should show openat and read (top 2), and mention the remaining 3 */
	if !strings.Contains(output, "openat") {
		t.Error("top-1 entry 'openat' should be present")
	}
	if !strings.Contains(output, "read") {
		t.Error("top-2 entry 'read' should be present")
	}
	if !strings.Contains(output, "3 more") {
		t.Errorf("should mention 3 more unique keys: %q", output)
	}
}

// ---------------------------------------------------------------------------
// Default key fields per module
// ---------------------------------------------------------------------------

func TestCountSink_DefaultKeyField_Syscall(t *testing.T) {
	var buf bytes.Buffer
	cs := NewCountSink(&buf, 10)

	cs.Emit("syscall", syscallFields("openat"))
	snap := cs.Snapshot("syscall")
	if snap["openat"] != 1 {
		t.Errorf("expected key 'openat', got snapshot: %v", snap)
	}
}

func TestCountSink_DefaultKeyField_Files(t *testing.T) {
	var buf bytes.Buffer
	cs := NewCountSink(&buf, 10)

	cs.Emit("files", fileFields("/etc/passwd", "read"))
	cs.Emit("files", fileFields("/etc/passwd", "write"))
	cs.Emit("files", fileFields("/var/log/syslog", "read"))

	snap := cs.Snapshot("files")
	if snap["/etc/passwd"] != 2 {
		t.Errorf("/etc/passwd count = %d, want 2", snap["/etc/passwd"])
	}
	if snap["/var/log/syslog"] != 1 {
		t.Errorf("/var/log/syslog count = %d, want 1", snap["/var/log/syslog"])
	}
}

func TestCountSink_DefaultKeyField_Network(t *testing.T) {
	var buf bytes.Buffer
	cs := NewCountSink(&buf, 10)

	cs.Emit("network", networkFields(443))
	cs.Emit("network", networkFields(443))
	cs.Emit("network", networkFields(80))

	snap := cs.Snapshot("network")
	if snap["443"] != 2 {
		t.Errorf("port 443 count = %d, want 2", snap["443"])
	}
}

// ---------------------------------------------------------------------------
// WithKeyField override
// ---------------------------------------------------------------------------

func TestCountSink_WithKeyField(t *testing.T) {
	var buf bytes.Buffer
	cs := NewCountSink(&buf, 10).WithKeyField("comm")

	cs.Emit("syscall", syscallFields("openat"))
	cs.Emit("syscall", syscallFields("read"))

	/* Both events have comm="bash", so they should be aggregated together */
	snap := cs.Snapshot("syscall")
	if snap["bash"] != 2 {
		t.Errorf("expected key 'bash' with count 2, got snapshot: %v", snap)
	}
}

func TestCountSink_WithKeyFieldAppliesToAllModules(t *testing.T) {
	var buf bytes.Buffer
	cs := NewCountSink(&buf, 10).WithKeyField("comm")

	cs.Emit("syscall", syscallFields("openat"))
	cs.Emit("files", fileFields("/etc/passwd", "read"))
	cs.Emit("network", networkFields(443))

	if cs.Snapshot("syscall")["bash"] != 1 {
		t.Error("syscall should be keyed by comm")
	}
	if cs.Snapshot("files")["cat"] != 1 {
		t.Error("files should be keyed by comm")
	}
	if cs.Snapshot("network")["curl"] != 1 {
		t.Error("network should be keyed by comm")
	}
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

func TestCountSink_EmptyClose(t *testing.T) {
	var buf bytes.Buffer
	cs := NewCountSink(&buf, 10)

	err := cs.Close()
	if err != nil {
		t.Fatalf("Close: %v", err)
	}

	/* No events, should produce no output */
	if buf.Len() != 0 {
		t.Errorf("expected empty output for no events, got %q", buf.String())
	}
}

func TestCountSink_SnapshotEmpty(t *testing.T) {
	cs := NewCountSink(nil, 10)
	snap := cs.Snapshot("nonexistent")
	if snap != nil {
		t.Errorf("expected nil for nonexistent module, got %v", snap)
	}
}

func TestCountSink_TotalEmpty(t *testing.T) {
	cs := NewCountSink(nil, 10)
	if cs.Total("nonexistent") != 0 {
		t.Error("expected 0 for nonexistent module")
	}
}

func TestCountSink_MissingKeyField(t *testing.T) {
	var buf bytes.Buffer
	cs := NewCountSink(&buf, 10)

	/* Event with no "syscall" field — should fall back to "comm" */
	cs.Emit("syscall", map[string]interface{}{
		"pid":  uint32(1),
		"comm": "mystery",
	})

	snap := cs.Snapshot("syscall")
	if snap["mystery"] != 1 {
		t.Errorf("expected fallback to comm: got %v", snap)
	}
}

func TestCountSink_MissingKeyFieldAndComm(t *testing.T) {
	var buf bytes.Buffer
	cs := NewCountSink(&buf, 10)

	/* Event with neither the default key field nor "comm" */
	cs.Emit("syscall", map[string]interface{}{
		"pid": uint32(1),
	})

	snap := cs.Snapshot("syscall")
	if snap["(unknown)"] != 1 {
		t.Errorf("expected '(unknown)' key: got %v", snap)
	}
}

func TestCountSink_UnknownModuleFallsBackToComm(t *testing.T) {
	var buf bytes.Buffer
	cs := NewCountSink(&buf, 10)

	cs.Emit("scheduler", map[string]interface{}{
		"pid":  uint32(1),
		"comm": "kworker",
	})

	snap := cs.Snapshot("scheduler")
	if snap["kworker"] != 1 {
		t.Errorf("unknown module should use comm as key: got %v", snap)
	}
}

func TestCountSink_NegativeTopN(t *testing.T) {
	/* Should default to 10 */
	cs := NewCountSink(nil, -5)
	if cs.topN != 10 {
		t.Errorf("negative topN should default to 10, got %d", cs.topN)
	}
}

func TestCountSink_ZeroTopN(t *testing.T) {
	cs := NewCountSink(nil, 0)
	if cs.topN != 10 {
		t.Errorf("zero topN should default to 10, got %d", cs.topN)
	}
}

// ---------------------------------------------------------------------------
// Percentage formatting
// ---------------------------------------------------------------------------

func TestCountSink_PercentageInOutput(t *testing.T) {
	var buf bytes.Buffer
	cs := NewCountSink(&buf, 10)

	for i := 0; i < 75; i++ {
		cs.Emit("syscall", syscallFields("openat"))
	}
	for i := 0; i < 25; i++ {
		cs.Emit("syscall", syscallFields("read"))
	}

	cs.Close()

	output := buf.String()
	if !strings.Contains(output, "75.0%") {
		t.Errorf("expected 75.0%% for openat: %q", output)
	}
	if !strings.Contains(output, "25.0%") {
		t.Errorf("expected 25.0%% for read: %q", output)
	}
}

// ---------------------------------------------------------------------------
// Concurrency safety
// ---------------------------------------------------------------------------

func TestCountSink_ConcurrentEmit(t *testing.T) {
	var buf bytes.Buffer
	cs := NewCountSink(&buf, 10)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				cs.Emit("syscall", syscallFields("openat"))
			}
		}()
	}
	wg.Wait()

	if cs.Total("syscall") != 10000 {
		t.Errorf("total = %d, want 10000", cs.Total("syscall"))
	}

	snap := cs.Snapshot("syscall")
	if snap["openat"] != 10000 {
		t.Errorf("openat = %d, want 10000", snap["openat"])
	}
}

// ---------------------------------------------------------------------------
// Multi-module Close output
// ---------------------------------------------------------------------------

func TestCountSink_MultiModuleCloseOutput(t *testing.T) {
	var buf bytes.Buffer
	cs := NewCountSink(&buf, 10)

	cs.Emit("files", fileFields("/etc/passwd", "read"))
	cs.Emit("network", networkFields(443))
	cs.Emit("syscall", syscallFields("openat"))

	cs.Close()

	output := buf.String()
	/* Modules should appear alphabetically */
	filesIdx := strings.Index(output, "[files]")
	networkIdx := strings.Index(output, "[network]")
	syscallIdx := strings.Index(output, "[syscall]")

	if filesIdx < 0 || networkIdx < 0 || syscallIdx < 0 {
		t.Fatalf("missing module headers: %q", output)
	}
	if filesIdx > networkIdx || networkIdx > syscallIdx {
		t.Error("modules should be sorted alphabetically")
	}
}

// ---------------------------------------------------------------------------
// keyFieldFor
// ---------------------------------------------------------------------------

func TestKeyFieldFor_Defaults(t *testing.T) {
	cs := NewCountSink(nil, 10)

	if f := cs.keyFieldFor("syscall"); f != "syscall" {
		t.Errorf("syscall key field = %q, want %q", f, "syscall")
	}
	if f := cs.keyFieldFor("files"); f != "filename" {
		t.Errorf("files key field = %q, want %q", f, "filename")
	}
	if f := cs.keyFieldFor("network"); f != "dport" {
		t.Errorf("network key field = %q, want %q", f, "dport")
	}
	if f := cs.keyFieldFor("unknown"); f != "comm" {
		t.Errorf("unknown key field = %q, want %q", f, "comm")
	}
}

func TestKeyFieldFor_Override(t *testing.T) {
	cs := NewCountSink(nil, 10).WithKeyField("pid")

	if f := cs.keyFieldFor("syscall"); f != "pid" {
		t.Errorf("overridden key field = %q, want %q", f, "pid")
	}
	if f := cs.keyFieldFor("unknown"); f != "pid" {
		t.Errorf("overridden key field for unknown = %q, want %q", f, "pid")
	}
}

// ---------------------------------------------------------------------------
// ValidateKeyField
// ---------------------------------------------------------------------------

func TestValidateKeyField_ValidCommon(t *testing.T) {
	validFields := []string{"pid", "tid", "uid", "gid", "timestamp", "comm", "kind"}
	for _, f := range validFields {
		if err := ValidateKeyField(f); err != nil {
			t.Errorf("ValidateKeyField(%q) unexpected error: %v", f, err)
		}
	}
}

func TestValidateKeyField_ValidModuleSpecific(t *testing.T) {
	validFields := []string{
		"syscall", "syscall_nr",
		"filename", "op",
		"saddr", "daddr", "sport", "dport", "evt_type", "oldstate", "newstate",
	}
	for _, f := range validFields {
		if err := ValidateKeyField(f); err != nil {
			t.Errorf("ValidateKeyField(%q) unexpected error: %v", f, err)
		}
	}
}

func TestValidateKeyField_Invalid(t *testing.T) {
	invalidFields := []string{"portt", "process", "name", "srcport", "bogus", ""}
	for _, f := range invalidFields {
		if err := ValidateKeyField(f); err == nil {
			t.Errorf("ValidateKeyField(%q) should have returned error", f)
		}
	}
}

func TestValidateKeyField_ErrorMessage(t *testing.T) {
	err := ValidateKeyField("bogus")
	if err == nil {
		t.Fatal("expected error")
	}
	errMsg := err.Error()
	if !strings.Contains(errMsg, "bogus") {
		t.Errorf("error should mention the invalid field: %q", errMsg)
	}
	if !strings.Contains(errMsg, "valid fields") {
		t.Errorf("error should list valid fields: %q", errMsg)
	}
}
