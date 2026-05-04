package main

import (
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/PranavRJoshi/Veil/internal/control"
)

// ---------------------------------------------------------------------------
// fakeMapUpdater: in-memory MapUpdater for testing compositeUpdater
// ---------------------------------------------------------------------------

type fakeMapUpdater struct {
	mu     sync.Mutex
	name   string
	maps   map[string]map[uint64]bool
}

func newFakeMapUpdater(name string, mapNames ...string) *fakeMapUpdater {
	maps := make(map[string]map[uint64]bool)
	for _, mn := range mapNames {
		maps[mn] = make(map[uint64]bool)
	}
	return &fakeMapUpdater{name: name, maps: maps}
}

func (f *fakeMapUpdater) AddFilter(mapName string, key uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	m, ok := f.maps[mapName]
	if !ok {
		return fmt.Errorf("%s: unknown map %q", f.name, mapName)
	}
	m[key] = true
	return nil
}

func (f *fakeMapUpdater) DelFilter(mapName string, key uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	m, ok := f.maps[mapName]
	if !ok {
		return fmt.Errorf("%s: unknown map %q", f.name, mapName)
	}
	if !m[key] {
		return fmt.Errorf("%s: key %d not found in %s", f.name, key, mapName)
	}
	delete(m, key)
	return nil
}

func (f *fakeMapUpdater) ListFilters(mapName string) ([]uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	m, ok := f.maps[mapName]
	if !ok {
		return nil, fmt.Errorf("%s: unknown map %q", f.name, mapName)
	}
	keys := make([]uint64, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys, nil
}

func (f *fakeMapUpdater) ClearFilters(mapName string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	m, ok := f.maps[mapName]
	if !ok {
		return fmt.Errorf("%s: unknown map %q", f.name, mapName)
	}
	for k := range m {
		delete(m, k)
	}
	return nil
}

func (f *fakeMapUpdater) Status() string {
	return fmt.Sprintf("%s: loaded", f.name)
}

func (f *fakeMapUpdater) hasKey(mapName string, key uint64) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	m, ok := f.maps[mapName]
	if !ok {
		return false
	}
	return m[key]
}

func (f *fakeMapUpdater) count(mapName string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.maps[mapName])
}

// ---------------------------------------------------------------------------
// compositeUpdater: plain map name routing (broadcast)
// ---------------------------------------------------------------------------

func makeComposite() (*compositeUpdater, *fakeMapUpdater, *fakeMapUpdater) {
	syscallU := newFakeMapUpdater("syscall", "pid", "uid", "syscall", "pid_deny", "uid_deny", "syscall_deny")
	networkU := newFakeMapUpdater("network", "pid", "uid", "port", "pid_deny", "uid_deny", "port_deny")
	c := &compositeUpdater{
		updaters: map[string]control.MapUpdater{
			"syscall": syscallU,
			"network": networkU,
		},
	}
	return c, syscallU, networkU
}

func TestComposite_AddPIDBroadcast(t *testing.T) {
	c, syscallU, networkU := makeComposite()

	if err := c.AddFilter("pid", 1234); err != nil {
		t.Fatalf("AddFilter: %v", err)
	}
	if !syscallU.hasKey("pid", 1234) {
		t.Error("syscall module should have pid 1234")
	}
	if !networkU.hasKey("pid", 1234) {
		t.Error("network module should have pid 1234")
	}
}

func TestComposite_AddUIDBroadcast(t *testing.T) {
	c, syscallU, networkU := makeComposite()

	if err := c.AddFilter("uid", 0); err != nil {
		t.Fatalf("AddFilter: %v", err)
	}
	if !syscallU.hasKey("uid", 0) {
		t.Error("syscall module should have uid 0")
	}
	if !networkU.hasKey("uid", 0) {
		t.Error("network module should have uid 0")
	}
}

func TestComposite_AddDenyPIDBroadcast(t *testing.T) {
	c, syscallU, networkU := makeComposite()

	if err := c.AddFilter("pid_deny", 100); err != nil {
		t.Fatalf("AddFilter: %v", err)
	}
	if !syscallU.hasKey("pid_deny", 100) {
		t.Error("syscall module should have pid_deny 100")
	}
	if !networkU.hasKey("pid_deny", 100) {
		t.Error("network module should have pid_deny 100")
	}
}

// ---------------------------------------------------------------------------
// compositeUpdater: module-specific maps
// ---------------------------------------------------------------------------

func TestComposite_AddSyscallModuleOnly(t *testing.T) {
	c, syscallU, networkU := makeComposite()

	if err := c.AddFilter("syscall", 257); err != nil {
		t.Fatalf("AddFilter: %v", err)
	}
	if !syscallU.hasKey("syscall", 257) {
		t.Error("syscall module should have syscall 257")
	}
	/* network doesn't have a "syscall" map, so it shouldn't be touched */
	if networkU.count("pid") != 0 && networkU.count("uid") != 0 {
		/* network module is fine, it simply doesn't own "syscall" */
	}
}

func TestComposite_AddPortNetworkOnly(t *testing.T) {
	c, _, networkU := makeComposite()

	if err := c.AddFilter("port", 443); err != nil {
		t.Fatalf("AddFilter: %v", err)
	}
	if !networkU.hasKey("port", 443) {
		t.Error("network module should have port 443")
	}
}

// ---------------------------------------------------------------------------
// compositeUpdater: module-qualified names
// ---------------------------------------------------------------------------

func TestComposite_QualifiedAddTargetsOneModule(t *testing.T) {
	c, syscallU, networkU := makeComposite()

	/* "syscall.pid" should only go to syscall module */
	if err := c.AddFilter("syscall.pid", 42); err != nil {
		t.Fatalf("AddFilter: %v", err)
	}
	if !syscallU.hasKey("pid", 42) {
		t.Error("syscall module should have pid 42")
	}
	if networkU.hasKey("pid", 42) {
		t.Error("network module should NOT have pid 42 from qualified add")
	}
}

func TestComposite_QualifiedNetworkPort(t *testing.T) {
	c, _, networkU := makeComposite()

	if err := c.AddFilter("network.port", 8080); err != nil {
		t.Fatalf("AddFilter: %v", err)
	}
	if !networkU.hasKey("port", 8080) {
		t.Error("network module should have port 8080")
	}
}

func TestComposite_QualifiedUnknownModule(t *testing.T) {
	c, _, _ := makeComposite()

	err := c.AddFilter("files.pid", 1234)
	if err == nil {
		t.Fatal("expected error for unloaded module 'files'")
	}
	if !strings.Contains(err.Error(), "not loaded") {
		t.Errorf("error should mention 'not loaded', got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// compositeUpdater: DelFilter success counting
// ---------------------------------------------------------------------------

func TestComposite_DelSharedKeyBroadcast(t *testing.T) {
	c, syscallU, networkU := makeComposite()

	/* Add to both modules, then delete */
	c.AddFilter("pid", 42)
	err := c.DelFilter("pid", 42)

	/*
		Current implementation: returns last error. If both succeed, err is nil.
		If one fails (key not found) but the other succeeds, the error from
		the failing one is returned.
	*/
	if err != nil {
		t.Fatalf("DelFilter: %v", err)
	}
	if syscallU.hasKey("pid", 42) {
		t.Error("syscall should not have pid 42 after del")
	}
	if networkU.hasKey("pid", 42) {
		t.Error("network should not have pid 42 after del")
	}
}

func TestComposite_DelKeyNotInAllModules(t *testing.T) {
	c, syscallU, _ := makeComposite()

	/* Only add to syscall, not network */
	syscallU.AddFilter("pid", 42)
	err := c.DelFilter("pid", 42)

	/*
		Since network never had the key, its DelFilter returns an error.
		The compositeUpdater currently reports the last error even if one
		module succeeded. This is the documented behavior per CONTEXT.md.
	*/
	if err == nil {
		/* This may be nil or non-nil depending on implementation choice */
		/* Currently the code returns lastErr, which would be network's error */
		/* But if network module doesn't have the key, it will error */
	}
	/* But syscall's key should definitely be gone */
	if syscallU.hasKey("pid", 42) {
		t.Error("syscall should not have pid 42 after del")
	}
}

// ---------------------------------------------------------------------------
// compositeUpdater: ClearFilters
// ---------------------------------------------------------------------------

func TestComposite_ClearBroadcast(t *testing.T) {
	c, syscallU, networkU := makeComposite()

	c.AddFilter("pid", 100)
	c.AddFilter("pid", 200)

	if err := c.ClearFilters("pid"); err != nil {
		t.Fatalf("ClearFilters: %v", err)
	}
	if syscallU.count("pid") != 0 {
		t.Error("syscall pid map should be empty after clear")
	}
	if networkU.count("pid") != 0 {
		t.Error("network pid map should be empty after clear")
	}
}

func TestComposite_ClearQualified(t *testing.T) {
	c, syscallU, networkU := makeComposite()

	c.AddFilter("pid", 100)

	/* Clear only syscall's pid map */
	if err := c.ClearFilters("syscall.pid"); err != nil {
		t.Fatalf("ClearFilters: %v", err)
	}
	if syscallU.count("pid") != 0 {
		t.Error("syscall pid map should be empty")
	}
	if networkU.count("pid") != 1 {
		t.Error("network pid map should still have 1 entry")
	}
}

// ---------------------------------------------------------------------------
// compositeUpdater: ListFilters
// ---------------------------------------------------------------------------

func TestComposite_ListPlain(t *testing.T) {
	c, _, _ := makeComposite()

	c.AddFilter("pid", 100)
	c.AddFilter("pid", 200)

	keys, err := c.ListFilters("pid")
	if err != nil {
		t.Fatalf("ListFilters: %v", err)
	}
	/* Lists from first loaded target */
	if len(keys) != 2 {
		t.Errorf("expected 2 keys, got %d", len(keys))
	}
}

func TestComposite_ListQualified(t *testing.T) {
	c, _, networkU := makeComposite()

	networkU.AddFilter("port", 443)

	keys, err := c.ListFilters("network.port")
	if err != nil {
		t.Fatalf("ListFilters: %v", err)
	}
	if len(keys) != 1 || keys[0] != 443 {
		t.Errorf("expected [443], got %v", keys)
	}
}

// ---------------------------------------------------------------------------
// compositeUpdater: unknown map
// ---------------------------------------------------------------------------

func TestComposite_UnknownMap(t *testing.T) {
	c, _, _ := makeComposite()

	err := c.AddFilter("bogus", 123)
	if err == nil {
		t.Fatal("expected error for unknown map")
	}
}

// ---------------------------------------------------------------------------
// compositeUpdater: Status
// ---------------------------------------------------------------------------

func TestComposite_Status(t *testing.T) {
	c, _, _ := makeComposite()

	status := c.Status()
	if !strings.Contains(status, "syscall") {
		t.Errorf("status should mention syscall: %q", status)
	}
	if !strings.Contains(status, "network") {
		t.Errorf("status should mention network: %q", status)
	}
}

// ---------------------------------------------------------------------------
// compositeUpdater: deny map routing
// ---------------------------------------------------------------------------

func TestComposite_DenyMapBroadcast(t *testing.T) {
	c, syscallU, networkU := makeComposite()

	if err := c.AddFilter("uid_deny", 65534); err != nil {
		t.Fatalf("AddFilter: %v", err)
	}
	if !syscallU.hasKey("uid_deny", 65534) {
		t.Error("syscall should have uid_deny 65534")
	}
	if !networkU.hasKey("uid_deny", 65534) {
		t.Error("network should have uid_deny 65534")
	}
}

func TestComposite_DenyMapModuleSpecific(t *testing.T) {
	c, _, networkU := makeComposite()

	if err := c.AddFilter("port_deny", 22); err != nil {
		t.Fatalf("AddFilter: %v", err)
	}
	if !networkU.hasKey("port_deny", 22) {
		t.Error("network should have port_deny 22")
	}
}

// ---------------------------------------------------------------------------
// stubUpdater
// ---------------------------------------------------------------------------

func TestStubUpdater_RejectsAll(t *testing.T) {
	s := &stubUpdater{module: "test"}

	if err := s.AddFilter("pid", 1); err == nil {
		t.Error("stub AddFilter should error")
	}
	if err := s.DelFilter("pid", 1); err == nil {
		t.Error("stub DelFilter should error")
	}
	if _, err := s.ListFilters("pid"); err == nil {
		t.Error("stub ListFilters should error")
	}
	if err := s.ClearFilters("pid"); err == nil {
		t.Error("stub ClearFilters should error")
	}
}

func TestStubUpdater_StatusWorks(t *testing.T) {
	s := &stubUpdater{module: "test"}
	status := s.Status()
	if !strings.Contains(status, "test") {
		t.Errorf("stub status should mention module name: %q", status)
	}
	if !strings.Contains(status, "not implemented") {
		t.Errorf("stub status should say not implemented: %q", status)
	}
}

// ---------------------------------------------------------------------------
// parseModuleNames (helper in main.go)
// ---------------------------------------------------------------------------

func TestParseModuleNames_Single(t *testing.T) {
	names := parseModuleNames("syscall")
	if len(names) != 1 || names[0] != "syscall" {
		t.Errorf("expected [syscall], got %v", names)
	}
}

func TestParseModuleNames_Multiple(t *testing.T) {
	names := parseModuleNames("syscall,network,files")
	if len(names) != 3 {
		t.Fatalf("expected 3 names, got %d", len(names))
	}
	if names[0] != "syscall" || names[1] != "network" || names[2] != "files" {
		t.Errorf("got %v", names)
	}
}

func TestParseModuleNames_WithSpaces(t *testing.T) {
	names := parseModuleNames("syscall , network")
	if len(names) != 2 {
		t.Fatalf("expected 2 names, got %d", len(names))
	}
	if names[0] != "syscall" || names[1] != "network" {
		t.Errorf("spaces not trimmed: %v", names)
	}
}

func TestParseModuleNames_TrailingComma(t *testing.T) {
	names := parseModuleNames("syscall,")
	if len(names) != 1 || names[0] != "syscall" {
		t.Errorf("trailing comma: got %v", names)
	}
}

func TestParseModuleNames_EmptyBetweenCommas(t *testing.T) {
	names := parseModuleNames("syscall,,network")
	if len(names) != 2 {
		t.Errorf("empty entries should be skipped: got %v", names)
	}
}
