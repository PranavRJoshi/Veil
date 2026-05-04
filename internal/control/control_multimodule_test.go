package control

import (
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Handler: 4-part module-qualified commands
//
// The Handler converts 4-part commands into "module.map" qualified names
// before passing them to the MapUpdater. These tests verify that conversion
// and the round-trip through the updater.
// ---------------------------------------------------------------------------

/*
	qualifiedFakeUpdater extends fakeUpdater to accept module-qualified
	map names (e.g. "network.port") as the compositeUpdater produces.

	fakeUpdater is defined in control_test.go file.
*/
type qualifiedFakeUpdater struct {
	fakeUpdater
}

func newQualifiedFakeUpdater() *qualifiedFakeUpdater {
	return &qualifiedFakeUpdater{
		fakeUpdater: fakeUpdater{
			maps: map[string]map[uint64]bool{
				"pid":            {},
				"uid":            {},
				"port":           {},
				"syscall":        {},
				"pid_deny":       {},
				"uid_deny":       {},
				"port_deny":      {},
				"syscall_deny":   {},
				"network.port":   {},
				"syscall.pid":    {},
				"network.pid":    {},
			},
		},
	}
}

func TestHandler_FourPartAdd(t *testing.T) {
	h := NewHandler(newQualifiedFakeUpdater())

	resp := h.HandleCommand("add network port 443")
	if resp != "OK" {
		t.Errorf("4-part add: got %q, want OK", resp)
	}
}

func TestHandler_FourPartDel(t *testing.T) {
	u := newQualifiedFakeUpdater()
	h := NewHandler(u)

	h.HandleCommand("add network port 443")
	resp := h.HandleCommand("del network port 443")
	if resp != "OK" {
		t.Errorf("4-part del: got %q, want OK", resp)
	}
}

func TestHandler_ThreePartList(t *testing.T) {
	u := newQualifiedFakeUpdater()
	h := NewHandler(u)

	h.HandleCommand("add network port 80")
	resp := h.HandleCommand("list network port")
	if resp != "80" {
		t.Errorf("4-part list: got %q, want %q", resp, "80")
	}
}

func TestHandler_ThreePartClear(t *testing.T) {
	u := newQualifiedFakeUpdater()
	h := NewHandler(u)

	h.HandleCommand("add network port 80")
	h.HandleCommand("add network port 443")
	resp := h.HandleCommand("clear network port")
	if resp != "OK" {
		t.Errorf("4-part clear: got %q, want OK", resp)
	}
	resp = h.HandleCommand("list network port")
	if resp != "(empty)" {
		t.Errorf("list after clear: got %q, want (empty)", resp)
	}
}

func TestHandler_FourPartModuleQualification(t *testing.T) {
	/*
		Verify that "add network port 443" passes "network.port" as the
		map name to the updater, not just "port".
	*/
	u := newQualifiedFakeUpdater()
	h := NewHandler(u)

	resp := h.HandleCommand("add network port 443")
	if resp != "OK" {
		t.Fatalf("4-part add: got %q, want OK", resp)
	}

	/* The key should be in "network.port", not in "port" */
	u.mu.Lock()
	if !u.maps["network.port"][443] {
		t.Error("key 443 should be in 'network.port' map")
	}
	if u.maps["port"][443] {
		t.Error("key 443 should NOT be in plain 'port' map")
	}
	u.mu.Unlock()
}

func TestHandler_FourPartAddModulePid(t *testing.T) {
	/*
		Verify that "add syscall pid 1234" targets "syscall.pid" map,
		distinct from plain "pid".
	*/
	u := newQualifiedFakeUpdater()
	h := NewHandler(u)

	resp := h.HandleCommand("add syscall pid 1234")
	if resp != "OK" {
		t.Fatalf("got %q, want OK", resp)
	}

	u.mu.Lock()
	if !u.maps["syscall.pid"][1234] {
		t.Error("key 1234 should be in 'syscall.pid' map")
	}
	if u.maps["pid"][1234] {
		t.Error("key 1234 should NOT be in plain 'pid' map")
	}
	u.mu.Unlock()
}

// ---------------------------------------------------------------------------
// Handler: deny map names via 3-part commands
// ---------------------------------------------------------------------------

func TestHandler_DenyMapAdd(t *testing.T) {
	u := newQualifiedFakeUpdater()
	h := NewHandler(u)

	resp := h.HandleCommand("add pid_deny 100")
	if resp != "OK" {
		t.Errorf("add pid_deny: got %q, want OK", resp)
	}

	u.mu.Lock()
	if !u.maps["pid_deny"][100] {
		t.Error("key 100 should be in pid_deny map")
	}
	u.mu.Unlock()
}

func TestHandler_DenyMapList(t *testing.T) {
	u := newQualifiedFakeUpdater()
	h := NewHandler(u)

	h.HandleCommand("add uid_deny 1000")
	resp := h.HandleCommand("list uid_deny")
	if resp != "1000" {
		t.Errorf("list uid_deny: got %q, want %q", resp, "1000")
	}
}

func TestHandler_DenyMapDel(t *testing.T) {
	u := newQualifiedFakeUpdater()
	h := NewHandler(u)

	h.HandleCommand("add syscall_deny 257")
	resp := h.HandleCommand("del syscall_deny 257")
	if resp != "OK" {
		t.Errorf("del syscall_deny: got %q, want OK", resp)
	}
	resp = h.HandleCommand("list syscall_deny")
	if resp != "(empty)" {
		t.Errorf("list after del: got %q, want (empty)", resp)
	}
}

func TestHandler_DenyMapClear(t *testing.T) {
	u := newQualifiedFakeUpdater()
	h := NewHandler(u)

	h.HandleCommand("add port_deny 22")
	h.HandleCommand("add port_deny 23")
	resp := h.HandleCommand("clear port_deny")
	if resp != "OK" {
		t.Errorf("clear port_deny: got %q, want OK", resp)
	}
	resp = h.HandleCommand("list port_deny")
	if resp != "(empty)" {
		t.Errorf("list after clear: got %q, want (empty)", resp)
	}
}

// ---------------------------------------------------------------------------
// Handler: edge cases for argument counts
// ---------------------------------------------------------------------------

func TestHandler_FivePartArgsError(t *testing.T) {
	h := NewHandler(newQualifiedFakeUpdater())

	/* 5 parts should be rejected for all commands */
	resp := h.HandleCommand("add network port 443 extra")
	if !strings.HasPrefix(resp, "ERR") {
		t.Errorf("5-part add: got %q, want ERR", resp)
	}
}

func TestHandler_TwoPartListClear(t *testing.T) {
	h := NewHandler(newQualifiedFakeUpdater())

	/* 2-part list should work (3-part form) */
	resp := h.HandleCommand("list pid")
	if resp != "(empty)" {
		t.Errorf("list pid: got %q, want (empty)", resp)
	}

	/* 2-part clear should work */
	resp = h.HandleCommand("clear pid")
	if resp != "OK" {
		t.Errorf("clear pid: got %q, want OK", resp)
	}
}

// ---------------------------------------------------------------------------
// Interactive: deny map commands round-trip
// ---------------------------------------------------------------------------

func TestInteractive_DenyMapRoundTrip(t *testing.T) {
	u := newQualifiedFakeUpdater()
	h := NewHandler(u)
	input := strings.NewReader("add pid_deny 42\nlist pid_deny\nquit\n")
	var out strings.Builder

	Interactive(h, input, &out)

	output := out.String()
	if !strings.Contains(output, "OK") {
		t.Errorf("output should contain OK: %q", output)
	}
	if !strings.Contains(output, "42") {
		t.Errorf("output should contain listed key 42: %q", output)
	}
}

func TestInteractive_FourPartRoundTrip(t *testing.T) {
	u := newQualifiedFakeUpdater()
	h := NewHandler(u)
	input := strings.NewReader("add network port 8080\nlist network port\nresume\n")
	var out strings.Builder

	result := Interactive(h, input, &out)
	if result != ResultResume {
		t.Errorf("expected ResultResume, got %d", result)
	}

	output := out.String()
	if !strings.Contains(output, "OK") {
		t.Errorf("output should contain OK: %q", output)
	}
	if !strings.Contains(output, "8080") {
		t.Errorf("output should contain listed key 8080: %q", output)
	}
}

// ---------------------------------------------------------------------------
// Handler: case insensitivity
// ---------------------------------------------------------------------------

func TestHandler_CaseInsensitiveCommands(t *testing.T) {
	u := newQualifiedFakeUpdater()
	h := NewHandler(u)

	resp := h.HandleCommand("ADD pid 42")
	if resp != "OK" {
		t.Errorf("uppercase ADD: got %q, want OK", resp)
	}

	resp = h.HandleCommand("HELP")
	if !strings.Contains(resp, "Veil control commands") {
		t.Errorf("uppercase HELP should work, got %q", resp)
	}

	resp = h.HandleCommand("STATUS")
	if resp != "test-status: ok" {
		t.Errorf("uppercase STATUS: got %q, want %q", resp, "test-status: ok")
	}
}
