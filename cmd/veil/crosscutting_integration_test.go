//go:build integration && linux

package main

/*
	Cross-cutting integration tests: the wiring main() performs, exercised
	against a real kernel rather than the fakes in runner_test.go and
	main_test.go.

	These live in package main because buildUpdater and compositeUpdater are
	unexported here. Driving them from an external package would mean
	re-deriving the composite, which is testing a copy of the routing rather
	than the routing itself.

	The modules register themselves through the blank imports in main.go,
	which are compiled into this same package, so the registry is populated.
*/

import (
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/PranavRJoshi/Veil/internal/control"
	"github.com/PranavRJoshi/Veil/internal/registry"
	"github.com/PranavRJoshi/Veil/internal/runner"
	"github.com/PranavRJoshi/Veil/internal/testutil"
)

func selfPID() uint32 { return uint32(os.Getpid()) }

/*
	buildModules constructs each named module through its registry factory,
	the same path main() takes, sharing one sink. flags is passed to every
	factory; each reads only the keys it understands.
*/
func buildModules(t *testing.T, sink *testutil.CaptureSink, flags map[string]string, names ...string) []runner.Module {
	t.Helper()

	mods := make([]runner.Module, 0, len(names))
	for _, name := range names {
		info, ok := registry.Get(name)
		if !ok {
			t.Fatalf("module %q not registered", name)
		}
		mod, err := info.Factory(flags, sink)
		if err != nil {
			t.Fatalf("factory %q: %v", name, err)
		}
		mods = append(mods, mod)
	}
	return mods
}

/*
	Two modules loaded together must interleave onto the one shared sink.
	Opening a file triggers both the files kprobes and the syscall
	tracepoint, so a single workload should surface events tagged with each
	module name.
*/
func TestIntegrationMultiModuleSharedSink(t *testing.T) {
	testutil.RequireBPF(t)

	sink := testutil.NewCaptureSink()
	flags := map[string]string{"pid": strconv.FormatUint(uint64(selfPID()), 10)}
	mods := buildModules(t, sink, flags, "syscall", "files")

	mr := runner.New(mods...)
	if err := mr.LoadAll(); err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	defer mr.CloseAll()

	done := make(chan struct{})
	go mr.RunAll(done)
	defer close(done)

	/* One workload that both modules observe. */
	path := t.TempDir() + "/veil-multimod.txt"
	if err := os.WriteFile(path, []byte("multi\n"), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := os.ReadFile(path); err != nil {
		t.Fatalf("read: %v", err)
	}

	fromModule := func(name string) func(testutil.Captured) bool {
		return func(c testutil.Captured) bool { return c.Module == name }
	}
	sink.WaitFor(t, testutil.DefaultTimeout, fromModule("files"))
	sink.WaitFor(t, testutil.DefaultTimeout, fromModule("syscall"))
}

/*
	The composite control path, against real BPF maps. buildUpdater derives
	the compositeUpdater from the loaded modules and their registered
	MapNames, and every command below is routed and applied in the kernel,
	then read back through the same handler.

	This is the fake-backed routing test from main_test.go promoted to real
	maps: it is what protects the registry-derived routing when the flag
	wiring is refactored.
*/
func TestIntegrationCompositeControlRoutesToRealMaps(t *testing.T) {
	testutil.RequireBPF(t)

	sink := testutil.NewCaptureSink()
	names := []string{"syscall", "network"}
	mods := buildModules(t, sink, map[string]string{}, names...)

	mr := runner.New(mods...)
	if err := mr.LoadAll(); err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	defer mr.CloseAll()

	handler := control.NewHandler(buildUpdater(mods, names))

	mustOK := func(cmd string) {
		t.Helper()
		if resp := handler.HandleCommand(cmd); !strings.HasPrefix(resp, "OK") && resp != "" {
			t.Fatalf("%q -> %q, want OK", cmd, resp)
		}
	}

	/*
		A plain shared name broadcasts. pid is owned by both modules, so
		the detailed listing must show the key under each.
	*/
	mustOK("add pid 4242")
	if resp := handler.HandleCommand("list pid"); !strings.Contains(resp, "syscall") ||
		!strings.Contains(resp, "network") || !strings.Contains(resp, "4242") {
		t.Errorf("list pid after broadcast add = %q, want both modules and 4242", resp)
	}

	/*
		A module-specific map routes to its owner only. port belongs to
		network; the syscall module has no port map, so the key must land
		in network and nowhere else.
	*/
	mustOK("add port 8080")
	if resp := handler.HandleCommand("list network port"); !strings.Contains(resp, "8080") {
		t.Errorf("list network port = %q, want 8080", resp)
	}

	/*
		A module-qualified name targets one module even for a map another
		also owns. Adding syscall.pid must not change network's pid set.
	*/
	mustOK("add syscall pid 777")
	if resp := handler.HandleCommand("list network pid"); strings.Contains(resp, "777") {
		t.Errorf("qualified add leaked into network: list network pid = %q", resp)
	}
	if resp := handler.HandleCommand("list syscall pid"); !strings.Contains(resp, "777") {
		t.Errorf("qualified add missing from syscall: list syscall pid = %q", resp)
	}

	/*
		Delete and clear must reach the kernel too. After clearing the
		broadcast key, neither module lists it.
	*/
	mustOK("del pid 4242")
	mustOK("clear pid")
	if resp := handler.HandleCommand("list pid"); strings.Contains(resp, "4242") ||
		strings.Contains(resp, "777") {
		t.Errorf("list pid after del+clear = %q, want no keys", resp)
	}
}
