//go:build integration && linux

package uprobe

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/PranavRJoshi/Veil/internal/testutil"
)

/*
	Integration tests for the uprobe module.

	The probe target is a small C helper compiled at test time. A C binary
	keeps an ordinary STT_FUNC symbol table that cilium resolves by name,
	independent of the Go toolchain (Go here strips its ELF .symtab, so the
	test binary's own functions are not resolvable by name). The helper loops
	calling the target, and each running instance has a distinct PID, which is
	what the filter tests key on.
*/

const helperSource = `
#include <unistd.h>

__attribute__((noinline))
int veil_uprobe_target(int x) { return x + 1; }

int main(void) {
	volatile int acc = 0;
	for (;;) {
		acc += veil_uprobe_target(acc);
		usleep(2000);
	}
	return 0;
}
`

const helperSymbol = "veil_uprobe_target"

/*
	buildHelper compiles the C helper to a temp binary. It skips the test if
	no C compiler is present, so an image without one (some CI runners) does
	not fail; the decode and config paths are covered by the unit tests.
*/
func buildHelper(t *testing.T) string {
	t.Helper()

	var cc string
	for _, c := range []string{"cc", "clang", "gcc"} {
		if p, err := exec.LookPath(c); err == nil {
			cc = p
			break
		}
	}
	if cc == "" {
		t.Skip("no C compiler (cc/clang/gcc) available")
	}

	dir := t.TempDir()
	src := filepath.Join(dir, "helper.c")
	bin := filepath.Join(dir, "helper")
	if err := os.WriteFile(src, []byte(helperSource), 0o644); err != nil {
		t.Fatal(err)
	}

	/* -O0 -fno-inline keep veil_uprobe_target out of line and callable. */
	out, err := exec.Command(cc, "-O0", "-fno-inline", "-o", bin, src).CombinedOutput()
	if err != nil {
		t.Fatalf("compile helper: %v\n%s", err, out)
	}
	return bin
}

/*
	startHelper runs the compiled helper and returns its PID. The process is
	killed on test cleanup.
*/
func startHelper(t *testing.T, bin string) int {
	t.Helper()

	cmd := exec.Command(bin)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start helper %s: %v", bin, err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})
	return cmd.Process.Pid
}

func isUprobe(c testutil.Captured) bool { return c.Module == "uprobe" }

func fromPID(pid int) func(testutil.Captured) bool {
	want := strconv.Itoa(pid)
	return func(c testutil.Captured) bool {
		if !isUprobe(c) {
			return false
		}
		p, _ := c.Field("pid")
		return p == want
	}
}

/*
	Entry-only mode emits one event per call, attributed to the calling
	process, with the probed symbol carried through toFields and a zero
	duration.
*/
func TestIntegrationUprobeEntryEmits(t *testing.T) {
	testutil.RequireBPF(t)

	bin := buildHelper(t)
	pid := startHelper(t, bin)

	sink := testutil.NewCaptureSink()
	mod := New(FilterConfig{
		Target: Target{Path: bin, Symbol: helperSymbol},
		PIDs:   []uint32{uint32(pid)},
	}, sink)
	testutil.StartModule(t, mod)

	c := sink.WaitFor(t, testutil.DefaultTimeout, fromPID(pid))

	if got, _ := c.Field("symbol"); got != helperSymbol {
		t.Errorf("symbol = %q, want %q", got, helperSymbol)
	}
	if got, _ := c.Field("duration_ns"); got != "0" {
		t.Errorf("duration_ns = %q, want 0 in entry-only mode", got)
	}
}

/*
	The PID allow filter must be exclusive: with two instances of the helper
	running the same symbol, only the filtered instance is captured.
*/
func TestIntegrationUprobePIDFilterIsExclusive(t *testing.T) {
	testutil.RequireBPF(t)

	bin := buildHelper(t)
	pidA := startHelper(t, bin)
	pidB := startHelper(t, bin)

	sink := testutil.NewCaptureSink()
	mod := New(FilterConfig{
		Target: Target{Path: bin, Symbol: helperSymbol},
		PIDs:   []uint32{uint32(pidA)},
	}, sink)
	stop := testutil.StartModule(t, mod)

	sink.WaitFor(t, testutil.DefaultTimeout, fromPID(pidA))
	stop()

	wantB := strconv.Itoa(pidB)
	for _, c := range sink.Snapshot() {
		if p, _ := c.Field("pid"); p == wantB {
			t.Errorf("pid filter leaked an event for pid %s (filtered to %d): %v", wantB, pidA, c.Fields)
		}
	}
}

/*
	Latency mode attaches the uretprobe and reports a positive entry-to-return
	duration. Safe here because the target is a C function, not a live Go
	stack that the runtime may relocate.
*/
func TestIntegrationUprobeLatencyMeasured(t *testing.T) {
	testutil.RequireBPF(t)

	bin := buildHelper(t)
	pid := startHelper(t, bin)

	sink := testutil.NewCaptureSink()
	mod := New(FilterConfig{
		Target:  Target{Path: bin, Symbol: helperSymbol},
		Latency: true,
		PIDs:    []uint32{uint32(pid)},
	}, sink)
	testutil.StartModule(t, mod)

	want := strconv.Itoa(pid)
	c := sink.WaitFor(t, testutil.DefaultTimeout, func(c testutil.Captured) bool {
		if !isUprobe(c) {
			return false
		}
		p, _ := c.Field("pid")
		d, _ := c.Field("duration_ns")
		return p == want && d != "0" && d != ""
	})

	d, _ := c.Field("duration_ns")
	if n, err := strconv.ParseUint(d, 10, 64); err != nil || n == 0 {
		t.Errorf("duration_ns = %q, want a positive integer", d)
	}
}

/*
	A missing symbol must fail the load with an actionable error. The helper
	has a real symbol table, so this fails for the right reason: the symbol is
	genuinely absent, not the whole table.
*/
func TestIntegrationUprobeUnknownSymbol(t *testing.T) {
	testutil.RequireBPF(t)

	bin := buildHelper(t)
	sink := testutil.NewCaptureSink()
	mod := New(FilterConfig{
		Target: Target{Path: bin, Symbol: "veil_no_such_symbol_zzz"},
	}, sink)

	if err := mod.Load(); err == nil {
		mod.Close()
		t.Fatal("expected load to fail for an unknown symbol")
	}
}
