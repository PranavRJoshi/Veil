package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PranavRJoshi/Veil/internal/output"
	"github.com/PranavRJoshi/Veil/internal/registry"
	"github.com/PranavRJoshi/Veil/internal/runner"
)

// registerTestModules installs two modules with distinct flags so per-module
// lowering and validation can be exercised.
func registerTestModules() {
	nilFactory := func(map[string]string, output.EventSink) (runner.Module, error) { return nil, nil }

	registry.Register(registry.ModuleInfo{
		Name: "syscall",
		Flags: []registry.FlagDef{
			{Name: "pid", Negatable: true, HasValue: true},
			{Name: "uid", Negatable: true, HasValue: true},
			{Name: "syscall", Negatable: true, HasValue: true},
		},
		Factory: nilFactory,
	})
	registry.Register(registry.ModuleInfo{
		Name: "uprobe",
		Flags: []registry.FlagDef{
			{Name: "pid", Negatable: true, HasValue: true},
			{Name: "uprobe", HasValue: true},
			{Name: "latency"}, // bool flag
		},
		Factory: nilFactory,
	})
}

func setupRegistry(t *testing.T) {
	t.Helper()
	registry.Reset()
	t.Cleanup(registry.Reset)
	registerTestModules()
}

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "veil.yaml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoad_LowersFilters(t *testing.T) {
	setupRegistry(t)

	path := writeConfig(t, `
modules:
  - name: syscall
    flags:
      pid: [1234, 5678]
      syscall: [openat, "!ioctl"]
output:
  format: json
  enrich: [time, proc]
  fields: [comm, pid, syscall]
  count_by: syscall
run:
  control: /tmp/veil.sock
  yes: true
`)

	sp, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}

	if len(sp.Modules) != 1 || sp.Modules[0].Name != "syscall" {
		t.Fatalf("modules = %+v", sp.Modules)
	}
	flags := sp.Modules[0].Flags
	if flags["pid"] != "1234,5678" {
		t.Errorf("pid list not joined: %q", flags["pid"])
	}
	// '!' deny value splits into the allow value and the _deny key.
	if flags["syscall"] != "openat" || flags["syscall_deny"] != "ioctl" {
		t.Errorf("negation split wrong: syscall=%q syscall_deny=%q", flags["syscall"], flags["syscall_deny"])
	}

	if sp.Output.Format != "json" {
		t.Errorf("format = %q", sp.Output.Format)
	}
	if sp.Output.Enrich != "time,proc" {
		t.Errorf("enrich = %q, want joined", sp.Output.Enrich)
	}
	if len(sp.Output.Fields) != 3 || sp.Output.Fields[0] != "comm" {
		t.Errorf("fields = %v", sp.Output.Fields)
	}
	// count_by implies count.
	if !sp.Output.Count || sp.Output.CountKey != "syscall" {
		t.Errorf("count=%v key=%q, want implied count on syscall", sp.Output.Count, sp.Output.CountKey)
	}
	if sp.Run.ControlPath != "/tmp/veil.sock" || !sp.Run.AssumeYes {
		t.Errorf("run = %+v", sp.Run)
	}
}

func TestLoad_BoolFlag(t *testing.T) {
	setupRegistry(t)

	// latency: true is emitted as "true"; latency: false is omitted entirely.
	on, err := Load(writeConfig(t, "modules:\n  - name: uprobe\n    flags:\n      latency: true\n"))
	if err != nil {
		t.Fatal(err)
	}
	if on.Modules[0].Flags["latency"] != "true" {
		t.Errorf("latency true = %q, want \"true\"", on.Modules[0].Flags["latency"])
	}

	off, err := Load(writeConfig(t, "modules:\n  - name: uprobe\n    flags:\n      latency: false\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := off.Modules[0].Flags["latency"]; ok {
		t.Error("latency false should be omitted, not set")
	}
}

func TestLoad_PerModuleFlags(t *testing.T) {
	setupRegistry(t)

	sp, err := Load(writeConfig(t, `
modules:
  - name: syscall
    flags:
      pid: [1]
  - name: uprobe
    flags:
      pid: [2]
      uprobe: /bin/bash:readline
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(sp.Modules) != 2 {
		t.Fatalf("want 2 modules, got %d", len(sp.Modules))
	}
	if sp.Modules[0].Flags["pid"] != "1" || sp.Modules[1].Flags["pid"] != "2" {
		t.Errorf("per-module flags leaked: %+v", sp.Modules)
	}
	if sp.Modules[1].Flags["uprobe"] != "/bin/bash:readline" {
		t.Errorf("uprobe flag = %q", sp.Modules[1].Flags["uprobe"])
	}
}

func TestLoad_Errors(t *testing.T) {
	setupRegistry(t)

	cases := map[string]string{
		"unknown module": "modules:\n  - name: nope\n",
		"unknown flag":   "modules:\n  - name: syscall\n    flags:\n      bogus: [1]\n",
		"unknown key":    "modules:\n  - name: syscall\nbogus: true\n",
		"no modules":     "output:\n  format: json\n",
		"malformed yaml": "modules: [ : ]\n",
		"nested list":    "modules:\n  - name: syscall\n    flags:\n      pid: [[1]]\n",
		"map flag value": "modules:\n  - name: syscall\n    flags:\n      pid:\n        a: b\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(writeConfig(t, body)); err == nil {
				t.Errorf("expected error for %s", name)
			}
		})
	}
}

func TestLoad_MissingFile(t *testing.T) {
	setupRegistry(t)
	if _, err := Load(filepath.Join(t.TempDir(), "absent.yaml")); err == nil {
		t.Error("expected error for missing file")
	}
}

// FuzzDecode drives arbitrary bytes through the flag-lowering path. Whatever
// decodes must satisfy the loader's invariants: no module survives that the
// registry rejects, and a negatable allow value never keeps a deny marker --
// the '!' is split into the _deny key.
func FuzzDecode(f *testing.F) {
	registry.Reset()
	f.Cleanup(registry.Reset)
	registerTestModules()

	seeds := []string{
		"modules:\n  - name: syscall\n    flags:\n      pid: [1, 2]\n      syscall: [openat, \"!ioctl\"]\n",
		"modules:\n  - name: uprobe\n    flags:\n      latency: true\n      uprobe: /bin/sh:main\n",
		"modules:\n  - name: syscall\n    flags:\n      pid: \"!5\"\noutput:\n  count_by: syscall\n",
		"modules: []\n",
		"not: valid\n",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		sp, err := decode(data)
		if err != nil {
			return
		}
		for _, m := range sp.Modules {
			info, ok := registry.Get(m.Name)
			if !ok {
				t.Fatalf("decoded unregistered module %q", m.Name)
			}
			for _, d := range info.Flags {
				if d.Negatable && strings.Contains(m.Flags[d.Name], "!") {
					t.Fatalf("negatable flag %q kept deny marker: %q", d.Name, m.Flags[d.Name])
				}
			}
		}
	})
}
