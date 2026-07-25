package cli

import (
	"os"
	"testing"

	"github.com/PranavRJoshi/Veil/internal/output"
	"github.com/PranavRJoshi/Veil/internal/registry"
	"github.com/PranavRJoshi/Veil/internal/runner"
)

/*
	TestMain registers fake modules before running CLI tests. Parse builds
	its flag table from the registry, so the fakes declare the same flags
	and Negatable settings as the real modules.
*/
func TestMain(m *testing.M) {
	noopFactory := func(map[string]string, output.EventSink) (runner.Module, error) { return nil, nil }
	common := []registry.FlagDef{
		{Name: "pid", Short: "p", HasValue: true, Negatable: true},
		{Name: "uid", Short: "u", HasValue: true, Negatable: true},
		{Name: "name", Short: "n", HasValue: true},
	}
	withCommon := func(extra ...registry.FlagDef) []registry.FlagDef {
		return append(append([]registry.FlagDef{}, common...), extra...)
	}

	registry.Register(registry.ModuleInfo{
		Name: "syscall", Description: "test syscall module", Factory: noopFactory,
		Flags: withCommon(registry.FlagDef{Name: "syscall", Short: "s", HasValue: true, Negatable: true}),
	})
	registry.Register(registry.ModuleInfo{
		Name: "files", Description: "test files module", Factory: noopFactory,
		Flags: withCommon(
			registry.FlagDef{Name: "op", HasValue: true},
			registry.FlagDef{Name: "file", HasValue: true},
		),
	})
	registry.Register(registry.ModuleInfo{
		Name: "network", Description: "test network module", Factory: noopFactory,
		Flags: withCommon(registry.FlagDef{Name: "port", HasValue: true, Negatable: true}),
	})
	registry.Register(registry.ModuleInfo{
		Name: "scheduler", Description: "test scheduler module", Factory: noopFactory,
		Flags: withCommon(registry.FlagDef{Name: "cpu", HasValue: true, Negatable: true}),
	})
	registry.Register(registry.ModuleInfo{
		Name: "memory", Description: "test memory module", Factory: noopFactory,
		Flags: withCommon(registry.FlagDef{Name: "fault", HasValue: true, Negatable: true}),
	})
	os.Exit(m.Run())
}

/*
	TestParseModuleOnly verifies that --module alone is accepted
	and the module name is correctly stored.
*/
func TestParseModuleOnly(t *testing.T) {
	cfg, err := Parse([]string{"--module", "syscall"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Module != "syscall" {
		t.Errorf("expected module 'syscall', got %q", cfg.Module)
	}
	if len(cfg.ModuleFlags) != 0 {
		t.Errorf("expected no module flags, got %v", cfg.ModuleFlags)
	}
}

/*
	TestParseWithFlags verifies that per-module flags are collected
	correctly into ModuleFlags.
*/
func TestParseWithFlags(t *testing.T) {
	cfg, err := Parse([]string{"--module", "syscall", "-p", "1234", "-n", "bash"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Module != "syscall" {
		t.Errorf("expected module 'syscall', got %q", cfg.Module)
	}
	if cfg.ModuleFlags["pid"] != "1234" {
		t.Errorf("expected pid '1234', got %q", cfg.ModuleFlags["pid"])
	}
	if cfg.ModuleFlags["name"] != "bash" {
		t.Errorf("expected name 'bash', got %q", cfg.ModuleFlags["name"])
	}
}

/*
	TestParseLongFormFlags verifies that long-form flags (--pid, --name)
	work identically to their short-form counterparts.
*/
func TestParseLongFormFlags(t *testing.T) {
	cfg, err := Parse([]string{"--module", "files", "--pid", "999", "--name", "nginx", "--op", "read,write", "--file", "passwd"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Module != "files" {
		t.Errorf("expected module 'files', got %q", cfg.Module)
	}
	if cfg.ModuleFlags["pid"] != "999" {
		t.Errorf("expected pid '999', got %q", cfg.ModuleFlags["pid"])
	}
	if cfg.ModuleFlags["op"] != "read,write" {
		t.Errorf("expected op 'read,write', got %q", cfg.ModuleFlags["op"])
	}
	if cfg.ModuleFlags["file"] != "passwd" {
		t.Errorf("expected file 'passwd', got %q", cfg.ModuleFlags["file"])
	}
}

/*
	TestParseHelp verifies that --help sets the ShowHelp flag.
*/
func TestParseHelp(t *testing.T) {
	cfg, err := Parse([]string{"--help"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.ShowHelp {
		t.Error("expected ShowHelp to be true")
	}
}

/*
	TestParseShortHelp verifies that -h is equivalent to --help.
*/
func TestParseShortHelp(t *testing.T) {
	cfg, err := Parse([]string{"-h"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.ShowHelp {
		t.Error("expected ShowHelp to be true")
	}
}

/*
	TestParseListModules verifies that --list-modules sets the flag.
*/
func TestParseListModules(t *testing.T) {
	cfg, err := Parse([]string{"--list-modules"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.ListModules {
		t.Error("expected ListModules to be true")
	}
}

/*
	TestParseMissingModule verifies that omitting --module produces
	a descriptive error.
*/
func TestParseMissingModule(t *testing.T) {
	_, err := Parse([]string{"-p", "1234"})
	if err == nil {
		t.Fatal("expected error for missing --module, got nil")
	}
}

/*
	TestParseUnknownModule verifies that an invalid module name
	is rejected.
*/
func TestParseUnknownModule(t *testing.T) {
	_, err := Parse([]string{"--module", "errormod"})
	if err == nil {
		t.Fatal("expected error for unknown module, got nil")
	}
}

/*
	TestParseMissingFlagValue verifies that flags without values
	produce errors.
*/
func TestParseMissingFlagValue(t *testing.T) {
	cases := [][]string{
		{"--module"},
		{"--module", "syscall", "-p"},
		{"--module", "syscall", "-n"},
		{"--module", "syscall", "-s"},
		{"--module", "files", "--op"},
		{"--module", "files", "--file"},
		{"--module", "network", "--port"},
	}

	for _, args := range cases {
		_, err := Parse(args)
		if err == nil {
			t.Errorf("expected error for args %v, got nil", args)
		}
	}
}

/*
	TestParseUnknownFlag verifies that unrecognized flags are
	rejected with an error.
*/
func TestParseUnknownFlag(t *testing.T) {
	_, err := Parse([]string{"--module", "syscall", "--bogus"})
	if err == nil {
		t.Fatal("expected error for unknown flag, got nil")
	}
}

/*
	TestParseSyscallFilter verifies the -s/--syscall flag for
	comma-separated syscall names.
*/
func TestParseSyscallFilter(t *testing.T) {
	cfg, err := Parse([]string{"--module", "syscall", "-s", "openat,read,write"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ModuleFlags["syscall"] != "openat,read,write" {
		t.Errorf("expected syscall 'openat,read,write', got %q", cfg.ModuleFlags["syscall"])
	}
}

/*
	TestParseOutputFlag verifies the --output flag.
*/
func TestParseOutputFlag(t *testing.T) {
	cfg, err := Parse([]string{"--module", "syscall", "--output", "json"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ModuleFlags["output"] != "json" {
		t.Errorf("expected output 'json', got %q", cfg.ModuleFlags["output"])
	}
}

/*
	TestParsePortFlag verifies the --port flag.
*/
func TestParsePortFlag(t *testing.T) {
	cfg, err := Parse([]string{"--module", "files", "--port", "8080"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ModuleFlags["port"] != "8080" {
		t.Errorf("expected port '8080', got %q", cfg.ModuleFlags["port"])
	}
}

/*
	TestParseCpuFlag verifies the --cpu flag.
*/
func TestParseCpuFlag(t *testing.T) {
	cfg, err := Parse([]string{"--module", "syscall", "--cpu", "0,1,2"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ModuleFlags["cpu"] != "0,1,2" {
		t.Errorf("cpu = %q, want %q", cfg.ModuleFlags["cpu"], "0,1,2")
	}
}

func TestParseCpuFlagSingleValue(t *testing.T) {
	cfg, err := Parse([]string{"--module", "syscall", "--cpu", "3"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ModuleFlags["cpu"] != "3" {
		t.Errorf("cpu = %q, want %q", cfg.ModuleFlags["cpu"], "3")
	}
}

/*
	TestParseCpuFlagWithDeny verifies that the '!' prefix in '--cpu' value
	is correctly split into cpu (allow) and cpu_deny keys.
*/
func TestParseCpuFlagWithDeny(t *testing.T) {
	cfg, err := Parse([]string{"--module", "syscall", "--cpu", "0,!3"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ModuleFlags["cpu"] != "0" {
		t.Errorf("cpu = %q, want %q", cfg.ModuleFlags["cpu"], "0")
	}
	if cfg.ModuleFlags["cpu_deny"] != "3" {
		t.Errorf("cpu_deny = %q, want %q", cfg.ModuleFlags["cpu_deny"], "3")
	}
}

func TestParseCpuFlagDenyOnly(t *testing.T) {
	cfg, err := Parse([]string{"--module", "syscall", "--cpu", "!0"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := cfg.ModuleFlags["cpu"]; ok {
		t.Errorf("cpu should not be set for deny-only, got %q", cfg.ModuleFlags["cpu"])
	}
	if cfg.ModuleFlags["cpu_deny"] != "0" {
		t.Errorf("cpu_deny = %q, want %q", cfg.ModuleFlags["cpu_deny"], "0")
	}
}

/*
	TestParseCpuFlagMissingValue verifies that '--cpu' flag must have an
	argument.
*/
func TestParseCpuFlagMissingValue(t *testing.T) {
	_, err := Parse([]string{"--module", "syscall", "--cpu"})
	if err == nil {
		t.Fatal("expected error for --cpu without value")
	}
}

/*
	TestParseFaultFlag verifies the '--fault' flag.
*/
func TestParseFaultFlag(t *testing.T) {
	cfg, err := Parse([]string{"--module", "syscall", "--fault", "major,minor"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ModuleFlags["fault"] != "major,minor" {
		t.Errorf("fault = %q, want %q", cfg.ModuleFlags["fault"], "major,minor")
	}
}

func TestParseFaultFlagSingleValue(t *testing.T) {
	cfg, err := Parse([]string{"--module", "syscall", "--fault", "major"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ModuleFlags["fault"] != "major" {
		t.Errorf("fault = %q, want %q", cfg.ModuleFlags["fault"], "major")
	}
}

/*
	TestParseFaultFlagWithDeny verifies deny splitting for '--fault'.
*/
func TestParseFaultFlagWithDeny(t *testing.T) {
	cfg, err := Parse([]string{"--module", "syscall", "--fault", "minor,!major"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ModuleFlags["fault"] != "minor" {
		t.Errorf("fault = %q, want %q", cfg.ModuleFlags["fault"], "minor")
	}
	if cfg.ModuleFlags["fault_deny"] != "major" {
		t.Errorf("fault_deny = %q, want %q", cfg.ModuleFlags["fault_deny"], "major")
	}
}

func TestParseFaultFlagDenyOnly(t *testing.T) {
	cfg, err := Parse([]string{"--module", "syscall", "--fault", "!major"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := cfg.ModuleFlags["fault"]; ok {
		t.Errorf("fault should not be set for deny-only, got %q", cfg.ModuleFlags["fault"])
	}
	if cfg.ModuleFlags["fault_deny"] != "major" {
		t.Errorf("fault_deny = %q, want %q", cfg.ModuleFlags["fault_deny"], "major")
	}
}

func TestParseFaultFlagMissingValue(t *testing.T) {
	_, err := Parse([]string{"--module", "syscall", "--fault"})
	if err == nil {
		t.Fatal("expected error for --fault without value")
	}
}

/*
	TestParseCpuAndFaultTogether verifies that module-specific flags do not
	interfere with each other or with global flags when used in combination.
*/
func TestParseCpuAndFaultTogether(t *testing.T) {
	cfg, err := Parse([]string{
		"--module", "syscall",
		"--cpu", "0,1",
		"--fault", "minor",
		"--pid", "1234",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ModuleFlags["cpu"] != "0,1" {
		t.Errorf("cpu = %q, want %q", cfg.ModuleFlags["cpu"], "0,1")
	}
	if cfg.ModuleFlags["fault"] != "minor" {
		t.Errorf("fault = %q, want %q", cfg.ModuleFlags["fault"], "minor")
	}
	if cfg.ModuleFlags["pid"] != "1234" {
		t.Errorf("pid = %q, want %q", cfg.ModuleFlags["pid"], "1234")
	}
}

/*
	Control flag (--control)
*/

func TestParseControlFlag(t *testing.T) {
	cfg, err := Parse([]string{"--module", "syscall", "--control", "/tmp/veil.sock"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ControlPath != "/tmp/veil.sock" {
		t.Errorf("expected ControlPath '/tmp/veil.sock', got %q", cfg.ControlPath)
	}
}

func TestParseControlFlagMissingValue(t *testing.T) {
	_, err := Parse([]string{"--module", "syscall", "--control"})
	if err == nil {
		t.Fatal("expected error for --control without value")
	}
}

func TestParseControlPathNotSetByDefault(t *testing.T) {
	cfg, err := Parse([]string{"--module", "syscall"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ControlPath != "" {
		t.Errorf("expected empty ControlPath by default, got %q", cfg.ControlPath)
	}
}

/*
	Enrichment flag (--enrich)
*/

func TestParseEnrichFlag(t *testing.T) {
	cfg, err := Parse([]string{"--module", "syscall", "--enrich", "time,proc"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.EnrichFlags != "time,proc" {
		t.Errorf("expected EnrichFlags 'time,proc', got %q", cfg.EnrichFlags)
	}
}

func TestParseEnrichAll(t *testing.T) {
	cfg, err := Parse([]string{"--module", "syscall", "--enrich", "all"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.EnrichFlags != "all" {
		t.Errorf("expected EnrichFlags 'all', got %q", cfg.EnrichFlags)
	}
}

func TestParseEnrichFlagMissingValue(t *testing.T) {
	_, err := Parse([]string{"--module", "syscall", "--enrich"})
	if err == nil {
		t.Fatal("expected error for --enrich without value")
	}
}

func TestParseEnrichNotSetByDefault(t *testing.T) {
	cfg, err := Parse([]string{"--module", "syscall"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.EnrichFlags != "" {
		t.Errorf("expected empty EnrichFlags by default, got %q", cfg.EnrichFlags)
	}
}

func TestParseCpuDenyWithEnrich(t *testing.T) {
	cfg, err := Parse([]string{
		"--module", "syscall",
		"--cpu", "!0,!1",
		"--enrich", "time",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ModuleFlags["cpu_deny"] != "0,1" {
		t.Errorf("cpu_deny = %q, want %q", cfg.ModuleFlags["cpu_deny"], "0,1")
	}
	if cfg.EnrichFlags != "time" {
		t.Errorf("EnrichFlags = %q, want %q", cfg.EnrichFlags, "time")
	}
}

/*
	Multi-module (--module name,name)
*/

func TestParseMultiModule(t *testing.T) {
	cfg, err := Parse([]string{"--module", "syscall,network"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Module != "syscall,network" {
		t.Errorf("expected 'syscall,network', got %q", cfg.Module)
	}
}

func TestParseMultiModuleWithSpaces(t *testing.T) {
	cfg, err := Parse([]string{"--module", "syscall, network"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Module != "syscall, network" {
		t.Errorf("expected 'syscall, network', got %q", cfg.Module)
	}
}

func TestParseMultiModuleOneInvalid(t *testing.T) {
	_, err := Parse([]string{"--module", "syscall,errmod"})
	if err == nil {
		t.Fatal("expected error for unknown module in multi-module list")
	}
}

func TestParseMultiModuleAllThree(t *testing.T) {
	cfg, err := Parse([]string{"--module", "syscall,files,network", "--pid", "1234"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Module != "syscall,files,network" {
		t.Errorf("expected 'syscall,files,network', got %q", cfg.Module)
	}
	if cfg.ModuleFlags["pid"] != "1234" {
		t.Errorf("expected pid '1234', got %q", cfg.ModuleFlags["pid"])
	}
}

func TestParseMultiModuleEmptyName(t *testing.T) {
	_, err := Parse([]string{"--module", "syscall,,network"})
	if err == nil {
		t.Fatal("expected error for empty module name in list")
	}
}
