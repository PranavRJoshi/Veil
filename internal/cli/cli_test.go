package cli

import (
	"os"
	"testing"

	"github.com/PranavRJoshi/Veil/internal/registry"
)

/*
	TestMain registers fake modules in the registry before running
	CLI tests. This is necessary because cli.Parse now validates
	module names against the registry instead of a hardcoded map.
*/
func TestMain(m *testing.M) {
	registry.Register(registry.ModuleInfo{
		Name:        "syscall",
		Description: "test syscall module",
		Factory:     func(map[string]string, interface{}) (interface{}, error) { return nil, nil },
	})
	registry.Register(registry.ModuleInfo{
		Name:        "files",
		Description: "test files module",
		Factory:     func(map[string]string, interface{}) (interface{}, error) { return nil, nil },
	})
	registry.Register(registry.ModuleInfo{
		Name:        "network",
		Description: "test network module",
		Factory:     func(map[string]string, interface{}) (interface{}, error) { return nil, nil },
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
