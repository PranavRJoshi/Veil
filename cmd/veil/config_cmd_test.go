package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "veil.yaml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// A well-formed config passes every offline layer.
func TestValidateConfig_OK(t *testing.T) {
	path := writeConfig(t, `
modules:
  - name: syscall
    flags:
      pid: [1]
      syscall: [openat, "!read"]
  - name: files
    flags:
      op: [read, write]
output:
  count_by: syscall
`)
	if err := validateConfig(path); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
}

// A syscall name absent from the host table is rejected with a suggestion.
// "opena" is one deletion from openat, present on every supported arch.
func TestValidateConfig_BadSyscall(t *testing.T) {
	path := writeConfig(t, "modules:\n  - name: syscall\n    flags:\n      syscall: [opena]\n")
	err := validateConfig(path)
	if err == nil {
		t.Fatal("expected error for unknown syscall name")
	}
	if !strings.Contains(err.Error(), "openat") {
		t.Errorf("error lacks suggestion: %v", err)
	}
}

// A deny-side syscall name is validated too.
func TestValidateConfig_BadDenySyscall(t *testing.T) {
	path := writeConfig(t, "modules:\n  - name: syscall\n    flags:\n      syscall: [\"!opena\"]\n")
	if err := validateConfig(path); err == nil {
		t.Fatal("expected error for unknown deny syscall name")
	}
}

// Every profile in a multi-profile file is validated, and a failure names the
// offending profile.
func TestValidateConfig_MultiProfile(t *testing.T) {
	good := writeConfig(t, `
profiles:
  a:
    modules:
      - name: syscall
        flags:
          syscall: [openat]
  b:
    modules:
      - name: files
        flags:
          op: [read]
`)
	if err := validateConfig(good); err != nil {
		t.Fatalf("multi-profile config rejected: %v", err)
	}

	bad := writeConfig(t, `
profiles:
  ok:
    modules:
      - name: syscall
        flags:
          syscall: [openat]
  broken:
    modules:
      - name: syscall
        flags:
          syscall: [opena]
`)
	err := validateConfig(bad)
	if err == nil {
		t.Fatal("expected error for the broken profile")
	}
	if !strings.Contains(err.Error(), "[broken]") {
		t.Errorf("error should name the failing profile: %v", err)
	}
}

// Structural problems surface through config.Load.
func TestValidateConfig_UnknownModule(t *testing.T) {
	path := writeConfig(t, "modules:\n  - name: nope\n")
	if err := validateConfig(path); err == nil {
		t.Fatal("expected error for unknown module")
	}
}

func TestRunConfigCmd_Usage(t *testing.T) {
	if code := runConfigCmd("veil", []string{"bogus"}); code != 2 {
		t.Errorf("unknown subcommand exit = %d, want 2", code)
	}
	if code := runConfigCmd("veil", []string{"validate"}); code != 2 {
		t.Errorf("validate without path exit = %d, want 2", code)
	}
}

func TestRunConfigCmd_ExitCodes(t *testing.T) {
	good := writeConfig(t, "modules:\n  - name: syscall\n    flags:\n      syscall: [openat]\n")
	bad := writeConfig(t, "modules:\n  - name: syscall\n    flags:\n      syscall: [opena]\n")

	if code := runConfigCmd("veil", []string{"validate", good}); code != 0 {
		t.Errorf("good config exit = %d, want 0", code)
	}
	if code := runConfigCmd("veil", []string{"validate", good, bad}); code != 1 {
		t.Errorf("one bad config exit = %d, want 1", code)
	}
}
