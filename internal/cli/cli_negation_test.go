package cli

import (
	"testing"
)

// ---------------------------------------------------------------------------
// splitAllowDeny
// ---------------------------------------------------------------------------

func TestSplitAllowDeny_AllowOnly(t *testing.T) {
	allow, deny := splitAllowDeny("1234,5678")
	if allow != "1234,5678" {
		t.Errorf("allow = %q, want %q", allow, "1234,5678")
	}
	if deny != "" {
		t.Errorf("deny = %q, want empty", deny)
	}
}

func TestSplitAllowDeny_DenyOnly(t *testing.T) {
	allow, deny := splitAllowDeny("!100,!200")
	if allow != "" {
		t.Errorf("allow = %q, want empty", allow)
	}
	if deny != "100,200" {
		t.Errorf("deny = %q, want %q", deny, "100,200")
	}
}

func TestSplitAllowDeny_Mixed(t *testing.T) {
	allow, deny := splitAllowDeny("1234,!5678")
	if allow != "1234" {
		t.Errorf("allow = %q, want %q", allow, "1234")
	}
	if deny != "5678" {
		t.Errorf("deny = %q, want %q", deny, "5678")
	}
}

func TestSplitAllowDeny_MultiMixed(t *testing.T) {
	allow, deny := splitAllowDeny("100,!200,300,!400")
	if allow != "100,300" {
		t.Errorf("allow = %q, want %q", allow, "100,300")
	}
	if deny != "200,400" {
		t.Errorf("deny = %q, want %q", deny, "200,400")
	}
}

func TestSplitAllowDeny_SingleDeny(t *testing.T) {
	allow, deny := splitAllowDeny("!42")
	if allow != "" {
		t.Errorf("allow = %q, want empty", allow)
	}
	if deny != "42" {
		t.Errorf("deny = %q, want %q", deny, "42")
	}
}

func TestSplitAllowDeny_WithSpaces(t *testing.T) {
	allow, deny := splitAllowDeny(" 100 , !200 ")
	if allow != "100" {
		t.Errorf("allow = %q, want %q", allow, "100")
	}
	if deny != "200" {
		t.Errorf("deny = %q, want %q", deny, "200")
	}
}

func TestSplitAllowDeny_EmptyString(t *testing.T) {
	allow, deny := splitAllowDeny("")
	if allow != "" {
		t.Errorf("allow = %q, want empty", allow)
	}
	if deny != "" {
		t.Errorf("deny = %q, want empty", deny)
	}
}

func TestSplitAllowDeny_BangAlone(t *testing.T) {
	allow, deny := splitAllowDeny("!")
	if allow != "" {
		t.Errorf("allow = %q, want empty", allow)
	}
	if deny != "" {
		t.Errorf("deny = %q, want empty (bare ! has no value)", deny)
	}
}

func TestSplitAllowDeny_TrailingComma(t *testing.T) {
	allow, deny := splitAllowDeny("100,")
	if allow != "100" {
		t.Errorf("allow = %q, want %q", allow, "100")
	}
	if deny != "" {
		t.Errorf("deny = %q, want empty", deny)
	}
}

// ---------------------------------------------------------------------------
// End-to-end CLI: negation filters produce correct ModuleFlags
// ---------------------------------------------------------------------------

func TestParsePIDNegation(t *testing.T) {
	cfg, err := Parse([]string{"--module", "syscall", "--pid", "1234,!5678"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ModuleFlags["pid"] != "1234" {
		t.Errorf("pid = %q, want %q", cfg.ModuleFlags["pid"], "1234")
	}
	if cfg.ModuleFlags["pid_deny"] != "5678" {
		t.Errorf("pid_deny = %q, want %q", cfg.ModuleFlags["pid_deny"], "5678")
	}
}

func TestParsePIDDenyOnly(t *testing.T) {
	cfg, err := Parse([]string{"--module", "syscall", "-p", "!1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := cfg.ModuleFlags["pid"]; ok {
		t.Errorf("pid should not be set for deny-only, got %q", cfg.ModuleFlags["pid"])
	}
	if cfg.ModuleFlags["pid_deny"] != "1" {
		t.Errorf("pid_deny = %q, want %q", cfg.ModuleFlags["pid_deny"], "1")
	}
}

func TestParseUIDNegation(t *testing.T) {
	cfg, err := Parse([]string{"--module", "syscall", "--uid", "0,!1000"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ModuleFlags["uid"] != "0" {
		t.Errorf("uid = %q, want %q", cfg.ModuleFlags["uid"], "0")
	}
	if cfg.ModuleFlags["uid_deny"] != "1000" {
		t.Errorf("uid_deny = %q, want %q", cfg.ModuleFlags["uid_deny"], "1000")
	}
}

func TestParseSyscallNegation(t *testing.T) {
	cfg, err := Parse([]string{"--module", "syscall", "-s", "read,!ioctl,write"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ModuleFlags["syscall"] != "read,write" {
		t.Errorf("syscall = %q, want %q", cfg.ModuleFlags["syscall"], "read,write")
	}
	if cfg.ModuleFlags["syscall_deny"] != "ioctl" {
		t.Errorf("syscall_deny = %q, want %q", cfg.ModuleFlags["syscall_deny"], "ioctl")
	}
}

func TestParsePortNegation(t *testing.T) {
	cfg, err := Parse([]string{"--module", "network", "--port", "443,!22"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ModuleFlags["port"] != "443" {
		t.Errorf("port = %q, want %q", cfg.ModuleFlags["port"], "443")
	}
	if cfg.ModuleFlags["port_deny"] != "22" {
		t.Errorf("port_deny = %q, want %q", cfg.ModuleFlags["port_deny"], "22")
	}
}

func TestParseMultipleDenies(t *testing.T) {
	cfg, err := Parse([]string{"--module", "syscall", "--pid", "!100,!200,!300"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := cfg.ModuleFlags["pid"]; ok {
		t.Errorf("pid should not be set, got %q", cfg.ModuleFlags["pid"])
	}
	if cfg.ModuleFlags["pid_deny"] != "100,200,300" {
		t.Errorf("pid_deny = %q, want %q", cfg.ModuleFlags["pid_deny"], "100,200,300")
	}
}

func TestParseNegationWithEnrich(t *testing.T) {
	cfg, err := Parse([]string{
		"--module", "syscall",
		"--pid", "!1",
		"--enrich", "all",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ModuleFlags["pid_deny"] != "1" {
		t.Errorf("pid_deny = %q, want %q", cfg.ModuleFlags["pid_deny"], "1")
	}
	if cfg.EnrichFlags != "all" {
		t.Errorf("EnrichFlags = %q, want %q", cfg.EnrichFlags, "all")
	}
}
