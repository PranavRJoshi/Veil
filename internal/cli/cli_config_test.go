package cli

import (
	"reflect"
	"testing"
)

// With --config the trace-defining flags are neither required nor validated;
// the config file governs them.
func TestParseConfigRelaxesModule(t *testing.T) {
	cfg, err := Parse([]string{"--config", "veil.yaml"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.ConfigPath != "veil.yaml" {
		t.Errorf("ConfigPath = %q", cfg.ConfigPath)
	}
}

func TestParseConfigMissingValue(t *testing.T) {
	if _, err := Parse([]string{"--config"}); err == nil {
		t.Error("expected error when --config has no value")
	}
}

func TestParseProfileWithConfig(t *testing.T) {
	cfg, err := Parse([]string{"--config", "veil.yaml", "--profile", "audit"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.ProfileName != "audit" {
		t.Errorf("ProfileName = %q, want audit", cfg.ProfileName)
	}
}

// --profile is a selector for --config; it is meaningless on its own.
func TestParseProfileRequiresConfig(t *testing.T) {
	if _, err := Parse([]string{"--profile", "audit"}); err == nil {
		t.Error("expected error for --profile without --config")
	}
}

func TestParseProfileMissingValue(t *testing.T) {
	if _, err := Parse([]string{"--config", "veil.yaml", "--profile"}); err == nil {
		t.Error("expected error when --profile has no value")
	}
}

func TestTraceFlags(t *testing.T) {
	c := Config{
		Module:      "syscall",
		ModuleFlags: map[string]string{"pid": "1", "output": "json"},
		EnrichFlags: "time",
		Fields:      "comm,pid",
		CountMode:   true,
		// operational flags must NOT appear in TraceFlags
		ControlPath: "/tmp/s.sock",
		PprofPath:   "/tmp/p",
		AssumeYes:   true,
	}
	got := c.TraceFlags()
	want := []string{"--count", "--enrich", "--fields", "--module", "--output", "--pid"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("TraceFlags = %v, want %v", got, want)
	}
}

func TestTraceFlagsEmpty(t *testing.T) {
	if got := (Config{}).TraceFlags(); len(got) != 0 {
		t.Errorf("TraceFlags on empty config = %v, want none", got)
	}
}
