package main

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/PranavRJoshi/Veil/internal/config"
	"github.com/PranavRJoshi/Veil/internal/registry"
	"github.com/PranavRJoshi/Veil/internal/runner"
	"github.com/PranavRJoshi/Veil/internal/spec"
)

// runConfigCmd handles the "config" verb. Today its only subcommand is
// validate; it returns the process exit code. prog is the invoked program
// name (os.Args[0]) so usage reflects how the binary was called.
func runConfigCmd(prog string, args []string) int {
	if len(args) < 2 || args[0] != "validate" {
		fmt.Fprintf(os.Stderr, "usage: %s config validate <path>...\n", prog)
		return 2
	}

	failed := false
	for _, path := range args[1:] {
		if err := validateConfig(path); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			failed = true
			continue
		}
	}
	if failed {
		return 1
	}
	return 0
}

/*
	validateConfig runs a config through everything a load checks that needs no
	kernel: structure and module/flag names (config.LoadAll), per-module flag
	parsing (the factory runs ParseFilterConfig), and value resolution for
	modules that implement runner.ConfigValidator (syscall names). Every profile
	in the file is checked, not just the one that would run.
*/
func validateConfig(path string) error {
	all, err := config.LoadAll(path)
	if err != nil {
		return err // config.LoadAll already prefixes the path
	}

	names := make([]string, 0, len(all))
	for name := range all {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		sp := all[name]
		if err := validateSpec(sp); err != nil {
			return fmt.Errorf("%s%s: %w", path, profileTag(name), err)
		}
		fmt.Printf("ok: %s%s (%s)\n", path, profileTag(name), summary(sp))
	}
	return nil
}

// validateSpec constructs each module (running its ParseFilterConfig) and runs
// any offline value checks, without loading BPF.
func validateSpec(sp spec.Spec) error {
	for _, m := range sp.Modules {
		info, _ := registry.Get(m.Name) // config validated the name
		mod, err := info.Factory(m.Flags, discardSink{})
		if err != nil {
			return err
		}
		if v, ok := mod.(runner.ConfigValidator); ok {
			if err := v.ValidateConfig(); err != nil {
				return err
			}
		}
	}
	return nil
}

func summary(sp spec.Spec) string {
	noun := "modules"
	if len(sp.Modules) == 1 {
		noun = "module"
	}
	return fmt.Sprintf("%d %s: %s; output %s",
		len(sp.Modules), noun, strings.Join(sp.Names(), ", "), outputFormat(sp))
}

// profileTag renders " [name]" for a named profile, or "" for a single-profile
// file (whose key is empty).
func profileTag(name string) string {
	if name == "" {
		return ""
	}
	return fmt.Sprintf(" [%s]", name)
}

func outputFormat(sp spec.Spec) string {
	if sp.Output.Format == "" {
		return "text"
	}
	return sp.Output.Format
}

// discardSink drops every event; validation constructs modules but never runs
// them, so nothing is ever emitted.
type discardSink struct{}

func (discardSink) Emit(string, map[string]interface{}) error { return nil }
func (discardSink) Close() error                              { return nil }
