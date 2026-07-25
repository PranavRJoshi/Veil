// Package registry provides self-registration for Veil modules.
//
// Each module calls Register() in its init() function, eliminating the
// need to manually wire new modules into cmd/veil/main.go and cli.go.
//
// Usage in a module package:
//
//	func init() {
//	    registry.Register(registry.ModuleInfo{
//	        Name:        "syscall",
//	        Description: "Trace system calls via raw_syscalls/sys_enter",
//	        Flags: []registry.FlagDef{
//	            {Name: "syscall", Short: "s", Description: "Filter by syscall name or number"},
//	        },
//	        MapNames: []string{"pid", "uid", "syscall", "pid_deny", "uid_deny", "syscall_deny"},
//	        Factory: func(flags map[string]string, sink output.EventSink) (runner.Module, error) {
//	            filter, err := ParseFilterConfig(flags)
//	            if err != nil { return nil, err }
//	            return New(filter, sink), nil
//	        },
//	    })
//	}
package registry

import (
	"fmt"
	"sort"
	"sync"

	"github.com/PranavRJoshi/Veil/internal/output"
	"github.com/PranavRJoshi/Veil/internal/runner"
)

// FlagDef describes a CLI flag that a module accepts.
type FlagDef struct {
	Name        string // long flag name (e.g. "syscall")
	Short       string // short flag (e.g. "s"), empty if none
	Description string // shown in --help
	HasValue    bool   // true if the flag takes an argument (default true for non-bool)
}

// ModuleFactory creates a module instance from parsed CLI flags and an
// output sink. The returned runner.Module must be safe to Load and Run.
type ModuleFactory func(flags map[string]string, sink output.EventSink) (runner.Module, error)

// ModuleInfo describes a registerable module.
type ModuleInfo struct {
	Name        string
	Description string
	Flags       []FlagDef
	MapNames    []string // BPF filter map names owned by this module (e.g. "pid", "uid")
	Factory     ModuleFactory
	Formatter   output.TextFormatFunc // renders an event as a text line

	DefaultCountKey string   // field --count aggregates on by default
	CountFields     []string // event field names valid for --count-by
}

var (
	mu       sync.RWMutex
	modules  = make(map[string]ModuleInfo)
	regOrder []string // preserves registration order for stable listing
)

// Register adds a module to the global registry. It panics on duplicate
// names (a programming error, not a runtime condition).
func Register(info ModuleInfo) {
	mu.Lock()
	defer mu.Unlock()
	if _, dup := modules[info.Name]; dup {
		panic(fmt.Sprintf("registry: duplicate module %q", info.Name))
	}
	modules[info.Name] = info
	regOrder = append(regOrder, info.Name)
}

// Get returns the ModuleInfo for the named module, or false if not found.
func Get(name string) (ModuleInfo, bool) {
	mu.RLock()
	defer mu.RUnlock()
	info, ok := modules[name]
	return info, ok
}

// Names returns all registered module names in alphabetical order.
func Names() []string {
	mu.RLock()
	defer mu.RUnlock()
	names := make([]string, len(regOrder))
	copy(names, regOrder)
	sort.Strings(names)
	return names
}

// All returns all registered modules in alphabetical order.
func All() []ModuleInfo {
	names := Names()
	mu.RLock()
	defer mu.RUnlock()
	result := make([]ModuleInfo, 0, len(names))
	for _, n := range names {
		result = append(result, modules[n])
	}
	return result
}

// AllFlags returns a deduplicated, sorted list of all flag definitions
// across all registered modules. Useful for building the CLI help text
// dynamically.
func AllFlags() []FlagDef {
	mu.RLock()
	defer mu.RUnlock()
	seen := make(map[string]bool)
	var flags []FlagDef
	for _, info := range modules {
		for _, f := range info.Flags {
			if !seen[f.Name] {
				seen[f.Name] = true
				flags = append(flags, f)
			}
		}
	}
	sort.Slice(flags, func(i, j int) bool {
		return flags[i].Name < flags[j].Name
	})
	return flags
}

// Reset clears the registry. Only intended for tests.
func Reset() {
	mu.Lock()
	defer mu.Unlock()
	modules = make(map[string]ModuleInfo)
	regOrder = nil
}
