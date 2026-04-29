// Package runner provides orchestration for running one or more Veil
// modules concurrently, with coordinated startup, shutdown, and a shared
// output sink.
//
// The key type is MultiRunner, which replaces the single-module goroutine
// pattern in main.go with a general-purpose fan-in coordinator.
package runner

import (
	"fmt"
	"sync"
)

// Runner is the interface that modules implement to consume events.
// It matches the existing convention: Run blocks until done is closed.
type Runner interface {
	Run(done <-chan struct{})
}

// Loader is the interface for loading/closing BPF programs.
// It matches loader.Program from the existing codebase.
type Loader interface {
	Load() error
	Close() error
	Name() string
}

// Module combines both interfaces: a module that can be loaded and run.
// Every Veil module satisfies this via its embedded BaseProgram + Run method.
type Module interface {
	Loader
	Runner
}

// MultiRunner manages the lifecycle of multiple modules running concurrently.
// It handles:
//   - Sequential loading (fail-fast: if any module fails to load, previously
//     loaded modules are closed and the error is returned)
//   - Concurrent Run() goroutines with a shared done channel
//   - Graceful shutdown with WaitGroup-based join
//
// All modules share a single EventSink (injected at module construction time
// via the factory), so their output is naturally interleaved through the
// sink's thread-safe Emit method.
type MultiRunner struct {
	modules []Module
	mu      sync.Mutex
	loaded  []Module // tracks successfully loaded modules for cleanup
}

// New creates a MultiRunner for the given modules. Modules are loaded and
// run in the order provided.
func New(modules ...Module) *MultiRunner {
	return &MultiRunner{modules: modules}
}

// LoadAll loads every module sequentially. If any module fails to load,
// all previously loaded modules are closed (best-effort) and the first
// error is returned.
func (mr *MultiRunner) LoadAll() error {
	mr.mu.Lock()
	defer mr.mu.Unlock()

	mr.loaded = mr.loaded[:0]
	for _, mod := range mr.modules {
		if err := mod.Load(); err != nil {
			// Roll back: close everything we've loaded so far.
			mr.closeLoadedLocked()
			return fmt.Errorf("module %s: load: %w", mod.Name(), err)
		}
		mr.loaded = append(mr.loaded, mod)
	}
	return nil
}

// RunAll starts every loaded module's Run() in its own goroutine and
// blocks until done is closed and all goroutines have returned. The caller
// is responsible for closing done (typically on SIGINT/SIGTERM).
func (mr *MultiRunner) RunAll(done <-chan struct{}) {
	var wg sync.WaitGroup
	for _, mod := range mr.modules {
		wg.Add(1)
		go func(m Module) {
			defer wg.Done()
			m.Run(done)
		}(mod)
	}
	wg.Wait()
}

// CloseAll closes all loaded modules in reverse order. Safe to call
// multiple times. Returns the first error encountered.
func (mr *MultiRunner) CloseAll() error {
	mr.mu.Lock()
	defer mr.mu.Unlock()
	return mr.closeLoadedLocked()
}

func (mr *MultiRunner) closeLoadedLocked() error {
	var firstErr error
	// Close in reverse order (LIFO): mirrors resource cleanup convention.
	for i := len(mr.loaded) - 1; i >= 0; i-- {
		if err := mr.loaded[i].Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	mr.loaded = nil
	return firstErr
}

// Names returns the names of all registered modules.
func (mr *MultiRunner) Names() []string {
	names := make([]string, len(mr.modules))
	for i, mod := range mr.modules {
		names[i] = mod.Name()
	}
	return names
}
