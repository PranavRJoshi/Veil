package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/PranavRJoshi/Veil/internal/cli"
	"github.com/PranavRJoshi/Veil/internal/control"
	"github.com/PranavRJoshi/Veil/internal/loader"
	"github.com/PranavRJoshi/Veil/internal/output"
	"github.com/PranavRJoshi/Veil/internal/registry"

	/*
		Blank imports trigger init() in each module package, which
		calls registry.Register(). Adding a new module to Veil
		requires only adding one blank import line here.
	*/
	_ "github.com/PranavRJoshi/Veil/modules/syscall"
	_ "github.com/PranavRJoshi/Veil/modules/files"
	_ "github.com/PranavRJoshi/Veil/modules/network"
)

/*
	Runner is the interface that modules implement for event consumption.
	Every module already has a Run(done <-chan struct{}) method.
*/
type Runner interface {
	Run(done <-chan struct{})
}

func main() {
	cfg, err := cli.Parse(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		cli.Usage()
		os.Exit(1)
	}
 
	if cfg.ShowHelp {
		cli.Usage()
		os.Exit(0)
	}
 
	if cfg.ListModules {
		cli.PrintModules()
		os.Exit(0)
	}

	/*
		Construct output pipeline. PausableSink wraps the format sink so we can
		suspend output during interactive control.
	*/
	var baseSink output.EventSink
	switch cfg.ModuleFlags["output"] {
		case "json":
			baseSink = output.NewJSONSink(os.Stdout)
		default:
			baseSink = output.NewTextSink(os.Stdout, output.DispatchTextFormat())
	}
	pausable := output.NewPausableSink(baseSink)
	defer baseSink.Close()

	/*
		Look up the module from the registry. The registry is populated
		by init() calls in each module package (triggered by blank imports).
	*/
	info, ok := registry.Get(cfg.Module)
	if !ok {
		fmt.Fprintf(os.Stderr, "unknown module %q; use --list-modules to see available modules\n", cfg.Module)
		os.Exit(1)
	}

	/*
		Create the module via its factory function. The factory
		handles ParseFilterConfig + New(filter, sink) internally.
	*/
	modIface, err := info.Factory(cfg.ModuleFlags, pausable)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	mod := modIface.(loader.Program)

	/*
		Register with the manager and load the BPF program into the kernel.
	*/
	m := loader.NewManager()
	m.Register(mod)

	if err := m.LoadAll(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	defer m.CloseAll()

	/*
		done is closed when the user sends SIGINT/SIGTERM. Module
		Run methods select on this channel to know when to exit.
	*/
	done := make(chan struct{})

	/*
		Start the module's event consumption loop as a goroutine.
		The type assertion to Runner is safe; every module has Run().
	*/
	if r, ok := modIface.(Runner); ok {
		go r.Run(done)
	}

	/*
		Build the control handler. If the module implements MapUpdater, use it
		for real filter modifications. Otherwise, use a stub that reports
		status but rejects filter changes.
	*/
	var handler *control.Handler
	if updater, ok := modIface.(control.MapUpdater); ok {
		handler = control.NewHandler(updater)
	} else {
		handler = control.NewHandler(&stubUpdater{module: cfg.Module})
	}

	/*
		Start socket server if '--control' was specified
	*/
	if cfg.ControlPath != "" {
		srv := control.NewServer(cfg.ControlPath, handler)
		if err := srv.Start(); err != nil {
			fmt.Fprintf(os.Stderr, "warning: control socket %v\n", err)
		} else {
			defer srv.Stop()
			fmt.Fprintf(os.Stderr, "control socket: %s\n", cfg.ControlPath)
		}
	}

	fmt.Fprintf(os.Stderr, "Veil [%s] running, press CTRL-C to pause and modify filters\n", cfg.Module)

	/*
		Two-stage signal handling:

		First CTRL-C  - pause events, enter interactive control
		"resume"      - resume evetns, go back to tracing
		"quit"/exit   - shut down
		Second CTRL-C - shut down (while in interactive mode)
	*/
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	for {
		sig := <- sigCh
		
		/* SIGTERM always means immeditate shutdown */
		if sig == syscall.SIGTERM {
			break
		}

		/* SIGINT: pause output and enter interactive mode */
		pausable.Pause()
		fmt.Fprintf(os.Stderr, "\n---  Veil Tracing Paused  ---\n")

		/*
			In interactive mode, a second CTRL-C should quit rather than
			be swallowed. We run interactive on stdin; if the user sends
			CTRL-C during the prompt, the signal handler fires and we
			check a flag.
		*/
		interruptedDuringPrompt := make(chan struct{}, 1)
		stopMonitor := make(chan struct{})
		go func() {
			select {
				case <-sigCh:
					interruptedDuringPrompt <- struct{}{}
					/* Write a newline so the prompt doesn't hang */
					fmt.Fprintln(os.Stderr)
				case <-stopMonitor:
					return
			}

		}()

		/*
			Run the interactive prompt. It blocks until the user types
			"resume", "quit", "exit", or CTRL-D
		*/
		resultCh := make(chan control.InteractiveResult, 1)
		go func() {
			resultCh <- control.Interactive(handler, os.Stdin, os.Stderr)
		}()

		var result control.InteractiveResult
		select {
			case result = <-resultCh:
				/* User typed a command */
				close(stopMonitor)
			case <-interruptedDuringPrompt:
				/* Second CTRL-C while in prompt */
				result = control.ResultQuit
		}

		if result == control.ResultQuit {
			break
		}

		/* Resume tracing */
		dropped := pausable.Resume()
		if dropped > 0 {
			fmt.Fprintf(os.Stderr, "---  resumed (%d events dropped while paused)  ---\n", dropped)
		} else {
			fmt.Fprintf(os.Stderr, "---  resumed  ---\n")
		}
		
		/*
			Reset the signal listener for the next CTRL-C cycle. Drain any
			pending signals.
		*/
		signal.Reset(syscall.SIGINT)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	}
 
	close(done)
}

/*
	printModules lists all registered modules with their descriptions,
	built dynamically from the registry.
*/
func printModules() {
	fmt.Println("Available modules:")
	for _, info := range registry.All() {
		fmt.Printf("  %-12s %s\n", info.Name, info.Description)
	}
	fmt.Println()
	fmt.Println("Planned modules:")
	fmt.Println("  scheduler   CPU run queue latency profiling")
	fmt.Println("  memory      OOM event inspection and page fault tracing")
}

// stubUpdater is used when the module doesn't implement MapUpdater.
// It allows status queries but rejects filter modifications.
type stubUpdater struct {
	module string
}

func (s *stubUpdater) AddFilter(mapName string, key uint64) error {
	return fmt.Errorf("module %q does not support runtime filter modification", s.module)
}
 
func (s *stubUpdater) DelFilter(mapName string, key uint64) error {
	return fmt.Errorf("module %q does not support runtime filter modification", s.module)
}
 
func (s *stubUpdater) ListFilters(mapName string) ([]uint64, error) {
	return nil, fmt.Errorf("module %q does not support runtime filter modification", s.module)
}
 
func (s *stubUpdater) ClearFilters(mapName string) error {
	return fmt.Errorf("module %q does not support runtime filter modification", s.module)
}

func (s *stubUpdater) Status() string {
	return fmt.Sprintf("module %s: loaded (runtime filter modification not implemented)", s.module)
}
