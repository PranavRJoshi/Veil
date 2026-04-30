package main

import (
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/PranavRJoshi/Veil/internal/cli"
	"github.com/PranavRJoshi/Veil/internal/control"
	"github.com/PranavRJoshi/Veil/internal/enrich"
	"github.com/PranavRJoshi/Veil/internal/output"
	"github.com/PranavRJoshi/Veil/internal/registry"
	"github.com/PranavRJoshi/Veil/internal/runner"

	/*
		Blank imports trigger init() in each module package, which
		calls registry.Register(). Adding a new module to Veil
		requires only adding one blank import line here.
	*/
	_ "github.com/PranavRJoshi/Veil/modules/syscall"
	_ "github.com/PranavRJoshi/Veil/modules/files"
	_ "github.com/PranavRJoshi/Veil/modules/network"
)

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

		baseSink (TextSink or JSONSink)
			|
			+-> wrapped by PausableSink (for interactive control)
					|
					+-> wrapped by EnrichSink (optional)
							|
							+-> passed to module factories as their output target

		The enrichment layer sits between the pausable sink and the modules.
		When paused, events are dropped at the PausableSink level, before
		enrichment runs, thus avoiding unnecessary /proc reads during pause.
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
		Build the enrichment pipeline when --enrich option is specified.
		Enrichers are sink middleware that add derived fields to events
		before they reach the output formatter. Enriched sinks wrap pausable,
		so all modules share the same enrichment chain regardless of count.
	*/
	var sink output.EventSink = pausable
	if cfg.EnrichFlags != "" {
		var opts []enrich.EnricherOption
		for _, name := range strings.Split(cfg.EnrichFlags, ",") {
			switch strings.TrimSpace(name) {
				case "time":
					opts = append(opts, enrich.WithTimestamp())
				case "proc":
					opts = append(opts, enrich.WithProcName())
				case "user":
					opts = append(opts, enrich.WithUserName())
				case "all":
					opts = append(opts, enrich.WithTimestamp(),
								enrich.WithProcName(), enrich.WithUserName())
				default:
					fmt.Fprintf(os.Stderr,
					"warning: unknown enricher %q (valid: time, proc, user, all)\n",
					name)
					
			}
		}
		if len(opts) > 0 {
			sink = enrich.Chain(pausable, opts...)
		}
	}

	/*
		Parse the module list and create each module via its registry factory.
		Supports single or comma-separated module names. The same ModuleFlags
		map is passed to every factory--each module's ParseFilterConfig reads
		only the keys it understands and ignores the rest.
	*/
	moduleNames := parseModuleNames(cfg.Module)
	var modules []runner.Module

	for _, name := range moduleNames {
		info, _ := registry.Get(name)	/* already validated by CLI */

		modIface, err := info.Factory(cfg.ModuleFlags, sink)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error creating module: %v\n", err)
			os.Exit(1)
		}

		mod, ok := modIface.(runner.Module)
		if !ok {
			fmt.Fprintf(os.Stderr,
			"module %s does not implement runner.Module\n",
			name)
			os.Exit(1)
		}
		modules = append(modules, mod)
	}

	/*
		Use MultiRunner for both single and multi-module modes. LoadAll loads
		modules sequentially with fail-fast rollback: if module B fails to
		load, module A is automatically closed. CloseAll shuts down in reverse
		order (LIFO).
	*/
	mr := runner.New(modules...)
	if err := mr.LoadAll(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	defer mr.CloseAll()

	/*
		done is closed when the user sends SIGINT/SIGTERM. Module
		Run methods select on this channel to know when to exit.
		RunAll starts each module's Run() in its own goroutine and
		blocks until done is closed and all goroutines return.
	*/
	done := make(chan struct{})
	go mr.RunAll(done)

	/*
		Build the control handler. Until modules implement MapUpdater, we use
		a stub that reports status for all loaded modules but rejects filter
		modifications. When MapUpdater is implemented, this will become a
		routing dispatcher keyed by module name.
	*/
	moduleLabel := strings.Join(mr.Names(), ", ")
	handler := control.NewHandler(&stubUpdater{module: moduleLabel})

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
	sigCh := make(chan os.Signal, 1)	/* buffered channel */
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	for {
		sig := <- sigCh
		
		/* SIGTERM always means immeditate shutdown */
		if sig == syscall.SIGTERM {
			break
		}

		/* SIGINT: pause output and enter interactive mode */
		pausable.Pause()
		fmt.Fprintf(os.Stderr, "\n---  Veil Tracing Paused [%s]  ---\n", moduleLabel)

		/*
			In interactive mode, a second CTRL-C should quit rather than
			be swallowed. We run interactive on stdin; if the user sends
			CTRL-C during the prompt, the signal handler fires and we
			check a flag.
		*/
		interruptedDuringPrompt := make(chan struct{}, 1)
		/*
			stopMonitor exists to remedy the problem observed during program
			runtime. Without this, the following case could be noticed: after
			entering interactive mode and using the "resume" command, the
			program would consume the subsequent interrupt signal instead of
			entering the interactive mode. Once resultCh receives the data and
			assigns that value to result, stopMonitor is closed, which
			signals the goroutine below to return--terminate the gorotuine.
			If stopMonitor was not defined and not closed below, a race
			condition could occur where the goroutine below and the assignment
			to sig above could be waiting for the same channel to have some
			data.
		*/
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
	parseModuleNames splits a comma-separated module string into trimmed
	individual names. For a single module, returns a one-element slice.
*/
func parseModuleNames(raw string) []string {
	parts := strings.Split(raw, ",")
	names := make([]string, 0, len(parts))
	for _, p := range parts {
		name := strings.TrimSpace(p)
		if name != "" {
			names = append(names, name)
		}
	}
	return names
}

/*
	stubUpdater is used when module(s) don't implement MapUpdater.
	It allows status queries but rejects filter modifications.
	When modules implement MapUpdater, this will be replaced by a
	routing dispatcher keyed by module name.
*/
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
