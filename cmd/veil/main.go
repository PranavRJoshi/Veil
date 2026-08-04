package main

import (
	"bufio"
	"fmt"
	"os"
	"os/signal"
	"runtime/pprof"
	"sort"
	"strings"
	"syscall"

	"github.com/PranavRJoshi/Veil/internal/cli"
	"github.com/PranavRJoshi/Veil/internal/config"
	"github.com/PranavRJoshi/Veil/internal/control"
	"github.com/PranavRJoshi/Veil/internal/count"
	"github.com/PranavRJoshi/Veil/internal/enrich"
	"github.com/PranavRJoshi/Veil/internal/exterrs"
	"github.com/PranavRJoshi/Veil/internal/kernel"
	"github.com/PranavRJoshi/Veil/internal/output"
	"github.com/PranavRJoshi/Veil/internal/registry"
	"github.com/PranavRJoshi/Veil/internal/runner"
	"github.com/PranavRJoshi/Veil/internal/spec"

	/*
		Blank imports trigger init() in each module package, which
		calls registry.Register(). Adding a new module to Veil
		requires only adding one blank import line here.
	*/
	_ "github.com/PranavRJoshi/Veil/modules/files"
	_ "github.com/PranavRJoshi/Veil/modules/memory"
	_ "github.com/PranavRJoshi/Veil/modules/network"
	_ "github.com/PranavRJoshi/Veil/modules/scheduler"
	_ "github.com/PranavRJoshi/Veil/modules/syscall"
	_ "github.com/PranavRJoshi/Veil/modules/uprobe"
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
		Verify the kernel can run the modules before doing any work, so an
		unsupported kernel reports what is missing instead of failing with a
		cryptic load error.
	*/
	if err := kernel.Preflight(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	sp, err := loadSpec(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	/*
		CPU profiling: start recording CPU samples using Go's runtime/pprof.
		The profile is written to the specified file path when the program
		exits via the deferred StopCPUProfile call. The output can be
		analyzed using:

		        go tool pprof -http=:8080 <path>

		This opens an interactive browser UI with flamegraphs, top functions,
		source annotation, and call graphs.
	*/
	if sp.Run.PprofPath != "" {
		pprofFile, err := os.Create(sp.Run.PprofPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "pprof: %v\n", err)
			os.Exit(1)
		}
		if err := pprof.StartCPUProfile(pprofFile); err != nil {
			pprofFile.Close()
			fmt.Fprintf(os.Stderr, "pprof: %v\n", err)
			os.Exit(1)
		}
		defer func() {
			pprof.StopCPUProfile()
			pprofFile.Close()
			fmt.Fprintf(os.Stderr, "CPU profile written to %s\n", sp.Run.PprofPath)
		}()
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
							+-> wrapped by CountSink (optional)
									|
									+-> passed to module factories as their output target

		The optional Sink wrappers EnrichSink and CountSink are only in use
		if the user passed appropriate flags in command-line arguments; --enrich
		and --count[-by] respectively.

		Regarding enrichment layer, when paused, events are dropped at the PausableSink
		level, before enrichment runs, thus avoiding unnecessary /proc reads during
		pause.

		For CountSink, if the EventSink is wrapped by CountSink, the live reporting
		is suppressed in favor of overall summary at the termination of program. Once
		Close() of CountSink method is called, the report is shown to the user.
	*/
	var baseSink output.EventSink
	switch sp.Output.Format {
	case "json":
		js := output.NewJSONSink(os.Stdout)
		if len(sp.Output.Fields) > 0 {
			js.WithFields(sp.Output.Fields)
		}
		baseSink = js
	default:
		format := output.DispatchTextFormat(moduleFormatters())
		if len(sp.Output.Fields) > 0 {
			format = output.FieldsFormat(sp.Output.Fields)
		}
		baseSink = output.NewTextSink(os.Stdout, format)
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
	if sp.Output.Enrich != "" {
		var opts []enrich.EnricherOption
		for _, name := range strings.Split(sp.Output.Enrich, ",") {
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
		Count/summary mode: when --count or --count-by is specified, replace the
		normal output sink with a CountSink that aggregates events and prints a
		top-N summary. In this mode, live events are **not** streamed to standard
		output stream--only the summary is shown (on standard error stream).

		Enrichment (--enrich) has no effect in count mode since the summary output
		does not include the enriched fields. Warn the user if both are
		specified.
	*/
	var countSink *count.CountSink
	if sp.Output.Count {
		if sp.Output.CountKey != "" {
			/* First check if the user provided a valid key */
			if err := count.ValidateKeyField(sp.Output.CountKey); err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n", err)
				os.Exit(1)
			}
		}
		if sp.Output.Enrich != "" {
			fmt.Fprintln(os.Stderr, "warning: --enrich has no observable effect in conjunction with --count")
		}
		if len(sp.Output.Fields) > 0 {
			fmt.Fprintln(os.Stderr, "warning: --fields has no observable effect in conjunction with --count")
		}
		countSink = count.NewCountSink(os.Stderr, 10)
		if sp.Output.CountKey != "" {
			/* Now assign the key to the Sink */
			countSink.WithKeyField(sp.Output.CountKey)
		}
		sink = countSink
	}

	/*
		Parse the module list and create each module via its registry factory.
		Supports single or comma-separated module names. The same ModuleFlags
		map is passed to every factory--each module's ParseFilterConfig reads
		only the keys it understands and ignores the rest.
	*/
	var modules []runner.Module

	for _, m := range sp.Modules {
		info, _ := registry.Get(m.Name) /* already validated by CLI */

		mod, err := info.Factory(m.Flags, sink)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error creating module: %v\n", err)
			os.Exit(1)
		}
		modules = append(modules, mod)
	}

	/*
		Confirm before high-volume tracing floods the terminal. Runs after
		construction so a config error (a missing --uprobe target) surfaces
		before the prompt. Only uprobe is wired today; highVolumeReason is
		the seam for a per-module policy later.
	*/
	for _, m := range sp.Modules {
		reason := highVolumeReason(m.Name, m.Flags)
		if reason == "" {
			continue
		}
		if err := confirmHighVolume(reason, sp.Run.AssumeYes); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
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
		Build the control handler. Every module implements MapUpdater, so
		buildUpdater routes commands directly (single module) or through a
		compositeUpdater keyed by module name (multi-module). The stub is
		only a fallback for a module that drops MapUpdater support.
	*/
	moduleLabel := strings.Join(mr.Names(), ", ")
	updater := buildUpdater(modules, sp.Names())
	handler := control.NewHandler(updater)

	/*
		Start socket server if '--control' was specified
	*/
	if sp.Run.ControlPath != "" {
		srv := control.NewServer(sp.Run.ControlPath, handler)
		if err := srv.Start(); err != nil {
			fmt.Fprintf(os.Stderr, "warning: control socket %v\n", err)
		} else {
			defer srv.Stop()
			fmt.Fprintf(os.Stderr, "control socket: %s\n", sp.Run.ControlPath)
		}
	}

	moduleList := strings.Join(sp.Names(), ",")
	if sp.Output.Count {
		fmt.Fprintf(os.Stderr,
			"Veil [%s] running in count mode, press CTRL-C to stop and show summary\n",
			moduleList)
	} else {
		fmt.Fprintf(os.Stderr,
			"Veil [%s] running, press CTRL-C to pause and modify filters\n",
			moduleList)
	}

	/*
		Two-stage signal handling:

		First CTRL-C  - pause events, enter interactive control
		"resume"      - resume events, go back to tracing
		"quit"/exit   - shut down
		Second CTRL-C - shut down (while in interactive mode)
	*/
	sigCh := make(chan os.Signal, 1) /* buffered channel */
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	for {
		sig := <-sigCh

		/* SIGTERM always means immediate shutdown */
		if sig == syscall.SIGTERM {
			break
		}

		/* SIGINT: pause output and enter interactive mode */
		pausable.Pause()
		fmt.Fprintf(os.Stderr, "\n---  Veil Tracing Paused [%s]  ---\n", moduleLabel)

		/*
			readline intercepts CTRL-C in raw mode (returns ErrInterrupt) so
			SIGINT does not reach sigCh during the prompt. cancelInteractive is
			only closed on an external signal (SIGTERM / kill -INT); Interactive
			watches it and calls rl.Close() to unblock Readline(). Because no
			goroutine blocks on sigCh between the inner select and the next
			outer-loop iteration, the previous signal-consuming race cannot
			occur here.
		*/
		cancelInteractive := make(chan struct{})
		resultCh := make(chan control.InteractiveResult, 1)
		go func() {
			resultCh <- control.Interactive(handler, os.Stderr, cancelInteractive)
		}()

		var result control.InteractiveResult
		select {
		case result = <-resultCh:
			/* readline returned normally (resume / quit / CTRL-C / CTRL-D) */
		case <-sigCh:
			/* external signal during interactive mode */
			close(cancelInteractive)
			<-resultCh /* wait for readline to restore the terminal */
			result = control.ResultQuit
		}

		if result == control.ResultQuit {
			break
		}

		/* Resume tracing: print the banner before calling Resume so the
		   marker always appears before events start flowing again. */
		dropped := pausable.DroppedCount()
		if dropped > 0 {
			fmt.Fprintf(os.Stderr, "---  resumed (%d events dropped while paused)  ---\n", dropped)
		} else {
			fmt.Fprintf(os.Stderr, "---  resumed  ---\n")
		}
		pausable.Resume()

		/*
			Reset the signal listener for the next CTRL-C cycle. Drain any
			pending signals.
		*/
		signal.Reset(syscall.SIGINT)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	}

	close(done)

	/*
		If count mode is active, print the summary now that all modules have
		stopped producing events.
	*/
	if countSink != nil {
		countSink.Close()
	}
}

/*
	moduleFormatters builds the module-name to text-formatter map that the
	text sink dispatches on, from each registered module's Formatter. Lives
	here because internal/output cannot import the registry.
*/
func moduleFormatters() map[string]output.TextFormatFunc {
	formatters := make(map[string]output.TextFormatFunc)
	for _, info := range registry.All() {
		if info.Formatter != nil {
			formatters[info.Name] = info.Formatter
		}
	}
	return formatters
}

/*
	loadSpec resolves the run's spec. With --config the file governs modules
	and output; any trace-defining CLI flags are ignored with a warning, while
	operational flags (control, pprof, yes) layer on top and win when set.
	Without --config the spec comes entirely from the parsed flags.
*/
func loadSpec(cfg cli.Config) (spec.Spec, error) {
	if cfg.ConfigPath == "" {
		return cfg.ToSpec(), nil
	}

	sp, err := config.Load(cfg.ConfigPath)
	if err != nil {
		return spec.Spec{}, err
	}

	if ignored := cfg.TraceFlags(); len(ignored) > 0 {
		fmt.Fprintf(os.Stderr, "warning: --config governs the run; ignoring %s\n", strings.Join(ignored, ", "))
	}

	if cfg.ControlPath != "" {
		sp.Run.ControlPath = cfg.ControlPath
	}
	if cfg.PprofPath != "" {
		sp.Run.PprofPath = cfg.PprofPath
	}
	if cfg.AssumeYes {
		sp.Run.AssumeYes = true
	}
	return sp, nil
}

/*
	highVolumeReason returns a warning message if the module's configuration
	will flood output, or "" if not. Only uprobe without a pid/uid filter is
	wired today; this is where a per-module policy would hook in.
*/
func highVolumeReason(name string, flags map[string]string) string {
	if name != "uprobe" {
		return ""
	}
	if flags["pid"] != "" || flags["uid"] != "" {
		return ""
	}
	return fmt.Sprintf("uprobe %q has no --pid/--uid filter and will trace every process", flags["uprobe"])
}

/*
	confirmHighVolume guards a firehose action. On a terminal it prompts; with
	no terminal it refuses unless assumeYes (--yes) is set, so a piped or
	scripted invocation never blocks on input that will not arrive. The prompt
	defaults to no: only an explicit "y" proceeds.
*/
func confirmHighVolume(reason string, assumeYes bool) error {
	if assumeYes {
		return nil
	}

	info, err := os.Stdin.Stat()
	interactive := err == nil && info.Mode()&os.ModeCharDevice != 0
	if !interactive {
		return fmt.Errorf("%s; pass --pid to filter or --yes to proceed", reason)
	}

	fmt.Fprintf(os.Stderr, "%s\nProceed? [y/N]: ", reason)
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	if strings.TrimSpace(strings.ToLower(line)) == "y" {
		return nil
	}
	return fmt.Errorf("aborted")
}

/*
	buildUpdater constructs a MapUpdater from the loaded modules. If only one
	module is loaded and it implements MapUpdater, use it directly (no module
	prefix needed in commands). For multiple modules, build a
	compositeUpdater that dispatches by module name.

	If a module doesn't implement MapUpdater, it gets a stub entry that reports
	status but rejects filter modification.
*/

func buildUpdater(modules []runner.Module, names []string) control.MapUpdater {
	updaters := make(map[string]control.MapUpdater, len(modules))
	for i, mod := range modules {
		if mu, ok := mod.(control.MapUpdater); ok {
			updaters[names[i]] = mu
		} else {
			updaters[names[i]] = &stubUpdater{module: names[i]}
		}
	}

	/*
		Single module mode: use the module's updater directly so commands like
		"add pid 1234" work without a module prefix.
	*/
	if len(updaters) == 1 {
		for _, u := range updaters {
			return u
		}
	}

	ownership := make(map[string][]string)
	for _, info := range registry.All() {
		for _, mapName := range info.MapNames {
			ownership[mapName] = append(ownership[mapName], info.Name)
		}
	}

	return &compositeUpdater{updaters: updaters, mapOwnership: ownership}
}

/*
	compositeUpdater dispatches control commands to the correct module's
	MapUpdater based on a module prefix in the map name.

	Plain map name ("pid", "port"):
		Routes via mapOwnership. Shared maps (pid, uid) are sent to all loaded
		modules. Module-specific maps (syscall, port) are sent to their owner only.

	Module-qualified map name ("network.port", "syscall.pid"):
		Routes directly to the named module. This allows targeting a specific
		module's map in multi-module mode, e.g., adding a PID filter only to
		the network module without affecting syscall.
		The Handler builds these from 4-part commands (see HandleCommand())
*/
type compositeUpdater struct {
	updaters     map[string]control.MapUpdater
	mapOwnership map[string][]string
}

/*
	resolveTargets determines which modules and what map name have to use for
	a given (possibly qualified) map name.

	NOTE: In the current implementation, checking for a single module here is
	redundant: buildUpdater() only creates a compositeUpdater when the user
	requests multiple modules. In single-module mode the module's own
	MapUpdater is used directly, so compositeUpdater never sees that case.

	"pid"           -> targets all loaded modules, map name "pid"
	"network.port"  -> targets only network module, map name "port"
	"files.uid"     -> targets only file module, map name "uid"
*/
func (c *compositeUpdater) resolveTargets(mapName string) (targets []string, realMap string, err error) {
	if dot := strings.IndexByte(mapName, '.'); dot >= 0 {
		/* Module-qualified: check if loaded*/
		modName := mapName[:dot]
		realMap = mapName[dot+1:]
		if _, exists := c.updaters[modName]; !exists {
			return nil, "", fmt.Errorf("module %q is not loaded (loaded: %s)", modName, strings.Join(c.loadedNames(), ", "))
		}
		return []string{modName}, realMap, nil
	}

	/* Plain map name: route via ownership, restricted to loaded modules */
	owners, ok := c.mapOwnership[mapName]
	if !ok {
		return nil, "", fmt.Errorf("unknown filter map %q (use help)", mapName)
	}
	loaded := make([]string, 0, len(owners))
	for _, mod := range owners {
		if _, exists := c.updaters[mod]; exists {
			loaded = append(loaded, mod)
		}
	}
	if len(loaded) == 0 {
		return nil, "", fmt.Errorf("no loaded module owns map %q (loaded: %s)", mapName, strings.Join(c.loadedNames(), ", "))
	}
	return loaded, mapName, nil
}

func (c *compositeUpdater) loadedNames() []string {
	names := make([]string, 0, len(c.updaters))
	for name := range c.updaters {
		names = append(names, name)
	}

	return names
}

func (c *compositeUpdater) AddFilter(mapName string, key uint64) error {
	targets, realMap, err := c.resolveTargets(mapName)
	if err != nil {
		return err
	}
	var errs []error
	for _, name := range targets {
		if u, exists := c.updaters[name]; exists {
			if err := u.AddFilter(realMap, key); err != nil {
				errs = append(errs, err)
			}
		}
	}

	return exterrs.Join(errs)
}

func (c *compositeUpdater) DelFilter(mapName string, key uint64) error {
	targets, realMap, err := c.resolveTargets(mapName)
	if err != nil {
		return err
	}

	/*
		For shared maps, a key may exist in some modules but not others
		(e.g. added via a module-qualified name). Collect all per-module
		errors so the caller sees every failure, not just the last one.
	*/
	var errs []error
	for _, name := range targets {
		if u, exists := c.updaters[name]; exists {
			if err := u.DelFilter(realMap, key); err != nil {
				errs = append(errs, err)
			}
		}
	}

	return exterrs.Join(errs)
}

func (c *compositeUpdater) ListFilters(mapName string) ([]uint64, error) {
	targets, realMap, err := c.resolveTargets(mapName)
	if err != nil {
		return nil, err
	}
	/*
		List from the first loaded target. For shared maps via plain names,
		this list from one module (they share the same filter semantics). For
		qualified names, it lists from the specified module.
	*/
	for _, name := range targets {
		if u, exists := c.updaters[name]; exists {
			return u.ListFilters(realMap)
		}
	}

	return nil, fmt.Errorf("no loaded module owns map %q", mapName)
}

/*
	ListFiltersDetailed implements control.DetailedLister. It collects filter
	keys from every target module so the interactive list command can show
	per-module results instead of only the first match.
*/
func (c *compositeUpdater) ListFiltersDetailed(mapName string) (map[string][]uint64, error) {
	targets, realMap, err := c.resolveTargets(mapName)
	if err != nil {
		return nil, err
	}
	result := make(map[string][]uint64, len(targets))
	for _, name := range targets {
		if u, exists := c.updaters[name]; exists {
			keys, err := u.ListFilters(realMap)
			if err != nil {
				return nil, fmt.Errorf("module %s: %w", name, err)
			}
			result[name] = keys
		}
	}
	return result, nil
}

/*
	ValidateFilter routes validation to each target module that implements
	control.FilterValidator, combining their soft warnings and blocking on
	the first hard error. Routing errors are left for AddFilter to report.
*/
func (c *compositeUpdater) ValidateFilter(mapName string, key uint64) (string, error) {
	targets, realMap, err := c.resolveTargets(mapName)
	if err != nil {
		return "", nil
	}
	var warns []string
	for _, name := range targets {
		v, ok := c.updaters[name].(control.FilterValidator)
		if !ok {
			continue
		}
		w, err := v.ValidateFilter(realMap, key)
		if err != nil {
			return "", err
		}
		if w != "" {
			warns = append(warns, w)
		}
	}
	return strings.Join(warns, "; "), nil
}

func (c *compositeUpdater) ClearFilters(mapName string) error {
	targets, realMap, err := c.resolveTargets(mapName)
	if err != nil {
		return err
	}

	var errs []error
	for _, name := range targets {
		if u, exists := c.updaters[name]; exists {
			if err := u.ClearFilters(realMap); err != nil {
				errs = append(errs, err)
			}
		}
	}

	return exterrs.Join(errs)
}

func (c *compositeUpdater) Status() string {
	names := make([]string, 0, len(c.updaters))
	for name := range c.updaters {
		names = append(names, name)
	}
	sort.Strings(names)

	parts := make([]string, 0, len(names))
	for _, name := range names {
		parts = append(parts, c.updaters[name].Status())
	}

	return strings.Join(parts, "\n")
}

/*
	stubUpdater is the fallback for a module that does not implement
	MapUpdater. It allows status queries but rejects filter modifications.
	Every current module implements MapUpdater, so this only guards
	against future modules that omit runtime filter support.
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
