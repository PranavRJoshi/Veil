package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/PranavRJoshi/Veil/internal/registry"
)

/*
	Config structure which holds the result of the parsed
	command line argument.
*/
type Config struct {
	Module       string            /* comma-separated module names */
	ModuleFlags  map[string]string /* shared module key=value flags */
	ControlPath  string            /* --control <path>: Unix socket */
	EnrichFlags  string            /* --enrich <opts>: time,proc,user,all */
	ListModules  bool              /* --list-modules */
	ShowHelp     bool              /* --help or -h */
}

/*
	Print out the usage message to the standard error stream.
*/
func usage() {
	u := `Usage: veil --module <name[,name...>] [module-flags...]

Global flags:
  --module <name>    Select the module to run (required)
  --list-modules     List available modules and exit
  --output <format>  Output format: text (default), json
  --enrich <opts>    Enable enrichment: time, proc, user, all (comma-separated)
  --control <path>   Start a Unix socket control server at <path>
  -h, --help         Show this help message

Common filter flags:
  -p, --pid <pid>    Filter events by process ID (comma-separated)
  -u, --uid <uid>    Filter events by user ID (comma-separated)
  -n, --name <n>     Filter events by process name (comm)

Syscall module flags:
  -s, --syscall <name>  Filter events by syscall name (comma-separated)

Files module flags:
  --op <op>             Filter by operation: open, read, write (comma-separated)
  --file <name>		    Filter by filename (substring match)

Network module flags:
  --port <port>         Filter by port number (comma-separated)
`
	fmt.Fprint(os.Stderr, u)
}

/*
	A simple parser which lineraly parses the command line arguments and
	appropriately modifies the Config structure.

	We could probably use standard library function such as 'getopt' or
	similar to parse it though...
*/
func Parse(args []string) (Config, error) {
	cfg := Config{
		ModuleFlags: make(map[string]string),
	}

	/* Veil expects arguments, specially '--module'  */
	if len(args) == 0 {
		usage()
		os.Exit(0)
	}

	i := 0		/* used as index for argument vector */
	/* parse all the supplied command line arguments */
	for i < len(args) {
		arg := args[i]

		switch {
			case arg == "-h" || arg == "--help":
				cfg.ShowHelp = true
				return cfg, nil

			case arg == "--list-modules":
				cfg.ListModules = true
				return cfg, nil

			case arg == "--module":
				if i+1 >= len(args) {
					return cfg, fmt.Errorf("--module requires a value")
				}
				i++
				cfg.Module = args[i]

			case arg == "--output":
				if i+1 >= len(args) {
					return cfg, fmt.Errorf("--output requires a value")
				}
				i++
				cfg.ModuleFlags["output"] = args[i]

			case arg == "--control":
				if i+1 >= len(args) {
					return cfg, fmt.Errorf("--control requires a socket path")
				}
				i++
				cfg.ControlPath = args[i]

			case arg == "--enrich":
				if i+1 >= len(args) {
					return cfg, fmt.Errorf("--enrich requires a value (time, proc, user, all)")
				}
				i++
				cfg.EnrichFlags = args[i]

			/*
				Short-form: -p, -n, -s all take a value argument.
				Long-form: --pid, --name, --syscall, --op, --path
				all take a value argument.

				We normalize them into a consistent key in ModuleFlags.
			*/
			case arg == "-p" || arg == "--pid":
				if i+1 >= len(args) {
					return cfg, fmt.Errorf("%s requires a value", arg)
				}
				i++
				cfg.ModuleFlags["pid"] = args[i]

			case arg == "-u" || arg == "--uid":
				if i+1 >= len(args) {
					return cfg, fmt.Errorf("%s requires a value", arg)
				}
				i++
				cfg.ModuleFlags["uid"] = args[i]

			case arg == "-n" || arg == "--name":
				if i+1 >= len(args) {
					return cfg, fmt.Errorf("%s requires a value", arg)
				}
				i++
				cfg.ModuleFlags["name"] = args[i]

		/* syscall module specific */
			case arg == "-s" || arg == "--syscall":
				if i+1 >= len(args) {
					return cfg, fmt.Errorf("%s requires a value", arg)
				}
				i++
				cfg.ModuleFlags["syscall"] = args[i]

		/* file module specific */
			case arg == "--op":
				if i+1 >= len(args) {
					return cfg, fmt.Errorf("--op requires a value")
				}
				i++
				cfg.ModuleFlags["op"] = args[i]

			case arg == "--file":
				if i+1 >= len(args) {
					return cfg, fmt.Errorf("--file requires a value")
				}
				i++
				cfg.ModuleFlags["file"] = args[i]

		/* network module specific */
			case arg == "--port":
				if i+1 >= len(args) {
					return cfg, fmt.Errorf("--port requires a value")
				}
				i++
				cfg.ModuleFlags["port"] = args[i]

			case strings.HasPrefix(arg, "-"):
				return cfg, fmt.Errorf("unknown flag: %s", arg)

			default:
				return cfg, fmt.Errorf("unexpected argument: %s", arg)
		}

		i++
	}

	/* user must supply one module to work with */
	if cfg.Module == "" {
		return cfg, fmt.Errorf("--module is required; use --list-modules to see available modules")
	}

	/*
		Validate the module name against the registry.
		Supports comma-separated lists for multi-module mode
		(e.g., "syscall,network").
	*/
	for _, name := range strings.Split(cfg.Module, ",") {
		name = strings.TrimSpace(name)
		if name == "" {
			return cfg, fmt.Errorf("empty module name in --module list")
		}
		if _, ok := registry.Get(name); !ok {
			return cfg, fmt.Errorf("unknown module %q; use --list-modules to see available modules", name)
		}
	}


	return cfg, nil
}

/*
	Display the currently supported modules.
*/
func PrintModules() {
	fmt.Println("Available modules:")
	for _, info := range registry.All() {
		fmt.Printf("  %-12s %s\n", info.Name, info.Description)
	}
	fmt.Println()
	fmt.Println("Planned modules:")
	fmt.Println("  scheduler - CPU run queue latency profiling")
	fmt.Println("  memory    - OOM event inspection and page fault tracing")
}

func Usage() {
	usage()
}
