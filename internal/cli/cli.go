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

Negation filter examples:
  --pid '!1234'         Exclude PID 1234
  --pid '100,!200'      Allow only PID 100, but never 200
  --syscall '!ioctl'    Exclude ioctl syscalls
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
				/*
					We pass a string that may be a comma separated numbers
					which may optionally include the '!' character, indicating
					exclusion (negation). This function returns two strings,
					which are stored in allow and deny variables below.
				*/
				allow, deny := splitAllowDeny(args[i])
				if allow != "" {
					cfg.ModuleFlags["pid"] = allow
				}
				if deny != "" {
					cfg.ModuleFlags["pid_deny"] = deny
				}

			case arg == "-u" || arg == "--uid":
				if i+1 >= len(args) {
					return cfg, fmt.Errorf("%s requires a value", arg)
				}
				i++
				allow, deny := splitAllowDeny(args[i])
				if allow != "" {
					cfg.ModuleFlags["uid"] = allow
				}
				if deny != "" {
					cfg.ModuleFlags["uid_deny"] = deny
				}

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
				allow, deny := splitAllowDeny(args[i])
				if allow != "" {
					cfg.ModuleFlags["syscall"] = allow
				}
				if deny != "" {
					cfg.ModuleFlags["syscall_deny"] = deny
				}

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
				allow, deny := splitAllowDeny(args[i])
				if allow != "" {
					cfg.ModuleFlags["port"] = allow
				}
				if deny != "" {
					cfg.ModuleFlags["port_deny"] = deny
				}

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

/*
	splitAllowDeny separates a comma-separated value string into allow and deny
	components. Values prefixed with '!' are deny values.

	NOTE: In interactive mode, shell programs interpret the '!' character as
	"history expansion" character. The sequence of characters '!!' is used to
	indicate execution of previous command. Likewise, the sequence of characters
	'!:<n>', where '<n>' is a non-negative integer indicates '<n>'th argument
	of previous command. To overcome this, when using the negation filter, the
	user should explicitly wrap the argument in single quotes. For example,
	instead of writing:

			# ./bin/veil --module syscall --pid !100

	one should write:

			# ./bin/veil --module syscall --pid '!100'

	such that it will be correctly interpreted.

	The '!' is stripped from deny values in the returned string.
*/
func splitAllowDeny(raw string) (allow, deny string) {
	var allows, denies []string

	for _, s := range strings.Split(raw, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}

		if strings.HasPrefix(s, "!") {
			v := strings.TrimPrefix(s, "!")
			if v != "" {
				denies = append(denies, v)
			}
		} else {
			allows = append(allows, s)
		}
	}

	return strings.Join(allows, ","), strings.Join(denies, ",")
}
