package cli

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/PranavRJoshi/Veil/internal/registry"
)

/*
	Config structure which holds the result of the parsed
	command line argument.
*/
type Config struct {
	Module      string            /* comma-separated module names */
	ModuleFlags map[string]string /* shared module key=value flags */
	ControlPath string            /* --control <path>: Unix socket */
	EnrichFlags string            /* --enrich <opts>: time,proc,user,all */
	CountMode   bool              /* --count: enable count/summary mode */
	CountKey    string            /* --count-by <field>: override aggregation key */
	PprofPath   string            /* --pprof <path>: write CPU profile on exit */
	ListModules bool              /* --list-modules */
	ShowHelp    bool              /* --help or -h */
	AssumeYes   bool              /* --yes: skip high-volume confirmation prompts */
}

const globalUsage = `Usage: veil --module <name[,name...]> [module-flags...]

Global flags:
  --module <name>    Select the module to run (required)
  --list-modules     List available modules and exit
  --output <format>  Output format: text (default), json
  --enrich <opts>    Enable enrichment: time, proc, user, all (comma-separated)
  --count            Enable count/summary mode: suppress live output, show top-N on exit
  --count-by <field> Override aggregation key (default: per-module, e.g., syscall, file, dport)
  --control <path>   Start a Unix socket control server at <path>
  --pprof <path>     Write CPU profile to <path> on exit (use with go tool pprof)
  --yes              Skip confirmation prompts for high-volume tracing
  -h, --help         Show this help message
`

const negationUsage = `
Negation filter examples:
  --pid '!1234'         Exclude PID 1234
  --pid '100,!200'      Allow only PID 100, but never 200
  --syscall '!ioctl'    Exclude ioctl syscalls
  --cpu '!0'            Exclude CPU 0
`

/*
	Print out the usage message to the standard error stream. The module
	flag sections are generated from the registry so adding a module keeps
	the help in sync automatically.
*/
func usage() {
	var b strings.Builder
	b.WriteString(globalUsage)

	if shared := sharedFlags(); len(shared) > 0 {
		b.WriteString("\nCommon filter flags:\n")
		for _, f := range shared {
			b.WriteString(flagLine(f))
		}
	}

	for _, info := range registry.All() {
		specific := moduleSpecificFlags(info)
		if len(specific) == 0 {
			continue
		}
		b.WriteString("\n" + title(info.Name) + " module flags:\n")
		for _, f := range specific {
			b.WriteString(flagLine(f))
		}
	}

	b.WriteString(negationUsage)
	fmt.Fprint(os.Stderr, b.String())
}

/*
	flagLine renders one flag as a help line.
*/
func flagLine(f registry.FlagDef) string {
	name := "--" + f.Name
	if f.Short != "" {
		name = "-" + f.Short + ", " + name
	}
	if f.HasValue {
		name += " <value>"
	}
	return fmt.Sprintf("  %-24s %s\n", name, f.Description)
}

/*
	sharedFlags returns the flags declared by every registered module (pid,
	uid, name), sorted by name.
*/
func sharedFlags() []registry.FlagDef {
	all := registry.All()
	if len(all) == 0 {
		return nil
	}
	counts := make(map[string]int)
	defs := make(map[string]registry.FlagDef)
	for _, info := range all {
		seen := make(map[string]bool)
		for _, f := range info.Flags {
			if seen[f.Name] {
				continue
			}
			seen[f.Name] = true
			counts[f.Name]++
			defs[f.Name] = f
		}
	}
	var shared []registry.FlagDef
	for name, c := range counts {
		if c == len(all) {
			shared = append(shared, defs[name])
		}
	}
	sort.Slice(shared, func(i, j int) bool { return shared[i].Name < shared[j].Name })
	return shared
}

/*
	moduleSpecificFlags returns a module's flags that are not shared by all
	modules.
*/
func moduleSpecificFlags(info registry.ModuleInfo) []registry.FlagDef {
	sharedSet := make(map[string]bool)
	for _, f := range sharedFlags() {
		sharedSet[f.Name] = true
	}
	var specific []registry.FlagDef
	seen := make(map[string]bool)
	for _, f := range info.Flags {
		if sharedSet[f.Name] || seen[f.Name] {
			continue
		}
		seen[f.Name] = true
		specific = append(specific, f)
	}
	return specific
}

/*
	title upper-cases the first byte of a module name for the help listing.
*/
func title(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

/*
	buildFlagTable maps every module flag's long and short name to its
	definition, drawn from the registry.
*/
func buildFlagTable() map[string]registry.FlagDef {
	table := make(map[string]registry.FlagDef)
	for _, f := range registry.AllFlags() {
		table["--"+f.Name] = f
		if f.Short != "" {
			table["-"+f.Short] = f
		}
	}
	return table
}

/*
	A simple parser which linearly parses the command line arguments and
	appropriately modifies the Config structure. Global flags are handled
	explicitly; module flags are looked up in the registry-derived table.
*/
func Parse(args []string) (Config, error) {
	cfg := Config{
		ModuleFlags: make(map[string]string),
	}

	/* Veil expects arguments, especially '--module' */
	if len(args) == 0 {
		usage()
		os.Exit(0)
	}

	flags := buildFlagTable()

	i := 0 /* used as index for argument vector */
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

		case arg == "--yes":
			cfg.AssumeYes = true

		case arg == "--count":
			cfg.CountMode = true

		case arg == "--count-by":
			if i+1 >= len(args) {
				return cfg, fmt.Errorf("--count-by requires a field name")
			}
			i++
			cfg.CountKey = args[i]
			cfg.CountMode = true /* --count-by implies --count */

		case arg == "--pprof":
			if i+1 >= len(args) {
				return cfg, fmt.Errorf("--pprof requires an output file path")
			}
			i++
			cfg.PprofPath = args[i]

		default:
			/*
				Module flags are declared per module in the registry. Look
				the flag up by long or short name; negatable flags split
				their value into allow and <name>_deny via splitAllowDeny.
			*/
			def, ok := flags[arg]
			switch {
			case !ok && strings.HasPrefix(arg, "-"):
				return cfg, fmt.Errorf("unknown flag: %s", arg)
			case !ok:
				return cfg, fmt.Errorf("unexpected argument: %s", arg)
			case !def.HasValue:
				cfg.ModuleFlags[def.Name] = "true"
			default:
				if i+1 >= len(args) {
					return cfg, fmt.Errorf("%s requires a value", arg)
				}
				i++
				if def.Negatable {
					allow, deny := splitAllowDeny(args[i])
					if allow != "" {
						cfg.ModuleFlags[def.Name] = allow
					}
					if deny != "" {
						cfg.ModuleFlags[def.Name+"_deny"] = deny
					}
				} else {
					cfg.ModuleFlags[def.Name] = args[i]
				}
			}
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
