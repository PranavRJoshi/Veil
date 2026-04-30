package output

import "fmt"

/*
	Module-specific text formatters.
	Each reproduces the existing fmt.Printf output from the corresponding
	module's Run() method, so switching to the sink is a transparent change.
	
	SyscallTextFormat formats syscall events as the original module does.
	If enrichment fields (time, username, proc_name) are present, they are included in the output. This allows the formatter to work transparently with or without enrichment enabled.
*/
func SyscallTextFormat(module string, f map[string]interface{}) string {
	/* timestamp is followed by actual module-specific information */
	var prefix string
	if t, ok := f["time"]; ok {
		prefix = fmt.Sprintf("[%v] ", t)
	}

	/* module-specific information */
	base := fmt.Sprintf("%-16s PID=%-6v TID=%-6v UID=%-5v GID=%-5v syscall=%v(%v)",
		f["comm"], f["pid"], f["tid"], f["uid"], f["gid"],
		f["syscall"], f["syscall_nr"],
	)

	/* username and proc_name is displayed after module-specifc information */
	var suffix string
	if u, ok := f["username"]; ok {
		suffix += fmt.Sprintf(" user=%v", u)
	}
	if p, ok := f["proc_name"]; ok {
		suffix += fmt.Sprintf(" proc=%v", p)
	}
	return prefix + base + suffix
}

// FilesTextFormat formats file-access events.
func FilesTextFormat(module string, f map[string]interface{}) string {
	var prefix string
	if t, ok := f["time"]; ok {
		prefix = fmt.Sprintf("[%v] ", t)
	}

	base := fmt.Sprintf("%-16s PID=%-6v UID=%-5v op=%-5v filename=%v",
		f["comm"], f["pid"], f["uid"], f["op"], f["filename"],
	)

	var suffix string
	if u, ok := f["username"]; ok {
		suffix += fmt.Sprintf(" user=%v", u)
	}
	if p, ok := f["proc_name"]; ok {
		suffix += fmt.Sprintf(" proc=%v", p)
	}

	return prefix + base + suffix
}

// NetworkTextFormat formats TCP connection lifecycle events.
func NetworkTextFormat(module string, f map[string]interface{}) string {
	var prefix string
	if t, ok := f["time"]; ok {
		prefix = fmt.Sprintf("[%v] ", t)
	}

	base := fmt.Sprintf("%-16s PID=%-6v %-12v %v:%v -> %v:%v [%v->%v]",
		f["comm"], f["pid"], f["evt_type"],
		f["saddr"], f["sport"],
		f["daddr"], f["dport"],
		f["oldstate"], f["newstate"],
	)

	var suffix string
	if u, ok := f["username"]; ok {
		suffix += fmt.Sprintf(" user=%v", u)
	}
	if p, ok := f["proc_name"]; ok {
		suffix += fmt.Sprintf(" proc=%v", p)
	}

	return prefix + base + suffix
}

/*
	ModuleFormatters maps module names to their text formatters.
	Used by the CLI to select the right formatter when --output=text (default).
*/
var ModuleFormatters = map[string]TextFormatFunc{
	"syscall": SyscallTextFormat,
	"files":   FilesTextFormat,
	"network": NetworkTextFormat,
}

/*
	DispatchTextFormat returns a TextFormatFunc that dispatches to
	per-module formatters based on the module name. Falls back to the
	generic format for unknown modules. This is the default formatter
	for multi-module mode where events from different modules are
	interleaved on the same output stream.
*/
func DispatchTextFormat() TextFormatFunc {
	return func(module string, f map[string]interface{}) string {
		if fn, ok := ModuleFormatters[module]; ok {
			return fn(module, f)
		}
		return genericTextFormat(module, f)
	}
}
