package syscall

import (
	"fmt"

	"github.com/PranavRJoshi/Veil/internal/output"
)

/*
	textFormat renders a syscall event as a text line. Registered as the
	module's Formatter and dispatched by module name.
*/
func textFormat(module string, f map[string]interface{}) string {
	base := fmt.Sprintf("%-16s PID=%-6v TID=%-6v UID=%-5v GID=%-5v syscall=%v(%v)",
		f["comm"], f["pid"], f["tid"], f["uid"], f["gid"],
		f["syscall"], f["syscall_nr"],
	)
	return output.TimePrefix(f) + base + output.EnrichSuffix(f)
}
