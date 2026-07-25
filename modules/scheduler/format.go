package scheduler

import (
	"fmt"

	"github.com/PranavRJoshi/Veil/internal/output"
)

/*
	textFormat renders a context-switch event as a text line.
*/
func textFormat(module string, f map[string]interface{}) string {
	base := fmt.Sprintf("CPU=%-3v %-16v PID=%-6v prio=%-3v -> %-16v PID=%-6v prio=%-3v  [%v]",
		f["cpu"],
		f["prev_comm"], f["prev_pid"], f["prev_prio"],
		f["next_comm"], f["next_pid"], f["next_prio"],
		f["prev_state"],
	)
	return output.TimePrefix(f) + base + output.EnrichSuffix(f)
}
