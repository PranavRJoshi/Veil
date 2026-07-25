package network

import (
	"fmt"

	"github.com/PranavRJoshi/Veil/internal/output"
)

/*
	textFormat renders a TCP connection lifecycle event as a text line.
*/
func textFormat(module string, f map[string]interface{}) string {
	base := fmt.Sprintf("%-16s PID=%-6v %-12v %v:%v -> %v:%v [%v->%v]",
		f["comm"], f["pid"], f["evt_type"],
		f["saddr"], f["sport"],
		f["daddr"], f["dport"],
		f["oldstate"], f["newstate"],
	)
	return output.TimePrefix(f) + base + output.EnrichSuffix(f)
}
