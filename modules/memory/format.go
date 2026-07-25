package memory

import (
	"fmt"

	"github.com/PranavRJoshi/Veil/internal/output"
)

/*
	textFormat renders a page-fault event as a text line.
*/
func textFormat(module string, f map[string]interface{}) string {
	base := fmt.Sprintf("%-16s PID=%-6v TID=%-6v UID=%-5v fault=%-7v addr=%v",
		f["comm"], f["pid"], f["tid"], f["uid"],
		f["evt_type"], f["address"],
	)
	return output.TimePrefix(f) + base + output.EnrichSuffix(f)
}
