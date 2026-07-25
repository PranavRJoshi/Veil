package files

import (
	"fmt"

	"github.com/PranavRJoshi/Veil/internal/output"
)

/*
	textFormat renders a file-access event as a text line.
*/
func textFormat(module string, f map[string]interface{}) string {
	base := fmt.Sprintf("%-16s PID=%-6v UID=%-5v op=%-5v filename=%v",
		f["comm"], f["pid"], f["uid"], f["op"], f["filename"],
	)
	return output.TimePrefix(f) + base + output.EnrichSuffix(f)
}
