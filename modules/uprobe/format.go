package uprobe

import (
	"fmt"

	"github.com/PranavRJoshi/Veil/internal/output"
)

/*
	textFormat renders a uprobe event as a text line. The latency suffix
	appears only when a duration was measured (latency mode).
*/
func textFormat(module string, f map[string]interface{}) string {
	base := fmt.Sprintf("%-16v PID=%-6v %v:%v",
		f["comm"], f["pid"], f["path"], f["symbol"])

	if d, ok := f["duration_ns"].(uint64); ok && d > 0 {
		base += "  " + formatDuration(d)
	}

	return output.TimePrefix(f) + base + output.EnrichSuffix(f)
}

/*
	formatDuration renders a nanosecond count in the largest unit that keeps
	the value readable.
*/
func formatDuration(ns uint64) string {
	switch {
	case ns >= 1_000_000_000:
		return fmt.Sprintf("%.2fs", float64(ns)/1e9)
	case ns >= 1_000_000:
		return fmt.Sprintf("%.2fms", float64(ns)/1e6)
	case ns >= 1_000:
		return fmt.Sprintf("%.2fus", float64(ns)/1e3)
	default:
		return fmt.Sprintf("%dns", ns)
	}
}
