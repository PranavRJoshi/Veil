package output

import "fmt"

/*
	TimePrefix and EnrichSuffix format the enrichment fields shared by every
	module's text formatter. A module's formatter renders only its own base
	line and wraps it with these, so the enrichment convention lives in one
	place instead of being repeated per module.

	Both return an empty string when their fields are absent, so a formatter
	works unchanged with or without --enrich.
*/
func TimePrefix(f map[string]interface{}) string {
	if t, ok := f["time"]; ok {
		return fmt.Sprintf("[%v] ", t)
	}
	return ""
}

func EnrichSuffix(f map[string]interface{}) string {
	var s string
	if u, ok := f["username"]; ok {
		s += fmt.Sprintf(" user=%v", u)
	}
	if p, ok := f["proc_name"]; ok {
		s += fmt.Sprintf(" proc=%v", p)
	}
	return s
}

/*
	DispatchTextFormat returns a TextFormatFunc that routes each event to
	its module's formatter, falling back to the generic format for modules
	absent from the map. The map is built by main from the registered
	modules, since this package cannot import the registry.
*/
func DispatchTextFormat(formatters map[string]TextFormatFunc) TextFormatFunc {
	return func(module string, f map[string]interface{}) string {
		if fn, ok := formatters[module]; ok {
			return fn(module, f)
		}
		return genericTextFormat(module, f)
	}
}
