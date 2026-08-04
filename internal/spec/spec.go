// Package spec is the canonical description of a Veil trace: which modules
// to run with which filters, how to shape output, and operational settings.
package spec

type Spec struct {
	Modules []Module
	Output  Output
	Run     Run
}

// Flags matches the key/value shape module factories accept.
type Module struct {
	Name  string
	Flags map[string]string
}

type Output struct {
	Format   string   // "text" (default) or "json"
	Enrich   string   // comma-separated: time, proc, user, all
	Fields   []string // project output to these fields; empty means all
	Count    bool
	CountKey string // implies Count
}

type Run struct {
	ControlPath string
	PprofPath   string
	AssumeYes   bool
}

func (s Spec) Names() []string {
	names := make([]string, len(s.Modules))
	for i, m := range s.Modules {
		names[i] = m.Name
	}
	return names
}
