// Package count provides an EventSink that aggregates events by a key
// field and prints a top-N summary on Close(). It is designed for batch
// analysis: run Veil for a period, then see the most frequent events.
//
// Usage in the pipeline:
//
//   countSink := count.NewCountSink(os.Stderr, 10)
//   // pass countSink as the module's EventSink
//   // on shutdown: countSink.Close() prints the summary
//
// The aggregation key is selected automatically per module:
//
//   syscall  -> "syscall" (e.g. openat, read, write)
//   files    -> "filename" (e.g. /etc/passwd)
//   network  -> "dport" (destination port, e.g. 443)
//
// For --count-by variant, the argument to it requires
// a valid key. Upon invalid key, the program will
// prematurely terminate.
//
// TODO: The current implementation of --count-by does
// not honor multi-module mode. It would be helpful to
// introduce comma-separated options in --count-by argument
// and appropriately mark it for respective modules.
package count

import (
	"fmt"
	"io"
	"sort"
	"sync"

	"github.com/PranavRJoshi/Veil/internal/registry"
	"github.com/PranavRJoshi/Veil/internal/suggest"
)

/*
	commonFields are present in every module's events (from the base
	events.Event and the shared toFields keys), so they are valid to
	--count-by regardless of which modules are loaded.
*/
var commonFields = []string{"pid", "tid", "uid", "gid", "timestamp", "comm", "kind"}

/*
	defaultCountKeys maps each registered module to its default aggregation
	field, from ModuleInfo.DefaultCountKey.
*/
func defaultCountKeys() map[string]string {
	m := make(map[string]string)
	for _, info := range registry.All() {
		if info.DefaultCountKey != "" {
			m[info.Name] = info.DefaultCountKey
		}
	}
	return m
}

/*
	validCountFields is the set of field names --count-by accepts: the
	common fields plus every registered module's declared CountFields.
*/
func validCountFields() map[string]bool {
	m := make(map[string]bool, len(commonFields))
	for _, f := range commonFields {
		m[f] = true
	}
	for _, info := range registry.All() {
		for _, f := range info.CountFields {
			m[f] = true
		}
	}
	return m
}

/*
	ValidateKeyField checks whether the given field name is a known
	event field. Returns an error with the list of valid fields if
	the name is not recognized.
*/
func ValidateKeyField(field string) error {
	valid := validCountFields()
	if valid[field] {
		return nil
	}

	names := make([]string, 0, len(valid))
	for k := range valid {
		names = append(names, k)
	}
	sort.Strings(names)
	if hint := suggest.Hint(field, names, 5); hint != "" {
		return fmt.Errorf("unknown count-by field %q%s", field, hint)
	}
	return fmt.Errorf("unknown count-by field %q; valid fields: %v", field, names)
}

/*
	entry tracks the count for a single (module, key) pair.
*/
type entry struct {
	module string
	key    string
	count  uint64
}

/*
	CountSink aggregates events by module and key field, then prints
	a ranked summary to the writer on Close. Thread-safe.
*/
type CountSink struct {
	mu          sync.Mutex
	counts      map[string]map[string]uint64 /* module -> key -> count */
	total       map[string]uint64            /* module -> total events */
	topN        int                          /* how many entries to show */
	w           io.Writer                    /* summary output destination */
	keyField    string                       /* override: use this field for all modules */
	defaultKeys map[string]string            /* per-module default, from the registry */
}

/*
	NewCountSink creates a count sink that prints the top-N summary
	to w when Close is called.
*/
func NewCountSink(w io.Writer, topN int) *CountSink {
	if topN <= 0 {
		topN = 10
	}
	return &CountSink{
		counts:      make(map[string]map[string]uint64),
		total:       make(map[string]uint64),
		topN:        topN,
		w:           w,
		defaultKeys: defaultCountKeys(),
	}
}

/*
	WithKeyField sets a custom key field for all modules, overriding
	the per-module defaults. For example, WithKeyField("comm") would
	aggregate by process name regardless of module.
*/
func (s *CountSink) WithKeyField(field string) *CountSink {
	s.keyField = field
	return s
}

/*
	Emit records the event in the aggregation table. The key is
	extracted from the field map using the module's default key
	field (or the override if set).
*/
func (s *CountSink) Emit(module string, fields map[string]interface{}) error {
	key := s.extractKey(module, fields)

	s.mu.Lock()
	defer s.mu.Unlock()

	s.total[module]++

	m, ok := s.counts[module]
	if !ok {
		m = make(map[string]uint64)
		s.counts[module] = m
	}
	m[key]++

	return nil
}

/*
	Close prints the top-N summary to the writer and returns nil.
*/
func (s *CountSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.counts) == 0 {
		return nil
	}

	fmt.Fprintln(s.w, "")
	fmt.Fprintln(s.w, "--- Veil Event Summary ---")
	fmt.Fprintln(s.w, "")

	/*
		Sort modules alphabetically for consistent output.
	*/
	modules := make([]string, 0, len(s.counts))
	for mod := range s.counts {
		modules = append(modules, mod)
	}
	sort.Strings(modules)

	for _, mod := range modules {
		keyField := s.keyFieldFor(mod)
		total := s.total[mod]
		fmt.Fprintf(s.w, "[%s] %d events (grouped by %s)\n", mod, total, keyField)

		/*
			Build a sorted slice of entries for this module.
		*/
		entries := make([]entry, 0, len(s.counts[mod]))
		for k, c := range s.counts[mod] {
			entries = append(entries, entry{module: mod, key: k, count: c})
		}
		sort.Slice(entries, func(i, j int) bool {
			if entries[i].count != entries[j].count {
				return entries[i].count > entries[j].count
			}
			return entries[i].key < entries[j].key
		})

		/*
			Print top-N entries. If there are fewer than N, print all.
		*/
		limit := s.topN
		if limit > len(entries) {
			limit = len(entries)
		}
		for i := 0; i < limit; i++ {
			e := entries[i]
			pct := float64(e.count) / float64(total) * 100
			fmt.Fprintf(s.w, "  %-40s %8d  (%5.1f%%)\n", e.key, e.count, pct)
		}

		remaining := len(entries) - limit
		if remaining > 0 {
			fmt.Fprintf(s.w, "  ... and %d more unique keys\n", remaining)
		}
		fmt.Fprintln(s.w, "")
	}

	return nil
}

/*
	Snapshot returns a copy of the current counts for a given module.
	This is useful for testing or for periodic reporting without
	closing the sink.
*/
func (s *CountSink) Snapshot(module string) map[string]uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()

	m, ok := s.counts[module]
	if !ok {
		return nil
	}

	snap := make(map[string]uint64, len(m))
	for k, v := range m {
		snap[k] = v
	}
	return snap
}

/*
	Total returns the total event count for a given module.
*/
func (s *CountSink) Total(module string) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.total[module]
}

/*
	extractKey pulls the aggregation key from the event fields.
*/
func (s *CountSink) extractKey(module string, fields map[string]interface{}) string {
	fieldName := s.keyFieldFor(module)

	v, ok := fields[fieldName]
	if !ok {
		/*
			Fall back to "comm" if the default key field isn't present.
			This handles modules that don't have the expected field in
			some events (e.g., network PID=0 events).
		*/
		if comm, ok := fields["comm"]; ok {
			return fmt.Sprintf("%v", comm)
		}
		return "(unknown)"
	}

	return fmt.Sprintf("%v", v)
}

/*
	keyFieldFor returns the aggregation field name for the given module.
*/
func (s *CountSink) keyFieldFor(module string) string {
	if s.keyField != "" {
		return s.keyField
	}
	if f, ok := s.defaultKeys[module]; ok {
		return f
	}
	return "comm"
}
