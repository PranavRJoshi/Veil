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
)

/*
	defaultKeyFields maps module names to the most useful aggregation
	field for that module. These are the field names produced by each
	module's toFields function.
*/
var defaultKeyFields = map[string]string{
	"syscall": "syscall",
	"files":   "filename",
	"network": "dport",
	"scheduler": "next_comm",
	"memory": "evt_type",
}

/*
	validKeyFields is the complete set of field names that can appear
	in event field maps across all modules. This is used to validate
	the --count-by argument at parse time.
 
	Common fields (all modules): pid, tid, uid, gid, timestamp, comm, kind
	Syscall: syscall, syscall_nr
	Files: filename, op
	Network: saddr, daddr, sport, dport, evt_type, oldstate, newstate
	Scheduler: prev_pid, next_pid, prev_tid, next_tid, cpu, prev_state,
	           prev_prio, next_prio, prev_comm, next_comm
	Memory: evt_type (shared with network), address
*/
var validKeyFields = map[string]bool{
	/* common */
	"pid": true, "tid": true, "uid": true, "gid": true,
	"timestamp": true, "comm": true, "kind": true,
	/* syscall */
	"syscall": true, "syscall_nr": true,
	/* files */
	"filename": true, "op": true,
	/* network */
	"saddr": true, "daddr": true, "sport": true, "dport": true,
	"evt_type": true, "oldstate": true, "newstate": true,
	/* scheduler */
	"prev_pid": true, "next_pid": true, "prev_tid": true, "next_tid": true,
	"cpu": true, "prev_state": true, "prev_prio": true, "next_prio": true,
	"prev_comm": true, "next_comm": true,
	/* memory */
	"address": true,
}

/*
	ValidateKeyField checks whether the given field name is a known
	event field. Returns an error with the list of valid fields if
	the name is not recognized.
*/
func ValidateKeyField(field string) error {
	if validKeyFields[field] {
		return nil
	}

	valid := make([]string, 0, len(validKeyFields))
	for k := range validKeyFields {
		valid = append(valid, k)
	}
	sort.Strings(valid)
	return fmt.Errorf("unknown count-by field %q; valid fields: %v", field, valid)
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
	mu       sync.Mutex
	counts   map[string]map[string]uint64 /* module -> key -> count */
	total    map[string]uint64            /* module -> total events */
	topN     int                          /* how many entries to show */
	w        io.Writer                    /* summary output destination */
	keyField string                       /* override: use this field for all modules */
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
		counts: make(map[string]map[string]uint64),
		total:  make(map[string]uint64),
		topN:   topN,
		w:      w,
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
	if f, ok := defaultKeyFields[module]; ok {
		return f
	}
	return "comm"
}
