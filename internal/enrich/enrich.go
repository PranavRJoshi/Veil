// Package enrich provides EventSink middleware that enriches events with
// data resolved from the host system; process names from /proc, usernames
// from /etc/passwd, human-readable timestamps, etc.
//
// Enrichers are sinks that wrap a downstream sink. They inspect event
// fields, add derived fields, and forward to the next sink. They can be
// chained:
//
//	enriched := enrich.NewProcName(
//	    enrich.NewUserName(
//	        enrich.NewTimestamp(baseSink)))
//
// Or combined with the convenience function:
//
//	enriched := enrich.Chain(baseSink,
//	    enrich.WithProcName(),
//	    enrich.WithUserName(),
//	    enrich.WithTimestamp())
package enrich

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// Sink is identical to output.EventSink. Redefined here to avoid a
// circular import. The main package wires them together.
type Sink interface {
	Emit(module string, fields map[string]interface{}) error
	Close() error
}

// Enricher is a function that modifies event fields in place.
type Enricher func(module string, fields map[string]interface{})

// EnrichSink wraps a downstream sink and applies one or more enrichers
// to every event before forwarding.
type EnrichSink struct {
	next      Sink
	enrichers []Enricher
}

// NewEnrichSink creates a middleware sink that applies enrichers in order.
func NewEnrichSink(next Sink, enrichers ...Enricher) *EnrichSink {
	return &EnrichSink{next: next, enrichers: enrichers}
}

func (s *EnrichSink) Emit(module string, fields map[string]interface{}) error {
	for _, fn := range s.enrichers {
		fn(module, fields)
	}
	return s.next.Emit(module, fields)
}

func (s *EnrichSink) Close() error {
	return s.next.Close()
}

// ---------------------------------------------------------------------------
// Chain: convenience builder
// ---------------------------------------------------------------------------

// EnricherOption returns an Enricher for use with Chain.
type EnricherOption func() Enricher

// Chain wraps baseSink with all provided enrichers in a single EnrichSink.
func Chain(baseSink Sink, opts ...EnricherOption) Sink {
	enrichers := make([]Enricher, len(opts))
	for i, opt := range opts {
		enrichers[i] = opt()
	}
	return NewEnrichSink(baseSink, enrichers...)
}

// ---------------------------------------------------------------------------
// ProcName: resolve PID -> process name via /proc/<pid>/comm
// ---------------------------------------------------------------------------

// procNameCache is a simple TTL cache for PID -> comm lookups. PIDs are
// recycled, so entries expire after a short window.
type procNameCache struct {
	mu      sync.RWMutex
	entries map[uint32]procEntry
	ttl     time.Duration
}

type procEntry struct {
	name    string
	fetched time.Time
}

func newProcNameCache(ttl time.Duration) *procNameCache {
	return &procNameCache{
		entries: make(map[uint32]procEntry),
		ttl:     ttl,
	}
}

func (c *procNameCache) get(pid uint32) (string, bool) {
	c.mu.RLock()
	e, ok := c.entries[pid]
	c.mu.RUnlock()
	if !ok || time.Since(e.fetched) > c.ttl {
		return "", false
	}
	return e.name, true
}

func (c *procNameCache) set(pid uint32, name string) {
	c.mu.Lock()
	c.entries[pid] = procEntry{name: name, fetched: time.Now()}
	c.mu.Unlock()
}

// resolveProcName reads /proc/<pid>/comm. Returns empty string on failure.
func resolveProcName(pid uint32) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// WithProcName returns an EnricherOption that resolves PID -> process name.
// If the event has a "pid" field (uint32 or float64 from JSON), it adds
// a "proc_name" field with the resolved comm name from /proc.
//
// Results are cached for 5 seconds to amortize /proc reads under high
// event volume.
func WithProcName() EnricherOption {
	return func() Enricher {
		cache := newProcNameCache(5 * time.Second)
		return func(module string, fields map[string]interface{}) {
			pid, ok := extractUint32(fields, "pid")
			if !ok || pid == 0 {
				return
			}
			if name, hit := cache.get(pid); hit {
				if name != "" {
					fields["proc_name"] = name
				}
				return
			}
			name := resolveProcName(pid)
			cache.set(pid, name)
			if name != "" {
				fields["proc_name"] = name
			}
		}
	}
}

// ---------------------------------------------------------------------------
// UserName: resolve UID -> username via /etc/passwd
// ---------------------------------------------------------------------------

// passwdCache loads /etc/passwd once and caches the uid->name mapping.
type passwdCache struct {
	once  sync.Once
	users map[uint32]string
}

func (c *passwdCache) lookup(uid uint32) string {
	c.once.Do(func() {
		c.users = loadPasswd()
	})
	return c.users[uid]
}

func loadPasswd() map[uint32]string {
	m := make(map[uint32]string)
	f, err := os.Open("/etc/passwd")
	if err != nil {
		return m
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ":", 4)
		if len(parts) < 4 {
			continue
		}
		var uid uint32
		if _, err := fmt.Sscanf(parts[2], "%d", &uid); err == nil {
			m[uid] = parts[0]
		}
	}
	return m
}

// WithUserName returns an EnricherOption that resolves UID -> username.
// If the event has a "uid" field, it adds a "username" field.
func WithUserName() EnricherOption {
	return func() Enricher {
		cache := &passwdCache{}
		return func(module string, fields map[string]interface{}) {
			uid, ok := extractUint32(fields, "uid")
			if !ok {
				return
			}
			if name := cache.lookup(uid); name != "" {
				fields["username"] = name
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Timestamp: format raw kernel timestamp to human-readable
// ---------------------------------------------------------------------------

// WithTimestamp returns an EnricherOption that converts a "timestamp"
// field (uint64 nanoseconds since boot, from bpf_ktime_get_ns) into
// a "time" field with a human-readable wall clock approximation.
//
// The conversion is approximate: it uses the difference between
// time.Now() and the boot-relative timestamp to derive wall time.
// This is the same approach used by bpftool and other eBPF tools.
func WithTimestamp() EnricherOption {
	return func() Enricher {
		// Capture boot time once at enricher creation.
		bootNano := estimateBootNano()
		return func(module string, fields map[string]interface{}) {
			ts, ok := extractUint64(fields, "timestamp")
			if !ok || ts == 0 {
				return
			}
			wall := time.Unix(0, int64(bootNano+ts))
			fields["time"] = wall.Format("15:04:05.000")
		}
	}
}

// estimateBootNano returns an approximate nanosecond wall-clock timestamp
// for system boot, derived from the current time minus /proc/uptime.
func estimateBootNano() uint64 {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	var uptimeSec float64
	if _, err := fmt.Sscanf(string(data), "%f", &uptimeSec); err != nil {
		return 0
	}
	now := time.Now().UnixNano()
	bootNano := now - int64(uptimeSec*1e9)
	if bootNano < 0 {
		return 0
	}
	return uint64(bootNano)
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// extractUint32 tries to pull a uint32 from fields[key], handling both
// the native uint32 type (from Go event structs) and float64 (from JSON
// round-trips).
func extractUint32(fields map[string]interface{}, key string) (uint32, bool) {
	v, ok := fields[key]
	if !ok {
		return 0, false
	}
	switch n := v.(type) {
	case uint32:
		return n, true
	case int:
		return uint32(n), true
	case int64:
		return uint32(n), true
	case float64:
		return uint32(n), true
	default:
		return 0, false
	}
}

// extractUint64 tries to pull a uint64 from fields[key].
func extractUint64(fields map[string]interface{}, key string) (uint64, bool) {
	v, ok := fields[key]
	if !ok {
		return 0, false
	}
	switch n := v.(type) {
	case uint64:
		return n, true
	case int64:
		return uint64(n), true
	case float64:
		return uint64(n), true
	default:
		return 0, false
	}
}
