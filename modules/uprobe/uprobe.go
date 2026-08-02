package uprobe

//go:generate bpf2go -cc clang -target amd64,arm64 -cflags "-O2 -g -Wall" UprobeTracer ../../bpf/uprobe_tracer.bpf.c

/*
	Uprobe module for Veil.

	Attaches a uprobe to a user-chosen binary:symbol, given at load time via
	--uprobe. Each call to the probed function emits an event. With --latency
	a uretprobe is attached too, and the entry-to-return duration is reported.

	The attach target is not fixed in the BPF source: the object is generic
	and Load selects the symbol. Only entry/return timing is captured, no
	function arguments, so the object stays architecture-neutral.

	Kernel-side filters: PID, UID (allow + deny)
	Userspace filters: process name (comm substring match)
*/

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/PranavRJoshi/Veil/internal/bpfutil"
	"github.com/PranavRJoshi/Veil/internal/events"
	"github.com/PranavRJoshi/Veil/internal/exterrs"
	"github.com/PranavRJoshi/Veil/internal/loader"
	"github.com/PranavRJoshi/Veil/internal/output"
	"github.com/PranavRJoshi/Veil/internal/registry"
	"github.com/PranavRJoshi/Veil/internal/runner"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

func init() {
	registry.Register(registry.ModuleInfo{
		Name:        "uprobe",
		Description: "Trace a userspace function via uprobe (--uprobe path:symbol)",
		Flags: []registry.FlagDef{
			{Name: "pid", Short: "p", Description: "Filter by PID (comma-separated)", HasValue: true, Negatable: true},
			{Name: "uid", Short: "u", Description: "Filter by UID (comma-separated)", HasValue: true, Negatable: true},
			{Name: "name", Short: "n", Description: "Filter by process name (comm)", HasValue: true},
			{Name: "uprobe", Short: "", Description: "Attach target as path:symbol (required)", HasValue: true},
			{Name: "latency", Short: "", Description: "Also measure call latency via uretprobe", HasValue: false},
		},
		MapNames:        []string{"pid", "uid", "pid_deny", "uid_deny"},
		Formatter:       textFormat,
		DefaultCountKey: "comm",
		CountFields:     []string{"pid", "tid", "uid", "comm", "duration_ns"},
		Factory: func(flags map[string]string, sink output.EventSink) (runner.Module, error) {
			filter, err := ParseFilterConfig(flags)
			if err != nil {
				return nil, err
			}
			return New(filter, sink), nil
		},
	})
}

/*
	Target identifies the executable and symbol to probe.
*/
type Target struct {
	Path   string
	Symbol string
}

/*
	FilterConfig holds parsed filter values and the attach target.
	PID and UID filters operate in the kernel via BPF maps. CommName is a
	userspace substring match. Latency selects the uretprobe path.
*/
type FilterConfig struct {
	Target   Target
	Latency  bool
	PIDs     []uint32
	UIDs     []uint32
	CommName string
	DenyPIDs []uint32
	DenyUIDs []uint32
}

/*
	parseTarget splits a "path:symbol" value. Splitting on the last colon
	tolerates colons in the path; symbol names cannot contain one.
*/
func parseTarget(raw string) (Target, error) {
	i := strings.LastIndexByte(raw, ':')
	if i < 0 {
		return Target{}, fmt.Errorf("--uprobe wants path:symbol, got %q", raw)
	}
	path := strings.TrimSpace(raw[:i])
	sym := strings.TrimSpace(raw[i+1:])
	if path == "" || sym == "" {
		return Target{}, fmt.Errorf("--uprobe wants path:symbol, got %q", raw)
	}
	return Target{Path: path, Symbol: sym}, nil
}

/*
	ParseFilterConfig interprets the raw CLI flags map into a typed
	FilterConfig. Returns an error for invalid values or a missing target.
*/
func ParseFilterConfig(flags map[string]string) (FilterConfig, error) {
	var cfg FilterConfig

	raw, ok := flags["uprobe"]
	if !ok {
		return cfg, fmt.Errorf("uprobe module requires --uprobe path:symbol")
	}
	target, err := parseTarget(raw)
	if err != nil {
		return cfg, err
	}
	cfg.Target = target

	if flags["latency"] == "true" {
		cfg.Latency = true
	}

	if raw, ok := flags["pid"]; ok {
		for _, s := range strings.Split(raw, ",") {
			v, err := strconv.ParseUint(strings.TrimSpace(s), 10, 32)
			if err != nil {
				return cfg, fmt.Errorf("invalid PID %q: %w", s, err)
			}
			cfg.PIDs = append(cfg.PIDs, uint32(v))
		}
	}

	if raw, ok := flags["pid_deny"]; ok {
		for _, s := range strings.Split(raw, ",") {
			v, err := strconv.ParseUint(strings.TrimSpace(s), 10, 32)
			if err != nil {
				return cfg, fmt.Errorf("invalid deny PID %q: %w", s, err)
			}
			cfg.DenyPIDs = append(cfg.DenyPIDs, uint32(v))
		}
	}

	if raw, ok := flags["uid"]; ok {
		for _, s := range strings.Split(raw, ",") {
			v, err := strconv.ParseUint(strings.TrimSpace(s), 10, 32)
			if err != nil {
				return cfg, fmt.Errorf("invalid UID %q: %w", s, err)
			}
			cfg.UIDs = append(cfg.UIDs, uint32(v))
		}
	}

	if raw, ok := flags["uid_deny"]; ok {
		for _, s := range strings.Split(raw, ",") {
			v, err := strconv.ParseUint(strings.TrimSpace(s), 10, 32)
			if err != nil {
				return cfg, fmt.Errorf("invalid deny UID %q: %w", s, err)
			}
			cfg.DenyUIDs = append(cfg.DenyUIDs, uint32(v))
		}
	}

	if raw, ok := flags["name"]; ok {
		cfg.CommName = raw
	}

	return cfg, nil
}

type UprobeModule struct {
	*loader.BaseProgram
	objs    UprobeTracerObjects
	uEnter  link.Link
	uReturn link.Link
	reader  *ringbuf.Reader
	Events  chan events.UprobeEvent
	filter  FilterConfig
	sink    output.EventSink
	updater *bpfutil.MapUpdaterState
}

func New(filter FilterConfig, sink output.EventSink) *UprobeModule {
	return &UprobeModule{
		BaseProgram: loader.NewBaseProgram("uprobe_tracer"),
		Events:      make(chan events.UprobeEvent, 256),
		filter:      filter,
		sink:        sink,
	}
}

/*
	populateFilters writes filter values into BPF maps and sets the
	filter_cfg bitmask. Uprobe has no module-specific filter dimension, so
	only the pid and uid bits (allow and deny) are used.

	Bitmask convention:
		bit 0 = pid allow
		bit 1 = uid allow
		bit 3 = pid deny
		bit 4 = uid deny
*/
func (u *UprobeModule) populateFilters() error {
	return bpfutil.PopulateFilters(u.objs.FilterCfg, []bpfutil.FilterSpec{
		{Map: u.objs.PidFilter, Bit: bpfutil.BitPID, KeySize: 4, Values: bpfutil.WidenU32(u.filter.PIDs)},
		{Map: u.objs.UidFilter, Bit: bpfutil.BitUID, KeySize: 4, Values: bpfutil.WidenU32(u.filter.UIDs)},
		{Map: u.objs.PidDeny, Bit: bpfutil.BitPIDDeny, KeySize: 4, Values: bpfutil.WidenU32(u.filter.DenyPIDs)},
		{Map: u.objs.UidDeny, Bit: bpfutil.BitUIDDeny, KeySize: 4, Values: bpfutil.WidenU32(u.filter.DenyUIDs)},
	})
}

func (u *UprobeModule) Load() error {
	if err := LoadUprobeTracerObjects(&u.objs, nil); err != nil {
		return fmt.Errorf("uprobe: load objects: %w", err)
	}

	if err := u.populateFilters(); err != nil {
		return err
	}

	u.initMapUpdater()

	ex, err := link.OpenExecutable(u.filter.Target.Path)
	if err != nil {
		return fmt.Errorf("uprobe: open %s: %w", u.filter.Target.Path, err)
	}

	sym := u.filter.Target.Symbol

	/*
		Latency mode attaches the storing entry probe and the return probe;
		entry-only attaches the emitting entry probe. The entry probe filters
		in both modes, so the return probe only fires for admitted calls.
	*/
	if u.filter.Latency {
		u.uEnter, err = ex.Uprobe(sym, u.objs.UprobeStore, nil)
		if err != nil {
			return u.attachError(sym, err)
		}
		u.uReturn, err = ex.Uretprobe(sym, u.objs.UretprobeEmit, nil)
		if err != nil {
			return u.attachError(sym, err)
		}
	} else {
		u.uEnter, err = ex.Uprobe(sym, u.objs.UprobeEmit, nil)
		if err != nil {
			return u.attachError(sym, err)
		}
	}

	rd, err := ringbuf.NewReader(u.objs.UprobeEvents)
	if err != nil {
		return fmt.Errorf("uprobe: open ringbuf: %w", err)
	}
	u.reader = rd

	if err := u.MarkLoaded(); err != nil {
		return err
	}

	go u.poll()
	return nil
}

/*
	attachError turns a missing symbol into an actionable message; other
	attach failures pass through wrapped.
*/
func (u *UprobeModule) attachError(sym string, err error) error {
	if errors.Is(err, link.ErrNoSymbol) {
		return fmt.Errorf("uprobe: symbol %q not found in %s (stripped binary?)", sym, u.filter.Target.Path)
	}
	return fmt.Errorf("uprobe: attach %q: %w", sym, err)
}

func (u *UprobeModule) Close() error {
	var errs []error

	if u.reader != nil {
		errs = append(errs, u.reader.Close())
	}
	if u.uReturn != nil {
		errs = append(errs, u.uReturn.Close())
	}
	if u.uEnter != nil {
		errs = append(errs, u.uEnter.Close())
	}

	u.objs.Close()

	if err := u.MarkClosed(); err != nil {
		errs = append(errs, err)
	}

	return exterrs.Join(errs)
}

func (u *UprobeModule) Run(done <-chan struct{}) {
	for {
		select {
		case e, ok := <-u.Events:
			if !ok {
				return
			}
			u.sink.Emit("uprobe", u.toFields(e))
		case <-done:
			return
		}
	}
}

/*
	toFields converts a UprobeEvent into a generic field map. The probed
	symbol and path come from module state, not the record.
*/
func (u *UprobeModule) toFields(e events.UprobeEvent) map[string]interface{} {
	return map[string]interface{}{
		"kind":        e.Kind.String(),
		"pid":         e.PID,
		"tid":         e.TID,
		"uid":         e.UID,
		"timestamp":   e.Timestamp,
		"comm":        e.ProcessName(),
		"symbol":      u.filter.Target.Symbol,
		"path":        u.filter.Target.Path,
		"duration_ns": e.DurationNs,
	}
}

func (u *UprobeModule) poll() {
	defer close(u.Events)
	for {
		record, err := u.reader.Read()
		if err != nil {
			return
		}

		e, err := parseEvent(record.RawSample)
		if err != nil {
			continue
		}

		if !u.matchesFilter(e) {
			continue
		}

		u.Events <- e
	}
}

/*
	matchesFilter applies userspace-level filters. Currently only the comm
	name substring match.
*/
func (u *UprobeModule) matchesFilter(e events.UprobeEvent) bool {
	if u.filter.CommName != "" && !strings.Contains(e.ProcessName(), u.filter.CommName) {
		return false
	}
	return true
}
