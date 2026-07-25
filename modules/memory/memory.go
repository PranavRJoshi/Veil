package memory

//go:generate bpf2go -cc clang -target amd64,arm64 -cflags "-O2 -g -Wall" MemoryTracer ../../bpf/memory_tracer.bpf.c

/*
	Memory module for Veil.

	Traces page faults via a kprobe/kretprobe pair on handle_mm_fault.
	The kprobe captures process context at entry; the kretprobe classifies
	the fault as major (disk I/O) or minor (in-memory resolution) from the
	return value, then emits to the ring buffer.

	Kernel-side filters: PID, UID, fault type (allow + deny)
	Userspace filters: process name (comm substring match)
*/

import (
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
		Name:        "memory",
		Description: "Page fault tracing (major/minor via handle_mm_fault)",
		Flags: []registry.FlagDef{
			{Name: "pid", Short: "p", Description: "Filter by PID (comma-separated)", HasValue: true, Negatable: true},
			{Name: "uid", Short: "u", Description: "Filter by UID (comma-separated)", HasValue: true, Negatable: true},
			{Name: "name", Short: "n", Description: "Filter by process name (comm)", HasValue: true},
			{Name: "fault", Short: "", Description: "Filter by fault type: major, minor (comma-separated)", HasValue: true, Negatable: true},
		},
		MapNames:        []string{"pid", "uid", "fault", "pid_deny", "uid_deny", "fault_deny"},
		Formatter:       textFormat,
		DefaultCountKey: "evt_type",
		CountFields:     []string{"evt_type", "address"},
		Factory: func(flags map[string]string, sink output.EventSink) (runner.Module, error) {
			filter, err := ParseFilterConfig(flags)
			if err != nil {
				return nil, err
			}
			return New(filter, sink), nil
		},
	})
}

// Filter Configuration

/*
	FilterConfig holds parsed filter values from CLI flags.
	PID, UID, and fault type filters operate in the kernel via BPF maps.
	CommName is a userspace substring match.
*/
type FilterConfig struct {
	PIDs       []uint32
	UIDs       []uint32
	CommName   string
	FaultTypes []uint32 // 0=major, 1=minor
	DenyPIDs   []uint32
	DenyUIDs   []uint32
	DenyFaults []uint32
}

/*
	faultTypeFromName converts a fault type name to its numeric code.
*/
func faultTypeFromName(name string) (uint32, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "major":
		return 0, nil
	case "minor":
		return 1, nil
	default:
		return 0, fmt.Errorf("unknown fault type %q (valid: major, minor)", name)
	}
}

/*
	ParseFilterConfig interprets the raw CLI flags map into a typed
	FilterConfig. Returns an error for invalid values.
*/
func ParseFilterConfig(flags map[string]string) (FilterConfig, error) {
	var cfg FilterConfig

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

	if raw, ok := flags["fault"]; ok {
		for _, s := range strings.Split(raw, ",") {
			ft, err := faultTypeFromName(s)
			if err != nil {
				return cfg, err
			}
			cfg.FaultTypes = append(cfg.FaultTypes, ft)
		}
	}

	if raw, ok := flags["fault_deny"]; ok {
		for _, s := range strings.Split(raw, ",") {
			ft, err := faultTypeFromName(s)
			if err != nil {
				return cfg, err
			}
			cfg.DenyFaults = append(cfg.DenyFaults, ft)
		}
	}

	if raw, ok := flags["name"]; ok {
		cfg.CommName = raw
	}

	return cfg, nil
}

// Module

type MemoryModule struct {
	*loader.BaseProgram
	objs        MemoryTracerObjects
	kprobeEntry link.Link
	kretReturn  link.Link
	reader      *ringbuf.Reader
	Events      chan events.MemoryEvent
	filter      FilterConfig
	sink        output.EventSink
	updater     *bpfutil.MapUpdaterState
}

func New(filter FilterConfig, sink output.EventSink) *MemoryModule {
	return &MemoryModule{
		BaseProgram: loader.NewBaseProgram("memory_tracer"),
		Events:      make(chan events.MemoryEvent, 256),
		filter:      filter,
		sink:        sink,
	}
}

/*
	populateFilters writes filter values into BPF maps and sets the
	filter_cfg bitmask.

	Bitmask convention:
		bit 0 = pid allow
		bit 1 = uid allow
		bit 2 = fault type allow
		bit 3 = pid deny
		bit 4 = uid deny
		bit 5 = fault type deny
*/
func (m *MemoryModule) populateFilters() error {
	return bpfutil.PopulateFilters(m.objs.FilterCfg, []bpfutil.FilterSpec{
		{Map: m.objs.PidFilter, Bit: bpfutil.BitPID, KeySize: 4, Values: bpfutil.WidenU32(m.filter.PIDs)},
		{Map: m.objs.UidFilter, Bit: bpfutil.BitUID, KeySize: 4, Values: bpfutil.WidenU32(m.filter.UIDs)},
		{Map: m.objs.FaultFilter, Bit: bpfutil.BitSpecific, KeySize: 4, Values: bpfutil.WidenU32(m.filter.FaultTypes)},
		{Map: m.objs.PidDeny, Bit: bpfutil.BitPIDDeny, KeySize: 4, Values: bpfutil.WidenU32(m.filter.DenyPIDs)},
		{Map: m.objs.UidDeny, Bit: bpfutil.BitUIDDeny, KeySize: 4, Values: bpfutil.WidenU32(m.filter.DenyUIDs)},
		{Map: m.objs.FaultDeny, Bit: bpfutil.BitSpecificDeny, KeySize: 4, Values: bpfutil.WidenU32(m.filter.DenyFaults)},
	})
}

func (m *MemoryModule) Load() error {
	if err := LoadMemoryTracerObjects(&m.objs, nil); err != nil {
		return fmt.Errorf("memory: load objects: %w", err)
	}

	if err := m.populateFilters(); err != nil {
		return err
	}

	m.initMapUpdater()

	var err error

	/*
		Attach kprobe on handle_mm_fault for stashing process context.
	*/
	m.kprobeEntry, err = link.Kprobe("handle_mm_fault", m.objs.KprobeHandleMmFault, nil)
	if err != nil {
		return fmt.Errorf("memory: attach kprobe: %w", err)
	}

	/*
		Attach kretprobe on handle_mm_fault for fault classification
		and event emission.
	*/
	m.kretReturn, err = link.Kretprobe("handle_mm_fault", m.objs.KretprobeHandleMmFault, nil)
	if err != nil {
		return fmt.Errorf("memory: attach kretprobe: %w", err)
	}

	rd, err := ringbuf.NewReader(m.objs.MemEvents)
	if err != nil {
		return fmt.Errorf("memory: open ringbuf: %w", err)
	}
	m.reader = rd

	if err := m.MarkLoaded(); err != nil {
		return err
	}

	go m.poll()
	return nil
}

func (m *MemoryModule) Close() error {
	var errs []error

	if m.reader != nil {
		errs = append(errs, m.reader.Close())
	}
	if m.kprobeEntry != nil {
		errs = append(errs, m.kprobeEntry.Close())
	}
	if m.kretReturn != nil {
		errs = append(errs, m.kretReturn.Close())
	}

	m.objs.Close()

	if err := m.MarkClosed(); err != nil {
		errs = append(errs, err)
	}

	return exterrs.Join(errs)
}

func (m *MemoryModule) Run(done <-chan struct{}) {
	for {
		select {
		case e, ok := <-m.Events:
			if !ok {
				return
			}
			m.sink.Emit("memory", memoryToFields(e))
		case <-done:
			return
		}
	}
}

/*
	memoryToFields converts a MemoryEvent into a generic field map.
*/
func memoryToFields(e events.MemoryEvent) map[string]interface{} {
	return map[string]interface{}{
		"kind":      e.Kind.String(),
		"pid":       e.PID,
		"tid":       e.TID,
		"uid":       e.UID,
		"timestamp": e.Timestamp,
		"comm":      e.ProcessName(),
		"evt_type":  faultTypeName(e.EvtType),
		"address":   fmt.Sprintf("0x%x", e.Address),
	}
}

func (m *MemoryModule) poll() {
	defer close(m.Events)
	for {
		record, err := m.reader.Read()
		if err != nil {
			return
		}

		e, err := parseEvent(record.RawSample)
		if err != nil {
			continue
		}

		if !m.matchesFilter(e) {
			continue
		}

		m.Events <- e
	}
}

/*
	matchesFilter applies userspace-level filters. Currently only
	comm name substring match.
*/
func (m *MemoryModule) matchesFilter(e events.MemoryEvent) bool {
	if m.filter.CommName != "" && !strings.Contains(e.ProcessName(), m.filter.CommName) {
		return false
	}
	return true
}
