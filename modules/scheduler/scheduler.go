package scheduler

//go:generate bpf2go -cc clang -cflags "-O2 -g -Wall -target bpf" SchedulerTracer ../../bpf/sched_tracer.bpf.c

/*
	Scheduler module for Veil.

	Traces context switches via the sched/sched_switch tracepoint. Each event
	captures the task being switched out (prev) and the task being switched in
	(next), along with the CPU core, priority, and the reason for the switch.

	Kernel-side filters: PID (matches either prev or next), UID, CPU
	Userspace filters: process name (comm substring match)
*/

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/PranavRJoshi/Veil/internal/events"
	"github.com/PranavRJoshi/Veil/internal/exterrs"
	"github.com/PranavRJoshi/Veil/internal/loader"
	"github.com/PranavRJoshi/Veil/internal/output"
	"github.com/PranavRJoshi/Veil/internal/registry"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

func init() {
	registry.Register(registry.ModuleInfo{
		Name:        "scheduler",
		Description: "Trace context switches (sched:sched_switch)",
		Flags: []registry.FlagDef{
			{Name: "pid", Short: "p", Description: "Filter by PID (comma-separated)", HasValue: true},
			{Name: "uid", Short: "u", Description: "Filter by UID (comma-separated)", HasValue: true},
			{Name: "name", Short: "n", Description: "Filter by process name (comm)", HasValue: true},
			{Name: "cpu", Short: "", Description: "Filter by CPU core (comma-separated)", HasValue: true},
		},
		Factory: func(flags map[string]string, sinkIface interface{}) (interface{}, error) {
			sink, ok := sinkIface.(output.EventSink)
			if !ok {
				return nil, fmt.Errorf("scheduler: expected output.EventSink, got %T", sinkIface)
			}
			filter, err := ParseFilterConfig(flags)
			if err != nil {
				return nil, err
			}
			return New(filter, sink), nil
		},
	})
}

/*
	FilterConfig holds parsed filter values from CLI flags.
	PID, UID, and CPU filters operate in the kernel via BPF maps.
	CommName is a userspace substring match.
*/
type FilterConfig struct {
	PIDs     []uint32
	UIDs     []uint32
	CPUs     []uint32
	CommName string
	DenyPIDs []uint32
	DenyUIDs []uint32
	DenyCPUs []uint32
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

	if raw, ok := flags["cpu"]; ok {
		for _, s := range strings.Split(raw, ",") {
			v, err := strconv.ParseUint(strings.TrimSpace(s), 10, 32)
			if err != nil {
				return cfg, fmt.Errorf("invalid CPU %q: %w", s, err)
			}
			cfg.CPUs = append(cfg.CPUs, uint32(v))
		}
	}

	if raw, ok := flags["cpu_deny"]; ok {
		for _, s := range strings.Split(raw, ",") {
			v, err := strconv.ParseUint(strings.TrimSpace(s), 10, 32)
			if err != nil {
				return cfg, fmt.Errorf("invalid deny CPU %q: %w", s, err)
			}
			cfg.DenyCPUs = append(cfg.DenyCPUs, uint32(v))
		}
	}

	if raw, ok := flags["name"]; ok {
		cfg.CommName = raw
	}

	return cfg, nil
}

type SchedulerModule struct {
	*loader.BaseProgram
	objs    SchedulerTracerObjects
	link    link.Link
	reader  *ringbuf.Reader
	Events  chan events.SchedulerEvent
	filter  FilterConfig
	sink    output.EventSink
	updater *mapUpdaterState
}

func New(filter FilterConfig, sink output.EventSink) *SchedulerModule {
	return &SchedulerModule{
		BaseProgram: loader.NewBaseProgram("sched_tracer"),
		Events:      make(chan events.SchedulerEvent, 256),
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
		bit 2 = cpu allow
		bit 3 = pid deny
		bit 4 = uid deny
		bit 5 = cpu deny
*/
func (t *SchedulerModule) populateFilters() error {
	var mask uint32
	enable := uint8(1)

	/* PID allow filter */
	if len(t.filter.PIDs) > 0 {
		mask |= 1
		for _, pid := range t.filter.PIDs {
			if err := t.objs.PidFilter.Update(pid, enable, ebpf.UpdateAny); err != nil {
				return fmt.Errorf("scheduler: update pid_filter: %w", err)
			}
		}
	}

	/* PID deny filter */
	if len(t.filter.DenyPIDs) > 0 {
		mask |= 8
		for _, pid := range t.filter.DenyPIDs {
			if err := t.objs.PidDeny.Update(pid, enable, ebpf.UpdateAny); err != nil {
				return fmt.Errorf("scheduler: update pid_deny: %w", err)
			}
		}
	}

	/* UID allow filter */
	if len(t.filter.UIDs) > 0 {
		mask |= 2
		for _, uid := range t.filter.UIDs {
			if err := t.objs.UidFilter.Update(uid, enable, ebpf.UpdateAny); err != nil {
				return fmt.Errorf("scheduler: update uid_filter: %w", err)
			}
		}
	}

	/* UID deny filter */
	if len(t.filter.DenyUIDs) > 0 {
		mask |= 16
		for _, uid := range t.filter.DenyUIDs {
			if err := t.objs.UidDeny.Update(uid, enable, ebpf.UpdateAny); err != nil {
				return fmt.Errorf("scheduler: update uid_deny: %w", err)
			}
		}
	}

	/* CPU allow filter */
	if len(t.filter.CPUs) > 0 {
		mask |= 4
		for _, cpu := range t.filter.CPUs {
			if err := t.objs.CpuFilter.Update(cpu, enable, ebpf.UpdateAny); err != nil {
				return fmt.Errorf("scheduler: update cpu_filter: %w", err)
			}
		}
	}

	/* CPU deny filter */
	if len(t.filter.DenyCPUs) > 0 {
		mask |= 32
		for _, cpu := range t.filter.DenyCPUs {
			if err := t.objs.CpuDeny.Update(cpu, enable, ebpf.UpdateAny); err != nil {
				return fmt.Errorf("scheduler: update cpu_deny: %w", err)
			}
		}
	}

	/* Write the bitmask */
	if mask != 0 {
		cfgKey := uint32(0)
		if err := t.objs.FilterCfg.Update(cfgKey, mask, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("scheduler: update filter_cfg: %w", err)
		}
	}

	return nil
}

func (t *SchedulerModule) Load() error {
	if err := LoadSchedulerTracerObjects(&t.objs, nil); err != nil {
		return fmt.Errorf("scheduler: load objects: %w", err)
	}

	if err := t.populateFilters(); err != nil {
		return err
	}

	t.initMapUpdater()

	lnk, err := link.Tracepoint("sched", "sched_switch", t.objs.TraceSchedSwitch, nil)
	if err != nil {
		return fmt.Errorf("scheduler: attach tracepoint: %w", err)
	}
	t.link = lnk

	rd, err := ringbuf.NewReader(t.objs.SchedEvents)
	if err != nil {
		return fmt.Errorf("scheduler: open ringbuf: %w", err)
	}
	t.reader = rd

	if err := t.MarkLoaded(); err != nil {
		return err
	}

	go t.poll()
	return nil
}

func (t *SchedulerModule) Close() error {
	var errs []error

	if t.reader != nil {
		errs = append(errs, t.reader.Close())
	}
	if t.link != nil {
		errs = append(errs, t.link.Close())
	}

	t.objs.Close()

	if err := t.MarkClosed(); err != nil {
		errs = append(errs, err)
	}

	return exterrs.Join(errs)
}

func (t *SchedulerModule) Run(done <-chan struct{}) {
	for {
		select {
		case e, ok := <-t.Events:
			if !ok {
				return
			}
			t.sink.Emit("scheduler", schedulerToFields(e))
		case <-done:
			return
		}
	}
}

/*
	schedulerToFields converts a SchedulerEvent into a generic field map.
*/
func schedulerToFields(e events.SchedulerEvent) map[string]interface{} {
	return map[string]interface{}{
		"kind":       e.Kind.String(),
		"prev_pid":   e.PrevPID,
		"next_pid":   e.NextPID,
		"prev_tid":   e.PrevTID,
		"next_tid":   e.NextTID,
		"uid":        e.UID,
		"cpu":        e.CPU,
		"prev_state": prevStateName(e.PrevState),
		"timestamp":  e.Timestamp,
		"prev_prio":  e.PrevPrio,
		"next_prio":  e.NextPrio,
		"prev_comm":  commString(e.PrevComm),
		"next_comm":  commString(e.NextComm),
		/* "comm" for compatibility with enrichment and count defaults */
		"comm": commString(e.PrevComm),
		"pid":  e.PrevPID,
	}
}

func (t *SchedulerModule) poll() {
	defer close(t.Events)
	for {
		record, err := t.reader.Read()
		if err != nil {
			return
		}

		e, err := parseEvent(record.RawSample)
		if err != nil {
			continue
		}

		if !t.matchesFilter(e) {
			continue
		}

		t.Events <- e
	}
}

/*
	matchesFilter applies userspace-level filters. Checks both prev_comm
	and next_comm for the name substring match.
*/
func (t *SchedulerModule) matchesFilter(e events.SchedulerEvent) bool {
	if t.filter.CommName != "" {
		prev := commString(e.PrevComm)
		next := commString(e.NextComm)
		if !strings.Contains(prev, t.filter.CommName) &&
			!strings.Contains(next, t.filter.CommName) {
			return false
		}
	}
	return true
}
