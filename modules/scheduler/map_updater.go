package scheduler

/*
	MapUpdater implementation for the scheduler module.

	Wraps PidFilter, UidFilter, CpuFilter, and their deny variants with
	live update, delete, list, and clear operations via bpfutil.

	Supported map names: pid, uid, cpu, pid_deny, uid_deny, cpu_deny
	Key types: all uint32

	Bitmask convention:
		bit 0 = pid_filter active
		bit 1 = uid_filter active
		bit 2 = cpu_filter active
		bit 3 = pid_deny filter active
		bit 4 = uid_deny filter active
		bit 5 = cpu_deny filter active
*/

import (
	"fmt"

	"github.com/PranavRJoshi/Veil/internal/bpfutil"
)

func (t *SchedulerModule) initMapUpdater() {
	t.updater = &bpfutil.MapUpdaterState{
		Filters: map[string]bpfutil.FilterMeta{
			"pid": {
				BpfMap:  t.objs.PidFilter,
				Bit:     1,
				KeySize: 4,
			},
			"uid": {
				BpfMap:  t.objs.UidFilter,
				Bit:     2,
				KeySize: 4,
			},
			"cpu": {
				BpfMap:  t.objs.CpuFilter,
				Bit:     4,
				KeySize: 4,
			},
			"pid_deny": {
				BpfMap:  t.objs.PidDeny,
				Bit:     8,
				KeySize: 4,
			},
			"uid_deny": {
				BpfMap:  t.objs.UidDeny,
				Bit:     16,
				KeySize: 4,
			},
			"cpu_deny": {
				BpfMap:  t.objs.CpuDeny,
				Bit:     32,
				KeySize: 4,
			},
		},
		CfgMap: t.objs.FilterCfg,
	}
}

func (t *SchedulerModule) AddFilter(mapName string, key uint64) error {
	t.updater.Mu.Lock()
	defer t.updater.Mu.Unlock()

	meta, ok := t.updater.Filters[mapName]
	if !ok {
		return fmt.Errorf("scheduler: unknown filter map %q", mapName)
	}

	if err := bpfutil.UpdateMapKey(meta.BpfMap, key, 1, meta.KeySize); err != nil {
		return fmt.Errorf("scheduler: add %s filter %d: %w", mapName, key, err)
	}

	return t.updater.SetBit(meta.Bit)
}

func (t *SchedulerModule) DelFilter(mapName string, key uint64) error {
	t.updater.Mu.Lock()
	defer t.updater.Mu.Unlock()

	meta, ok := t.updater.Filters[mapName]
	if !ok {
		return fmt.Errorf("scheduler: unknown filter map %q", mapName)
	}

	if !bpfutil.LookupMapKey(meta.BpfMap, key, meta.KeySize) {
		return fmt.Errorf("scheduler: key %d not found in %s filter", key, mapName)
	}

	if err := bpfutil.DeleteMapKey(meta.BpfMap, key, meta.KeySize); err != nil {
		return fmt.Errorf("scheduler: del %s filter %d: %w", mapName, key, err)
	}

	empty, err := bpfutil.IsMapEmpty(meta.BpfMap, meta.KeySize)
	if err != nil {
		return fmt.Errorf("scheduler: check %s empty: %w", mapName, err)
	}
	if empty {
		return t.updater.ClearBit(meta.Bit)
	}

	return nil
}

func (t *SchedulerModule) ListFilters(mapName string) ([]uint64, error) {
	t.updater.Mu.Lock()
	defer t.updater.Mu.Unlock()

	meta, ok := t.updater.Filters[mapName]
	if !ok {
		return nil, fmt.Errorf("scheduler: unknown filter map %q", mapName)
	}

	return bpfutil.IterateMapKeys(meta.BpfMap, meta.KeySize)
}

func (t *SchedulerModule) ClearFilters(mapName string) error {
	t.updater.Mu.Lock()
	defer t.updater.Mu.Unlock()

	meta, ok := t.updater.Filters[mapName]
	if !ok {
		return fmt.Errorf("scheduler: unknown filter map %q", mapName)
	}

	if err := bpfutil.ClearAllKeys(meta.BpfMap, meta.KeySize); err != nil {
		return fmt.Errorf("scheduler: clear %s: %w", mapName, err)
	}

	return t.updater.ClearBit(meta.Bit)
}

func (t *SchedulerModule) Status() string {
	t.updater.Mu.Lock()
	defer t.updater.Mu.Unlock()

	pids, _ := bpfutil.IterateMapKeys(t.updater.Filters["pid"].BpfMap, 4)
	uids, _ := bpfutil.IterateMapKeys(t.updater.Filters["uid"].BpfMap, 4)
	cpus, _ := bpfutil.IterateMapKeys(t.updater.Filters["cpu"].BpfMap, 4)
	pidDeny, _ := bpfutil.IterateMapKeys(t.updater.Filters["pid_deny"].BpfMap, 4)
	uidDeny, _ := bpfutil.IterateMapKeys(t.updater.Filters["uid_deny"].BpfMap, 4)
	cpuDeny, _ := bpfutil.IterateMapKeys(t.updater.Filters["cpu_deny"].BpfMap, 4)

	return fmt.Sprintf("scheduler: loaded, filters: pid=%s, uid=%s, cpu=%s, pid_deny=%s, uid_deny=%s, cpu_deny=%s",
		bpfutil.FmtKeys(pids), bpfutil.FmtKeys(uids), bpfutil.FmtKeys(cpus),
		bpfutil.FmtKeys(pidDeny), bpfutil.FmtKeys(uidDeny), bpfutil.FmtKeys(cpuDeny))
}
