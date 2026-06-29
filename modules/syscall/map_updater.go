package syscall

/*
	MapUpdater implementation for the syscall module.

	Wraps PidFilter, UidFilter, SyscallFilter, and their deny variants
	with live update, delete, list, and clear operations via bpfutil.

	Supported map names: pid, uid, syscall, pid_deny, uid_deny, syscall_deny
	Key types: pid=uint32, uid=uint32, syscall=uint64

	Bitmask convention:
		bit 0 - pid_filter active
		bit 1 - uid_filter active
		bit 2 - syscall_filter active
		bit 3 - pid_deny filter active
		bit 4 - uid_deny filter active
		bit 5 - syscall_deny filter active
*/

import (
	"fmt"

	"github.com/PranavRJoshi/Veil/internal/bpfutil"
)

func (t *TracerModule) initMapUpdater() {
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
			"syscall": {
				BpfMap:  t.objs.SyscallFilter,
				Bit:     4,
				KeySize: 8,
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
			"syscall_deny": {
				BpfMap:  t.objs.SyscallDeny,
				Bit:     32,
				KeySize: 8,
			},
		},
		CfgMap: t.objs.FilterCfg,
	}
}

func (t *TracerModule) AddFilter(mapName string, key uint64) error {
	t.updater.Mu.Lock()
	defer t.updater.Mu.Unlock()

	meta, ok := t.updater.Filters[mapName]
	if !ok {
		return fmt.Errorf("syscall: unknown filter map %q (valid: pid, uid, syscall)", mapName)
	}

	if err := bpfutil.UpdateMapKey(meta.BpfMap, key, 1, meta.KeySize); err != nil {
		return fmt.Errorf("syscall: add %s filter %d: %w", mapName, key, err)
	}

	return t.updater.SetBit(meta.Bit)
}

func (t *TracerModule) DelFilter(mapName string, key uint64) error {
	t.updater.Mu.Lock()
	defer t.updater.Mu.Unlock()

	meta, ok := t.updater.Filters[mapName]
	if !ok {
		return fmt.Errorf("syscall: unknown filter map %q (valid: pid, uid, syscall)", mapName)
	}

	if !bpfutil.LookupMapKey(meta.BpfMap, key, meta.KeySize) {
		return fmt.Errorf("syscall: key %d not found in %s filter", key, mapName)
	}

	if err := bpfutil.DeleteMapKey(meta.BpfMap, key, meta.KeySize); err != nil {
		return fmt.Errorf("syscall: del %s filter %d: %w", mapName, key, err)
	}

	empty, err := bpfutil.IsMapEmpty(meta.BpfMap, meta.KeySize)
	if err != nil {
		return fmt.Errorf("syscall: check %s empty: %w", mapName, err)
	}
	if empty {
		return t.updater.ClearBit(meta.Bit)
	}

	return nil
}

func (t *TracerModule) ListFilters(mapName string) ([]uint64, error) {
	t.updater.Mu.Lock()
	defer t.updater.Mu.Unlock()

	meta, ok := t.updater.Filters[mapName]
	if !ok {
		return nil, fmt.Errorf("syscall: unknown filter map %q (valid: pid, uid, syscall)", mapName)
	}

	return bpfutil.IterateMapKeys(meta.BpfMap, meta.KeySize)
}

func (t *TracerModule) ClearFilters(mapName string) error {
	t.updater.Mu.Lock()
	defer t.updater.Mu.Unlock()

	meta, ok := t.updater.Filters[mapName]
	if !ok {
		return fmt.Errorf("syscall: unknown filter map %q (valid: pid, uid, syscall)", mapName)
	}

	if err := bpfutil.ClearAllKeys(meta.BpfMap, meta.KeySize); err != nil {
		return fmt.Errorf("syscall: clear %s: %w", mapName, err)
	}

	return t.updater.ClearBit(meta.Bit)
}

func (t *TracerModule) Status() string {
	t.updater.Mu.Lock()
	defer t.updater.Mu.Unlock()

	pids, _ := bpfutil.IterateMapKeys(t.updater.Filters["pid"].BpfMap, 4)
	uids, _ := bpfutil.IterateMapKeys(t.updater.Filters["uid"].BpfMap, 4)
	syscalls, _ := bpfutil.IterateMapKeys(t.updater.Filters["syscall"].BpfMap, 8)
	pidDeny, _ := bpfutil.IterateMapKeys(t.updater.Filters["pid_deny"].BpfMap, 4)
	uidDeny, _ := bpfutil.IterateMapKeys(t.updater.Filters["uid_deny"].BpfMap, 4)
	syscallDeny, _ := bpfutil.IterateMapKeys(t.updater.Filters["syscall_deny"].BpfMap, 8)

	return fmt.Sprintf("syscall: loaded, filters: pid=%s, uid=%s, syscall=%s, pid_deny=%s, uid_deny=%s, syscall_deny=%s",
		bpfutil.FmtKeys(pids), bpfutil.FmtKeys(uids), bpfutil.FmtKeys(syscalls),
		bpfutil.FmtKeys(pidDeny), bpfutil.FmtKeys(uidDeny), bpfutil.FmtKeys(syscallDeny))
}
