package memory

/*
	MapUpdater implementation for the memory module.

	Wraps PidFilter, UidFilter, FaultFilter, and their deny variants with
	live update, delete, list, and clear operations via bpfutil.

	Supported map names: pid, uid, fault, pid_deny, uid_deny, fault_deny
	Key types: all uint32

	Bitmask convention:
		bit 0 = pid_filter active
		bit 1 = uid_filter active
		bit 2 = fault_filter active
		bit 3 = pid_deny filter active
		bit 4 = uid_deny filter active
		bit 5 = fault_deny filter active
*/

import (
	"fmt"

	"github.com/PranavRJoshi/Veil/internal/bpfutil"
)

func (m *MemoryModule) initMapUpdater() {
	m.updater = &bpfutil.MapUpdaterState{
		Filters: map[string]bpfutil.FilterMeta{
			"pid": {
				BpfMap:  m.objs.PidFilter,
				Bit:     bpfutil.BitPID,
				KeySize: 4,
			},
			"uid": {
				BpfMap:  m.objs.UidFilter,
				Bit:     bpfutil.BitUID,
				KeySize: 4,
			},
			"fault": {
				BpfMap:  m.objs.FaultFilter,
				Bit:     bpfutil.BitSpecific,
				KeySize: 4,
			},
			"pid_deny": {
				BpfMap:  m.objs.PidDeny,
				Bit:     bpfutil.BitPIDDeny,
				KeySize: 4,
			},
			"uid_deny": {
				BpfMap:  m.objs.UidDeny,
				Bit:     bpfutil.BitUIDDeny,
				KeySize: 4,
			},
			"fault_deny": {
				BpfMap:  m.objs.FaultDeny,
				Bit:     bpfutil.BitSpecificDeny,
				KeySize: 4,
			},
		},
		CfgMap: m.objs.FilterCfg,
	}
}

func (m *MemoryModule) AddFilter(mapName string, key uint64) error {
	m.updater.Mu.Lock()
	defer m.updater.Mu.Unlock()

	meta, ok := m.updater.Filters[mapName]
	if !ok {
		return fmt.Errorf("memory: unknown filter map %q", mapName)
	}

	if err := bpfutil.UpdateMapKey(meta.BpfMap, key, 1, meta.KeySize); err != nil {
		return fmt.Errorf("memory: add %s filter %d: %w", mapName, key, err)
	}

	return m.updater.SetBit(meta.Bit)
}

func (m *MemoryModule) DelFilter(mapName string, key uint64) error {
	m.updater.Mu.Lock()
	defer m.updater.Mu.Unlock()

	meta, ok := m.updater.Filters[mapName]
	if !ok {
		return fmt.Errorf("memory: unknown filter map %q", mapName)
	}

	if !bpfutil.LookupMapKey(meta.BpfMap, key, meta.KeySize) {
		return fmt.Errorf("memory: key %d not found in %s filter", key, mapName)
	}

	if err := bpfutil.DeleteMapKey(meta.BpfMap, key, meta.KeySize); err != nil {
		return fmt.Errorf("memory: del %s filter %d: %w", mapName, key, err)
	}

	empty, err := bpfutil.IsMapEmpty(meta.BpfMap, meta.KeySize)
	if err != nil {
		return fmt.Errorf("memory: check %s empty: %w", mapName, err)
	}
	if empty {
		return m.updater.ClearBit(meta.Bit)
	}

	return nil
}

func (m *MemoryModule) ListFilters(mapName string) ([]uint64, error) {
	m.updater.Mu.Lock()
	defer m.updater.Mu.Unlock()

	meta, ok := m.updater.Filters[mapName]
	if !ok {
		return nil, fmt.Errorf("memory: unknown filter map %q", mapName)
	}

	return bpfutil.IterateMapKeys(meta.BpfMap, meta.KeySize)
}

func (m *MemoryModule) ClearFilters(mapName string) error {
	m.updater.Mu.Lock()
	defer m.updater.Mu.Unlock()

	meta, ok := m.updater.Filters[mapName]
	if !ok {
		return fmt.Errorf("memory: unknown filter map %q", mapName)
	}

	if err := bpfutil.ClearAllKeys(meta.BpfMap, meta.KeySize); err != nil {
		return fmt.Errorf("memory: clear %s: %w", mapName, err)
	}

	return m.updater.ClearBit(meta.Bit)
}

func (m *MemoryModule) Status() string {
	m.updater.Mu.Lock()
	defer m.updater.Mu.Unlock()

	pids, _ := bpfutil.IterateMapKeys(m.updater.Filters["pid"].BpfMap, 4)
	uids, _ := bpfutil.IterateMapKeys(m.updater.Filters["uid"].BpfMap, 4)
	faults, _ := bpfutil.IterateMapKeys(m.updater.Filters["fault"].BpfMap, 4)
	pidDeny, _ := bpfutil.IterateMapKeys(m.updater.Filters["pid_deny"].BpfMap, 4)
	uidDeny, _ := bpfutil.IterateMapKeys(m.updater.Filters["uid_deny"].BpfMap, 4)
	faultDeny, _ := bpfutil.IterateMapKeys(m.updater.Filters["fault_deny"].BpfMap, 4)

	return fmt.Sprintf("memory: loaded, filters: pid=%s, uid=%s, fault=%s, pid_deny=%s, uid_deny=%s, fault_deny=%s",
		bpfutil.FmtKeys(pids), bpfutil.FmtKeys(uids), bpfutil.FmtKeys(faults),
		bpfutil.FmtKeys(pidDeny), bpfutil.FmtKeys(uidDeny), bpfutil.FmtKeys(faultDeny))
}
