package scheduler

/*
	MapUpdater implementation for the scheduler module.

	Supported map names: pid, uid, cpu, pid_deny, uid_deny, cpu_deny
	Key types: all uint32

	Bitmask layout:
		bit 0: pid allow
		bit 1: uid allow
		bit 2: cpu allow
		bit 3: pid deny
		bit 4: uid deny
		bit 5: cpu deny
*/

import (
	"fmt"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
)

type filterMeta struct {
	bpfMap  *ebpf.Map
	bit     uint32
	keySize int
}

type mapUpdaterState struct {
	mu      sync.Mutex
	filters map[string]filterMeta
	cfgMap  *ebpf.Map
}

func (t *SchedulerModule) initMapUpdater() {
	t.updater = &mapUpdaterState{
		filters: map[string]filterMeta{
			"pid": {
				bpfMap:  t.objs.PidFilter,
				bit:     1,
				keySize: 4,
			},
			"uid": {
				bpfMap:  t.objs.UidFilter,
				bit:     2,
				keySize: 4,
			},
			"cpu": {
				bpfMap:  t.objs.CpuFilter,
				bit:     4,
				keySize: 4,
			},
			"pid_deny": {
				bpfMap:  t.objs.PidDeny,
				bit:     8,
				keySize: 4,
			},
			"uid_deny": {
				bpfMap:  t.objs.UidDeny,
				bit:     16,
				keySize: 4,
			},
			"cpu_deny": {
				bpfMap:  t.objs.CpuDeny,
				bit:     32,
				keySize: 4,
			},
		},
		cfgMap: t.objs.FilterCfg,
	}
}

func (t *SchedulerModule) AddFilter(mapName string, key uint64) error {
	t.updater.mu.Lock()
	defer t.updater.mu.Unlock()

	meta, ok := t.updater.filters[mapName]
	if !ok {
		return fmt.Errorf("scheduler: unknown filter map %q", mapName)
	}

	enable := uint8(1)
	if err := updateMapKey(meta.bpfMap, key, enable, meta.keySize); err != nil {
		return fmt.Errorf("scheduler: add %s filter %d: %w", mapName, key, err)
	}

	return t.updater.setBit(meta.bit)
}

func (t *SchedulerModule) DelFilter(mapName string, key uint64) error {
	t.updater.mu.Lock()
	defer t.updater.mu.Unlock()

	meta, ok := t.updater.filters[mapName]
	if !ok {
		return fmt.Errorf("scheduler: unknown filter map %q", mapName)
	}

	if !lookupMapKey(meta.bpfMap, key, meta.keySize) {
		return fmt.Errorf("scheduler: key %d not found in %s filter", key, mapName)
	}

	if err := deleteMapKey(meta.bpfMap, key, meta.keySize); err != nil {
		return fmt.Errorf("scheduler: del %s filter %d: %w", mapName, key, err)
	}

	empty, err := isMapEmpty(meta.bpfMap, meta.keySize)
	if err != nil {
		return fmt.Errorf("scheduler: check %s empty: %w", mapName, err)
	}
	if empty {
		return t.updater.clearBit(meta.bit)
	}

	return nil
}

func (t *SchedulerModule) ListFilters(mapName string) ([]uint64, error) {
	t.updater.mu.Lock()
	defer t.updater.mu.Unlock()

	meta, ok := t.updater.filters[mapName]
	if !ok {
		return nil, fmt.Errorf("scheduler: unknown filter map %q", mapName)
	}

	return iterateMapKeys(meta.bpfMap, meta.keySize)
}

func (t *SchedulerModule) ClearFilters(mapName string) error {
	t.updater.mu.Lock()
	defer t.updater.mu.Unlock()

	meta, ok := t.updater.filters[mapName]
	if !ok {
		return fmt.Errorf("scheduler: unknown filter map %q", mapName)
	}

	if err := clearAllKeys(meta.bpfMap, meta.keySize); err != nil {
		return fmt.Errorf("scheduler: clear %s: %w", mapName, err)
	}

	return t.updater.clearBit(meta.bit)
}

func (t *SchedulerModule) Status() string {
	t.updater.mu.Lock()
	defer t.updater.mu.Unlock()

	pids, _ := iterateMapKeys(t.updater.filters["pid"].bpfMap, 4)
	uids, _ := iterateMapKeys(t.updater.filters["uid"].bpfMap, 4)
	cpus, _ := iterateMapKeys(t.updater.filters["cpu"].bpfMap, 4)
	pidDeny, _ := iterateMapKeys(t.updater.filters["pid_deny"].bpfMap, 4)
	uidDeny, _ := iterateMapKeys(t.updater.filters["uid_deny"].bpfMap, 4)
	cpuDeny, _ := iterateMapKeys(t.updater.filters["cpu_deny"].bpfMap, 4)

	return fmt.Sprintf("scheduler: loaded, filters: pid=%s, uid=%s, cpu=%s, pid_deny=%s, uid_deny=%s, cpu_deny=%s",
		fmtKeys(pids), fmtKeys(uids), fmtKeys(cpus), fmtKeys(pidDeny), fmtKeys(uidDeny), fmtKeys(cpuDeny))
}

// --------------------------------------------------------
// filter_cfg bitmask helpers (same pattern as other modules)
// --------------------------------------------------------

func (s *mapUpdaterState) setBit(bit uint32) error {
	mask, err := s.readCfg()
	if err != nil {
		return err
	}
	if mask&bit != 0 {
		return nil
	}
	mask |= bit
	return s.writeCfg(mask)
}

func (s *mapUpdaterState) clearBit(bit uint32) error {
	mask, err := s.readCfg()
	if err != nil {
		return err
	}
	if mask&bit == 0 {
		return nil
	}
	mask &^= bit
	return s.writeCfg(mask)
}

func (s *mapUpdaterState) readCfg() (uint32, error) {
	cfgKey := uint32(0)
	var mask uint32
	if err := s.cfgMap.Lookup(cfgKey, &mask); err != nil {
		return 0, nil
	}
	return mask, nil
}

func (s *mapUpdaterState) writeCfg(mask uint32) error {
	cfgKey := uint32(0)
	return s.cfgMap.Update(cfgKey, mask, ebpf.UpdateAny)
}

// --------------------------------------------------------
// BPF map operation helpers (same as other modules)
// --------------------------------------------------------

func updateMapKey(m *ebpf.Map, key uint64, value uint8, keySize int) error {
	switch keySize {
	case 4:
		k := uint32(key)
		return m.Update(k, value, ebpf.UpdateAny)
	case 8:
		return m.Update(key, value, ebpf.UpdateAny)
	default:
		return fmt.Errorf("unsupported key size: %d", keySize)
	}
}

func lookupMapKey(m *ebpf.Map, key uint64, keySize int) bool {
	var val uint8
	switch keySize {
	case 4:
		k := uint32(key)
		return m.Lookup(k, &val) == nil
	case 8:
		return m.Lookup(key, &val) == nil
	default:
		return false
	}
}

func deleteMapKey(m *ebpf.Map, key uint64, keySize int) error {
	switch keySize {
	case 4:
		k := uint32(key)
		return m.Delete(k)
	case 8:
		return m.Delete(key)
	default:
		return fmt.Errorf("unsupported key size: %d", keySize)
	}
}

func iterateMapKeys(m *ebpf.Map, keySize int) ([]uint64, error) {
	var keys []uint64
	switch keySize {
	case 4:
		var key uint32
		iter := m.Iterate()
		var val uint8
		for iter.Next(&key, &val) {
			keys = append(keys, uint64(key))
		}
		return keys, iter.Err()
	case 8:
		var key uint64
		iter := m.Iterate()
		var val uint8
		for iter.Next(&key, &val) {
			keys = append(keys, key)
		}
		return keys, iter.Err()
	default:
		return nil, fmt.Errorf("unsupported key size: %d", keySize)
	}
}

func isMapEmpty(m *ebpf.Map, keySize int) (bool, error) {
	keys, err := iterateMapKeys(m, keySize)
	if err != nil {
		return false, err
	}
	return len(keys) == 0, nil
}

func clearAllKeys(m *ebpf.Map, keySize int) error {
	keys, err := iterateMapKeys(m, keySize)
	if err != nil {
		return err
	}
	for _, k := range keys {
		if err := deleteMapKey(m, k, keySize); err != nil {
			return err
		}
	}
	return nil
}

func fmtKeys(keys []uint64) string {
	return strings.ReplaceAll(fmt.Sprintf("%v", keys), " ", ",")
}
