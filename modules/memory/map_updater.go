package memory

/*
	MapUpdater implementation for the memory module.

	Supported map names: pid, uid, fault, pid_deny, uid_deny, fault_deny
	Key types: all uint32

	Bitmask layout:
		bit 0: pid allow
		bit 1: uid allow
		bit 2: fault allow
		bit 3: pid deny
		bit 4: uid deny
		bit 5: fault deny
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

func (m *MemoryModule) initMapUpdater() {
	m.updater = &mapUpdaterState{
		filters: map[string]filterMeta{
			"pid": {
				bpfMap:  m.objs.PidFilter,
				bit:     1,
				keySize: 4,
			},
			"uid": {
				bpfMap:  m.objs.UidFilter,
				bit:     2,
				keySize: 4,
			},
			"fault": {
				bpfMap:  m.objs.FaultFilter,
				bit:     4,
				keySize: 4,
			},
			"pid_deny": {
				bpfMap:  m.objs.PidDeny,
				bit:     8,
				keySize: 4,
			},
			"uid_deny": {
				bpfMap:  m.objs.UidDeny,
				bit:     16,
				keySize: 4,
			},
			"fault_deny": {
				bpfMap:  m.objs.FaultDeny,
				bit:     32,
				keySize: 4,
			},
		},
		cfgMap: m.objs.FilterCfg,
	}
}

func (m *MemoryModule) AddFilter(mapName string, key uint64) error {
	m.updater.mu.Lock()
	defer m.updater.mu.Unlock()

	meta, ok := m.updater.filters[mapName]
	if !ok {
		return fmt.Errorf("memory: unknown filter map %q", mapName)
	}

	enable := uint8(1)
	if err := updateMapKey(meta.bpfMap, key, enable, meta.keySize); err != nil {
		return fmt.Errorf("memory: add %s filter %d: %w", mapName, key, err)
	}

	return m.updater.setBit(meta.bit)
}

func (m *MemoryModule) DelFilter(mapName string, key uint64) error {
	m.updater.mu.Lock()
	defer m.updater.mu.Unlock()

	meta, ok := m.updater.filters[mapName]
	if !ok {
		return fmt.Errorf("memory: unknown filter map %q", mapName)
	}

	if !lookupMapKey(meta.bpfMap, key, meta.keySize) {
		return fmt.Errorf("memory: key %d not found in %s filter", key, mapName)
	}

	if err := deleteMapKey(meta.bpfMap, key, meta.keySize); err != nil {
		return fmt.Errorf("memory: del %s filter %d: %w", mapName, key, err)
	}

	empty, err := isMapEmpty(meta.bpfMap, meta.keySize)
	if err != nil {
		return fmt.Errorf("memory: check %s empty: %w", mapName, err)
	}
	if empty {
		return m.updater.clearBit(meta.bit)
	}

	return nil
}

func (m *MemoryModule) ListFilters(mapName string) ([]uint64, error) {
	m.updater.mu.Lock()
	defer m.updater.mu.Unlock()

	meta, ok := m.updater.filters[mapName]
	if !ok {
		return nil, fmt.Errorf("memory: unknown filter map %q", mapName)
	}

	return iterateMapKeys(meta.bpfMap, meta.keySize)
}

func (m *MemoryModule) ClearFilters(mapName string) error {
	m.updater.mu.Lock()
	defer m.updater.mu.Unlock()

	meta, ok := m.updater.filters[mapName]
	if !ok {
		return fmt.Errorf("memory: unknown filter map %q", mapName)
	}

	if err := clearAllKeys(meta.bpfMap, meta.keySize); err != nil {
		return fmt.Errorf("memory: clear %s: %w", mapName, err)
	}

	return m.updater.clearBit(meta.bit)
}

func (m *MemoryModule) Status() string {
	m.updater.mu.Lock()
	defer m.updater.mu.Unlock()

	pids, _ := iterateMapKeys(m.updater.filters["pid"].bpfMap, 4)
	uids, _ := iterateMapKeys(m.updater.filters["uid"].bpfMap, 4)
	faults, _ := iterateMapKeys(m.updater.filters["fault"].bpfMap, 4)
	pidDeny, _ := iterateMapKeys(m.updater.filters["pid_deny"].bpfMap, 4)
	uidDeny, _ := iterateMapKeys(m.updater.filters["uid_deny"].bpfMap, 4)
	faultDeny, _ := iterateMapKeys(m.updater.filters["fault_deny"].bpfMap, 4)

	return fmt.Sprintf("memory: loaded, filters: pid=%s, uid=%s, fault=%s, pid_deny=%s, uid_deny=%s, fault_deny=%s",
		fmtKeys(pids), fmtKeys(uids), fmtKeys(faults), fmtKeys(pidDeny), fmtKeys(uidDeny), fmtKeys(faultDeny))
}

/*
	filter_cfg bitmask helpers (same pattern as other modules)
*/

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

/*
	BPF map operation helpers (same as other modules)
*/

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
