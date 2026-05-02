package network

/*
	MapUpdater implementation for the network module.
	NOTE: Refer to modules/syscall/map_updater.go for additional
	information since the implementations are mostly identical.

	Wraps PidFilter, UidFilter, and PortFilter BPF maps with live
	update, delete, list, and clear operations. Manages the filter_cfg
	bitmask to ensure consistency.

	Supported map names: "pid", "uid", "port"
	Key types: pid=uint32, uid=uint32, port=uint16

	Bitmask convention:
	  bit 0 = pid_filter active
	  bit 1 = uid_filter active
	  bit 2 = port_filter active
*/

import (
	"fmt"
	"sync"

	"github.com/cilium/ebpf"
)

type filterMeta struct {
	bpfMap  *ebpf.Map
	bit     uint32
	keySize int /* 2 for uint16 (port), 4 for uint32 (pid/uid) */
}

type mapUpdaterState struct {
	mu      sync.Mutex
	filters map[string]filterMeta
	cfgMap  *ebpf.Map
}

func (n *NetworkModule) initMapUpdater() {
	n.updater = &mapUpdaterState{
		filters: map[string]filterMeta{
			"pid": {
				bpfMap:  n.objs.PidFilter,
				bit:     1,
				keySize: 4,
			},
			"uid": {
				bpfMap:  n.objs.UidFilter,
				bit:     2,
				keySize: 4,
			},
			"port": {
				bpfMap:  n.objs.PortFilter,
				bit:     4,
				keySize: 2,
			},
		},
		cfgMap: n.objs.FilterCfg,
	}
}

func (n *NetworkModule) AddFilter(mapName string, key uint64) error {
	n.updater.mu.Lock()
	defer n.updater.mu.Unlock()

	meta, ok := n.updater.filters[mapName]
	if !ok {
		return fmt.Errorf("network: unknown filter map %q (valid: pid, uid, port)", mapName)
	}

	enable := uint8(1)
	if err := updateKey(meta.bpfMap, key, enable, meta.keySize); err != nil {
		return fmt.Errorf("network: add %s filter %d: %w", mapName, key, err)
	}

	return n.updater.setBit(meta.bit)
}

func (n *NetworkModule) DelFilter(mapName string, key uint64) error {
	n.updater.mu.Lock()
	defer n.updater.mu.Unlock()

	meta, ok := n.updater.filters[mapName]
	if !ok {
		return fmt.Errorf("network: unknown filter map %q (valid: pid, uid, port)", mapName)
	}

	if err := deleteKey(meta.bpfMap, key, meta.keySize); err != nil {
		return fmt.Errorf("network: del %s filter %d: %w", mapName, key, err)
	}

	empty, err := isMapEmpty(meta.bpfMap, meta.keySize)
	if err != nil {
		return fmt.Errorf("network: check %s empty: %w", mapName, err)
	}
	if empty {
		return n.updater.clearBit(meta.bit)
	}
	return nil
}

func (n *NetworkModule) ListFilters(mapName string) ([]uint64, error) {
	n.updater.mu.Lock()
	defer n.updater.mu.Unlock()

	meta, ok := n.updater.filters[mapName]
	if !ok {
		return nil, fmt.Errorf("network: unknown filter map %q (valid: pid, uid, port)", mapName)
	}

	return iterateKeys(meta.bpfMap, meta.keySize)
}

func (n *NetworkModule) ClearFilters(mapName string) error {
	n.updater.mu.Lock()
	defer n.updater.mu.Unlock()

	meta, ok := n.updater.filters[mapName]
	if !ok {
		return fmt.Errorf("network: unknown filter map %q (valid: pid, uid, port)", mapName)
	}

	if err := clearAll(meta.bpfMap, meta.keySize); err != nil {
		return fmt.Errorf("network: clear %s: %w", mapName, err)
	}

	return n.updater.clearBit(meta.bit)
}

func (n *NetworkModule) Status() string {
	n.updater.mu.Lock()
	defer n.updater.mu.Unlock()

	pids, _ := iterateKeys(n.updater.filters["pid"].bpfMap, 4)
	uids, _ := iterateKeys(n.updater.filters["uid"].bpfMap, 4)
	ports, _ := iterateKeys(n.updater.filters["port"].bpfMap, 2)

	return fmt.Sprintf("network: loaded, filters: pid=%v, uid=%v, port=%v",
		pids, uids, ports)
}

// ---------------------------------------------------------------------------
// filter_cfg bitmask helpers
// ---------------------------------------------------------------------------

func (s *mapUpdaterState) setBit(bit uint32) error {
	mask, _ := s.readCfg()
	if mask&bit != 0 {
		return nil
	}
	mask |= bit
	return s.writeCfg(mask)
}

func (s *mapUpdaterState) clearBit(bit uint32) error {
	mask, _ := s.readCfg()
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

// ---------------------------------------------------------------------------
// BPF map helpers
//
// The network module has three key sizes: uint16 (port), uint32 (pid/uid).
// ---------------------------------------------------------------------------

func updateKey(m *ebpf.Map, key uint64, value uint8, keySize int) error {
	switch keySize {
	case 2:
		k := uint16(key)
		return m.Update(k, value, ebpf.UpdateAny)
	case 4:
		k := uint32(key)
		return m.Update(k, value, ebpf.UpdateAny)
	default:
		return fmt.Errorf("unsupported key size: %d", keySize)
	}
}

func deleteKey(m *ebpf.Map, key uint64, keySize int) error {
	switch keySize {
	case 2:
		k := uint16(key)
		return m.Delete(k)
	case 4:
		k := uint32(key)
		return m.Delete(k)
	default:
		return fmt.Errorf("unsupported key size: %d", keySize)
	}
}

func iterateKeys(m *ebpf.Map, keySize int) ([]uint64, error) {
	var keys []uint64
	var val uint8
	switch keySize {
	case 2:
		var key uint16
		iter := m.Iterate()
		for iter.Next(&key, &val) {
			keys = append(keys, uint64(key))
		}
		return keys, iter.Err()
	case 4:
		var key uint32
		iter := m.Iterate()
		for iter.Next(&key, &val) {
			keys = append(keys, uint64(key))
		}
		return keys, iter.Err()
	default:
		return nil, fmt.Errorf("unsupported key size: %d", keySize)
	}
}

func isMapEmpty(m *ebpf.Map, keySize int) (bool, error) {
	keys, err := iterateKeys(m, keySize)
	if err != nil {
		return false, err
	}
	return len(keys) == 0, nil
}

func clearAll(m *ebpf.Map, keySize int) error {
	keys, err := iterateKeys(m, keySize)
	if err != nil {
		return err
	}
	for _, k := range keys {
		if err := deleteKey(m, k, keySize); err != nil {
			return err
		}
	}
	return nil
}
