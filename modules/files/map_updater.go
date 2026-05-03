package files

/*
	MapUpdater implementation for the files module.
	NOTE: Refer to modules/syscall/map_updater.go for additional
	information since the implementations are mostly identical.

	Wraps PidFilter and UidFilter BPF maps with live update, delete,
	list, and clear operations. Manages the filter_cfg bitmask to
	ensure consistency between map contents and filter activation.

	Supported map names: "pid", "uid"
	Key types: pid=uint32, uid=uint32

	Bitmask convention:
		bit 0 = pid_filter active
		bit 1 = uid_filter active
		bit 2 = <unused>
		bit 3 = pid_deny filter active
		bit 4 = uid_deny filter active
*/

import (
	"fmt"
	"sync"

	"github.com/cilium/ebpf"
)

type filterMeta struct {
	bpfMap *ebpf.Map
	bit    uint32
}

type mapUpdaterState struct {
	mu      sync.Mutex
	filters map[string]filterMeta
	cfgMap  *ebpf.Map
}

func (f *FilesModule) initMapUpdater() {
	f.updater = &mapUpdaterState{
		filters: map[string]filterMeta{
			"pid": {
				bpfMap: f.objs.PidFilter,
				bit:    1,
			},
			"uid": {
				bpfMap: f.objs.UidFilter,
				bit:    2,
			},
			"pid_deny": {
				bpfMap: f.objs.PidDeny,
				bit:    8,
			},
			"uid_deny": {
				bpfMap: f.objs.UidDeny,
				bit:    16,
			},
		},
		cfgMap: f.objs.FilterCfg,
	}
}

func (f *FilesModule) AddFilter(mapName string, key uint64) error {
	f.updater.mu.Lock()
	defer f.updater.mu.Unlock()

	meta, ok := f.updater.filters[mapName]
	if !ok {
		return fmt.Errorf("files: unknown filter map %q (valid: pid, uid)", mapName)
	}

	k := uint32(key)
	enable := uint8(1)
	if err := meta.bpfMap.Update(k, enable, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("files: add %s filter %d: %w", mapName, key, err)
	}

	return f.updater.setBit(meta.bit)
}

func (f *FilesModule) DelFilter(mapName string, key uint64) error {
	f.updater.mu.Lock()
	defer f.updater.mu.Unlock()

	meta, ok := f.updater.filters[mapName]
	if !ok {
		return fmt.Errorf("files: unknown filter map %q (valid: pid, uid)", mapName)
	}

	/* Verify that the key exists before attempting deletion */
	k := uint32(key)
	var val uint8
	if err := meta.bpfMap.Lookup(k, &val); err != nil {
		return fmt.Errorf("files: key %d not found in %s filter", key, mapName)
	}

	if err := meta.bpfMap.Delete(k); err != nil {
		return fmt.Errorf("files: del %s filter %d: %w", mapName, key, err)
	}

	empty, err := isMapEmpty(meta.bpfMap)
	if err != nil {
		return fmt.Errorf("files: check %s empty: %w", mapName, err)
	}
	if empty {
		return f.updater.clearBit(meta.bit)
	}

	return nil
}

func (f *FilesModule) ListFilters(mapName string) ([]uint64, error) {
	f.updater.mu.Lock()
	defer f.updater.mu.Unlock()

	meta, ok := f.updater.filters[mapName]
	if !ok {
		return nil, fmt.Errorf("files: unknown filter map %q (valid: pid, uid)", mapName)
	}

	return iterateMap32(meta.bpfMap)
}

func (f *FilesModule) ClearFilters(mapName string) error {
	f.updater.mu.Lock()
	defer f.updater.mu.Unlock()

	meta, ok := f.updater.filters[mapName]
	if !ok {
		return fmt.Errorf("files: unknown filter map %q (valid: pid, uid)", mapName)
	}

	if err := clearMap32(meta.bpfMap); err != nil {
		return fmt.Errorf("files: clear %s: %w", mapName, err)
	}

	return f.updater.clearBit(meta.bit)
}

func (f *FilesModule) Status() string {
	f.updater.mu.Lock()
	defer f.updater.mu.Unlock()

	pids, _ := iterateMap32(f.updater.filters["pid"].bpfMap)
	uids, _ := iterateMap32(f.updater.filters["uid"].bpfMap)
	pidDeny, _ := iterateMap32(f.updater.filters["pid_deny"].bpfMap)
	uidDeny, _ := iterateMap32(f.updater.filters["uid_deny"].bpfMap)

	return fmt.Sprintf("files: loaded, filters: pid=%v, uid=%v, pid_deny=%v, uid_deny=%v",
	pids, uids, pidDeny, uidDeny)
}

// ---------------------------------------------------------------------------
// filter_cfg bitmask helpers
// ---------------------------------------------------------------------------

func (s *mapUpdaterState) setBit(bit uint32) error {
	mask, _ := s.readCfg()
	if mask & bit != 0 {
		return nil
	}
	mask |= bit

	return s.writeCfg(mask)
}

func (s *mapUpdaterState) clearBit(bit uint32) error {
	mask, _ := s.readCfg()
	if mask & bit == 0 {
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
// BPF map helpers (all maps in files use uint32 keys)
// ---------------------------------------------------------------------------

func iterateMap32(m *ebpf.Map) ([]uint64, error) {
	var keys []uint64
	var key uint32
	var val uint8

	iter := m.Iterate()
	for iter.Next(&key, &val) {
		keys = append(keys, uint64(key))
	}

	return keys, iter.Err()
}

func isMapEmpty(m *ebpf.Map) (bool, error) {
	keys, err := iterateMap32(m)
	if err != nil {
		return false, err
	}

	return len(keys) == 0, nil
}

func clearMap32(m *ebpf.Map) error {
	keys, err := iterateMap32(m)
	if err != nil {
		return err
	}
	for _, k := range keys {
		key := uint32(k)
		if err := m.Delete(key); err != nil {
			return err
		}
	}

	return nil
}
