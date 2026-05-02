package syscall

/*
	MapUpdater implementation for the syscall module.

	This file implements control.MapUpdater by wrapping the module's BPF filter
	maps (PidFilter, UidFilter, SyscallFilter) with live update, delete, list,
	and clear operations.

	The critical invariant is the filter_cfg bitmask: the BPF program only checks
	a filter map if the corresponding bit is set. If the bit is set but the map
	is empty, all events are dropped. Therefore:

		- AddFilter: insert key into hash map, set the filter bit
		- DelFilter: remove key from hash map; if the map is now empty, clear the bit
		- ClearFilters: delete all keys && clear the corresponding cfg bit
		- ListFilters: iterate the hash map

	Supported map names: 'pid', 'uid', and 'syscall'
	Key types: pid=uint32, uid=uint32, syscall=uint64

	The filter_cfg bitmask convention matches the BPF C code:
		bit 0 - pid_filter active
		bit 1 - uid_filter active
		bit 2 - syscall_filter active
*/

import (
	"fmt"
	"sync"

	"github.com/cilium/ebpf"
)

/*
	filterMeta describes one filter map and its position in the filter_cfg
	bitmask. This avoids repeating the switch logic in every method.
*/
type filterMeta struct {
	bpfMap    *ebpf.Map
	bit       uint32    /* bitmask position: 1, 2, or 4 */
	keySize   int       /* bytes: 4 for uint32, 8 for uint64 */
}

/*
	mapUpdaterState holds the mutable state for runtime filter control.
	A mutex protects concurrent access from the control socket and interactive
	prompt.
*/
type mapUpdaterState struct {
	mu         sync.Mutex
	filters    map[string]filterMeta
	cfgMap     *ebpf.Map    /* filter_cfg array map */
}

/*
	Value of t.updater.filters[key] is a reference of t.objs.<mapname>
	It also possible for us to simply use t.objs.<mapname>, but having
	filterMeta object on mapUpdaterState isn't much of an expensive
	operation and also makes the code more readable.
*/
func (t *TracerModule) initMapUpdater() {
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
			"syscall": {
				bpfMap:  t.objs.SyscallFilter,
				bit:     4,
				keySize: 8,
			},
		},
		cfgMap: t.objs.FilterCfg,
	}
}

/*
	AddFilter inserts a key into the named filter map and ensures the
	corresponding filter_cfg bit is set. The BPF program will start checking
	this filter on the next event.
*/
func (t *TracerModule) AddFilter(mapName string, key uint64) error {
	t.updater.mu.Lock()
	defer t.updater.mu.Unlock()

	meta, ok := t.updater.filters[mapName]
	if !ok {
		return fmt.Errorf("syscall: unknown filter map %q (valid: pid, uid, syscall)", mapName)
	}

	enable := uint8(1)
	if err := updateMapKey(meta.bpfMap, key, enable, meta.keySize); err != nil {
		return fmt.Errorf("syscall: add %s filter %d: %w", mapName, key, err)
	}

	return t.updater.setBit(meta.bit)
}

/*
	DelFilter removes a key from the named filter map. If the map becomes empty,
	the corresponding filter_cfg bit is cleared so the BPF program stops
	filtering on this predicate (otherwise all events would be dropped).
*/
func (t *TracerModule) DelFilter(mapName string, key uint64) error {
	t.updater.mu.Lock()
	defer t.updater.mu.Unlock()

	meta, ok := t.updater.filters[mapName]
	if !ok {
		return fmt.Errorf("syscall: unknown filter map %q (valid: pid, uid, syscall)", mapName)
	}

	if err := deleteMapKey(meta.bpfMap, key, meta.keySize); err != nil {
		return fmt.Errorf("syscall: del %s filter %d: %w", mapName, key, err)
	}

	/*
		Check if the map is now empty. If so, clear the bit to avoid the BPF
		program dropping all events.
	*/
	empty, err := isMapEmpty(meta.bpfMap, meta.keySize)
	if err != nil {
		return fmt.Errorf("syscall: check %s empty: %w", mapName, err)
	}
	if empty {
		return t.updater.clearBit(meta.bit)
	}

	return nil
}

/*
	ListFilters iterates the named filter map and returns all keys.
*/
func (t *TracerModule) ListFilters(mapName string) ([]uint64, error) {
	t.updater.mu.Lock()
	defer t.updater.mu.Unlock()

	meta, ok := t.updater.filters[mapName]
	if !ok {
		return nil, fmt.Errorf("syscall: unknown filter map %q (valid: pid, uid, syscall)", mapName)
	}

	return iterateMapKeys(meta.bpfMap, meta.keySize)
}

/*
	ClearFilters removes all entries from the named filter map and clears the
	corresponding filter_cfg bit.
*/
func (t *TracerModule) ClearFilters(mapName string) error {
	t.updater.mu.Lock()
	defer t.updater.mu.Unlock()

	meta, ok := t.updater.filters[mapName]
	if !ok {
		return fmt.Errorf("syscall: unknown filter map %q (valid: pid, uid, syscall)", mapName)
	}

	if err := clearAllKeys(meta.bpfMap, meta.keySize); err != nil {
		return fmt.Errorf("syscall: clear %s: %w", mapName, err)
	}

	return t.updater.clearBit(meta.bit)
}

/*
	Status returns a human-readable summary of the module's filter state.
*/
func (t *TracerModule) Status() string {
	t.updater.mu.Lock()
	defer t.updater.mu.Unlock()

	pids, _ := iterateMapKeys(t.updater.filters["pid"].bpfMap, 4)
	uids, _ := iterateMapKeys(t.updater.filters["uid"].bpfMap, 4)
	syscalls, _ := iterateMapKeys(t.updater.filters["syscall"].bpfMap, 8)

	return fmt.Sprintf("syscall: loaded, filters: pid=%v, uid=%v, syscall=%v", pids, uids, syscalls)
}

// --------------------------------------------------------
// filter_cfg bitmask helpers
// --------------------------------------------------------

/*
	setBit sets a bit in the filter_cfg[0] bitmask. This tells the BPF program
	to start checking the corresponding filter map.
*/
func (s *mapUpdaterState) setBit(bit uint32) error {
	mask, err := s.readCfg()
	if err != nil {
		return err
	}

	if mask & bit != 0 {
		return nil /* already set */
	}
	mask |= bit

	return s.writeCfg(mask)
}

/*
	clearBit clears a bit in the filter_cfg[0] bitmask. This tells the BPF
	program to stop checking the corresponding filter map.
*/
func (s *mapUpdaterState) clearBit(bit uint32) error {
	mask, err := s.readCfg()
	if err != nil {
		return err
	}

	if mask & bit == 0 {
		return nil /* already clear */
	}
	/*
		bit-clear (AND NOT) operator.

		For bits that are set in 'bit', the corresponding bit in 'mask' is
		unset. It's essentially the same as:

			mask &= ~bit

		in C.
	*/
	mask &^= bit

	return s.writeCfg(mask)
}

func (s *mapUpdaterState) readCfg() (uint32, error) {
	cfgKey := uint32(0)
	var mask uint32

	if err := s.cfgMap.Lookup(cfgKey, &mask); err != nil {
		/*
			If the key doesn't exist yet (no filters were set at startup),
			treat it as 0.
		*/
		return 0, nil
	}

	return mask, nil
}

func (s *mapUpdaterState) writeCfg(mask uint32) error {
	cfgKey := uint32(0)
	return s.cfgMap.Update(cfgKey, mask, ebpf.UpdateAny)
}

// ------------------------------------------------------------------
// BPF map operation helpers
//
// These handle the key size conversion. The MapUpdater interface
// uses uint64 for all keys, but the BPF maps have typed keys
// (uint32 for PID/UID, uint64 for syscall nr). We marshal the
// key to the correct size before calling the ebpf.Map methods.
// ------------------------------------------------------------------

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
