// Package bpfutil provides shared BPF filter map helpers used by all Veil
// tracing modules.
//
// Every module maintains a set of BPF hash maps (pid, uid, and
// module-specific keys) along with a filter_cfg array map whose bitmask
// tells the BPF program which filter maps are active. This package
// centralises the types and operations common to all modules so they are
// not duplicated in each map_updater.go.
package bpfutil

import (
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
)

// Bitmask positions in filter_cfg[0]. Every module shares this convention,
// and it must match the (mask & N) checks in each BPF program.
const (
	BitPID          uint32 = 1
	BitUID          uint32 = 2
	BitSpecific     uint32 = 4
	BitPIDDeny      uint32 = 8
	BitUIDDeny      uint32 = 16
	BitSpecificDeny uint32 = 32
)

// FilterMeta describes one BPF filter map and its bitmask position in
// the filter_cfg array.
type FilterMeta struct {
	BpfMap  *ebpf.Map
	Bit     uint32
	KeySize int // bytes: 2=uint16 (port), 4=uint32 (pid/uid), 8=uint64 (syscall)
}

// FilterSpec describes one filter dimension to load at startup: the map to
// write, its bit in filter_cfg, its key width, and the values to insert.
type FilterSpec struct {
	Map     *ebpf.Map
	Bit     uint32
	KeySize int
	Values  []uint64
}

// PopulateFilters writes each spec's values into its map, sets that spec's
// bit in the mask when it has any values, and writes the final mask to
// cfgMap[0]. Specs with no values are skipped. This replaces the
// hand-written mask-building loop each module used to carry.
func PopulateFilters(cfgMap *ebpf.Map, specs []FilterSpec) error {
	var mask uint32
	for _, s := range specs {
		if len(s.Values) == 0 {
			continue
		}
		mask |= s.Bit
		for _, v := range s.Values {
			if err := UpdateMapKey(s.Map, v, 1, s.KeySize); err != nil {
				return fmt.Errorf("populate filter (bit %d): %w", s.Bit, err)
			}
		}
	}
	if mask != 0 {
		if err := cfgMap.Update(uint32(0), mask, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("write filter_cfg: %w", err)
		}
	}
	return nil
}

// WidenU32 converts a uint32 filter slice to the []uint64 FilterSpec carries.
func WidenU32(vals []uint32) []uint64 {
	out := make([]uint64, len(vals))
	for i, v := range vals {
		out[i] = uint64(v)
	}
	return out
}

// WidenU16 converts a uint16 filter slice to the []uint64 FilterSpec carries.
func WidenU16(vals []uint16) []uint64 {
	out := make([]uint64, len(vals))
	for i, v := range vals {
		out[i] = uint64(v)
	}
	return out
}

// MapUpdaterState holds the mutable state for runtime BPF filter control.
// Mu must be held for all reads and writes to Filters or CfgMap.
type MapUpdaterState struct {
	Mu      sync.Mutex
	Filters map[string]FilterMeta
	CfgMap  *ebpf.Map
}

// SetBit sets a bit in the filter_cfg[0] bitmask so the BPF program
// starts checking the corresponding filter map.
func (s *MapUpdaterState) SetBit(bit uint32) error {
	mask, err := s.ReadCfg()
	if err != nil {
		return err
	}
	if mask&bit != 0 {
		return nil
	}
	return s.WriteCfg(mask | bit)
}

// ClearBit clears a bit in the filter_cfg[0] bitmask so the BPF program
// stops checking the corresponding filter map.
func (s *MapUpdaterState) ClearBit(bit uint32) error {
	mask, err := s.ReadCfg()
	if err != nil {
		return err
	}
	if mask&bit == 0 {
		return nil
	}
	return s.WriteCfg(mask &^ bit)
}

// ReadCfg reads the current bitmask from filter_cfg[0].
// Returns 0 if the key does not yet exist (no filters set at startup)
// and a read failure is returned with the corresponding error message.
func (s *MapUpdaterState) ReadCfg() (uint32, error) {
	cfgKey := uint32(0)
	var mask uint32
	if err := s.CfgMap.Lookup(cfgKey, &mask); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return 0, nil
		}
		return 0, err
	}
	return mask, nil
}

// WriteCfg writes mask into filter_cfg[0].
func (s *MapUpdaterState) WriteCfg(mask uint32) error {
	cfgKey := uint32(0)
	return s.CfgMap.Update(cfgKey, mask, ebpf.UpdateAny)
}

// UpdateMapKey inserts or updates key in m with value 1.
// key is cast to the native type for the map (uint16, uint32, or uint64).
func UpdateMapKey(m *ebpf.Map, key uint64, value uint8, keySize int) error {
	switch keySize {
	case 2:
		return m.Update(uint16(key), value, ebpf.UpdateAny)
	case 4:
		return m.Update(uint32(key), value, ebpf.UpdateAny)
	case 8:
		return m.Update(key, value, ebpf.UpdateAny)
	default:
		return fmt.Errorf("unsupported key size: %d", keySize)
	}
}

// LookupMapKey returns true if key exists in m.
func LookupMapKey(m *ebpf.Map, key uint64, keySize int) bool {
	var val uint8
	switch keySize {
	case 2:
		return m.Lookup(uint16(key), &val) == nil
	case 4:
		return m.Lookup(uint32(key), &val) == nil
	case 8:
		return m.Lookup(key, &val) == nil
	default:
		return false
	}
}

// DeleteMapKey removes key from m.
func DeleteMapKey(m *ebpf.Map, key uint64, keySize int) error {
	switch keySize {
	case 2:
		return m.Delete(uint16(key))
	case 4:
		return m.Delete(uint32(key))
	case 8:
		return m.Delete(key)
	default:
		return fmt.Errorf("unsupported key size: %d", keySize)
	}
}

// IterateMapKeys returns all keys in m as []uint64.
func IterateMapKeys(m *ebpf.Map, keySize int) ([]uint64, error) {
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
	case 8:
		var key uint64
		iter := m.Iterate()
		for iter.Next(&key, &val) {
			keys = append(keys, key)
		}
		return keys, iter.Err()
	default:
		return nil, fmt.Errorf("unsupported key size: %d", keySize)
	}
}

// IsMapEmpty returns true if m contains no entries.
func IsMapEmpty(m *ebpf.Map, keySize int) (bool, error) {
	keys, err := IterateMapKeys(m, keySize)
	if err != nil {
		return false, err
	}
	return len(keys) == 0, nil
}

// ClearAllKeys deletes every entry from m.
func ClearAllKeys(m *ebpf.Map, keySize int) error {
	keys, err := IterateMapKeys(m, keySize)
	if err != nil {
		return err
	}
	for _, k := range keys {
		if err := DeleteMapKey(m, k, keySize); err != nil {
			return err
		}
	}
	return nil
}

// FmtKeys formats a slice of uint64 keys as a comma-separated string.
func FmtKeys(keys []uint64) string {
	return strings.ReplaceAll(fmt.Sprintf("%v", keys), " ", ",")
}
