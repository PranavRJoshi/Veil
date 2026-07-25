package files

/*
	MapUpdater implementation for the files module.

	Wraps PidFilter, UidFilter, and their deny variants with live update,
	delete, list, and clear operations via bpfutil.

	Supported map names: pid, uid, pid_deny, uid_deny
	Key types: all uint32

	Bitmask convention:
		bit 0 = pid_filter active
		bit 1 = uid_filter active
		bit 2 = <unused>
		bit 3 = pid_deny filter active
		bit 4 = uid_deny filter active
*/

import (
	"fmt"

	"github.com/PranavRJoshi/Veil/internal/bpfutil"
)

func (f *FilesModule) initMapUpdater() {
	f.updater = &bpfutil.MapUpdaterState{
		Filters: map[string]bpfutil.FilterMeta{
			"pid": {
				BpfMap:  f.objs.PidFilter,
				Bit:     bpfutil.BitPID,
				KeySize: 4,
			},
			"uid": {
				BpfMap:  f.objs.UidFilter,
				Bit:     bpfutil.BitUID,
				KeySize: 4,
			},
			"pid_deny": {
				BpfMap:  f.objs.PidDeny,
				Bit:     bpfutil.BitPIDDeny,
				KeySize: 4,
			},
			"uid_deny": {
				BpfMap:  f.objs.UidDeny,
				Bit:     bpfutil.BitUIDDeny,
				KeySize: 4,
			},
		},
		CfgMap: f.objs.FilterCfg,
	}
}

func (f *FilesModule) AddFilter(mapName string, key uint64) error {
	f.updater.Mu.Lock()
	defer f.updater.Mu.Unlock()

	meta, ok := f.updater.Filters[mapName]
	if !ok {
		return fmt.Errorf("files: unknown filter map %q (valid: pid, uid)", mapName)
	}

	if err := bpfutil.UpdateMapKey(meta.BpfMap, key, 1, meta.KeySize); err != nil {
		return fmt.Errorf("files: add %s filter %d: %w", mapName, key, err)
	}

	return f.updater.SetBit(meta.Bit)
}

func (f *FilesModule) DelFilter(mapName string, key uint64) error {
	f.updater.Mu.Lock()
	defer f.updater.Mu.Unlock()

	meta, ok := f.updater.Filters[mapName]
	if !ok {
		return fmt.Errorf("files: unknown filter map %q (valid: pid, uid)", mapName)
	}

	if !bpfutil.LookupMapKey(meta.BpfMap, key, meta.KeySize) {
		return fmt.Errorf("files: key %d not found in %s filter", key, mapName)
	}

	if err := bpfutil.DeleteMapKey(meta.BpfMap, key, meta.KeySize); err != nil {
		return fmt.Errorf("files: del %s filter %d: %w", mapName, key, err)
	}

	empty, err := bpfutil.IsMapEmpty(meta.BpfMap, meta.KeySize)
	if err != nil {
		return fmt.Errorf("files: check %s empty: %w", mapName, err)
	}
	if empty {
		return f.updater.ClearBit(meta.Bit)
	}

	return nil
}

func (f *FilesModule) ListFilters(mapName string) ([]uint64, error) {
	f.updater.Mu.Lock()
	defer f.updater.Mu.Unlock()

	meta, ok := f.updater.Filters[mapName]
	if !ok {
		return nil, fmt.Errorf("files: unknown filter map %q (valid: pid, uid)", mapName)
	}

	return bpfutil.IterateMapKeys(meta.BpfMap, meta.KeySize)
}

func (f *FilesModule) ClearFilters(mapName string) error {
	f.updater.Mu.Lock()
	defer f.updater.Mu.Unlock()

	meta, ok := f.updater.Filters[mapName]
	if !ok {
		return fmt.Errorf("files: unknown filter map %q (valid: pid, uid)", mapName)
	}

	if err := bpfutil.ClearAllKeys(meta.BpfMap, meta.KeySize); err != nil {
		return fmt.Errorf("files: clear %s: %w", mapName, err)
	}

	return f.updater.ClearBit(meta.Bit)
}

func (f *FilesModule) Status() string {
	f.updater.Mu.Lock()
	defer f.updater.Mu.Unlock()

	pids, _ := bpfutil.IterateMapKeys(f.updater.Filters["pid"].BpfMap, 4)
	uids, _ := bpfutil.IterateMapKeys(f.updater.Filters["uid"].BpfMap, 4)
	pidDeny, _ := bpfutil.IterateMapKeys(f.updater.Filters["pid_deny"].BpfMap, 4)
	uidDeny, _ := bpfutil.IterateMapKeys(f.updater.Filters["uid_deny"].BpfMap, 4)

	return fmt.Sprintf("files: loaded, filters: pid=%s, uid=%s, pid_deny=%s, uid_deny=%s",
		bpfutil.FmtKeys(pids), bpfutil.FmtKeys(uids), bpfutil.FmtKeys(pidDeny), bpfutil.FmtKeys(uidDeny))
}
