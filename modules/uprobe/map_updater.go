package uprobe

/*
	MapUpdater implementation for the uprobe module.

	Wraps PidFilter, UidFilter, and their deny variants with live update,
	delete, list, and clear operations via bpfutil. Uprobe has no
	module-specific filter dimension.

	Supported map names: pid, uid, pid_deny, uid_deny
	Key types: all uint32

	Bitmask convention:
		bit 0 = pid_filter active
		bit 1 = uid_filter active
		bit 3 = pid_deny filter active
		bit 4 = uid_deny filter active
*/

import (
	"fmt"

	"github.com/PranavRJoshi/Veil/internal/bpfutil"
)

func (u *UprobeModule) initMapUpdater() {
	u.updater = &bpfutil.MapUpdaterState{
		Filters: map[string]bpfutil.FilterMeta{
			"pid": {
				BpfMap:  u.objs.PidFilter,
				Bit:     bpfutil.BitPID,
				KeySize: 4,
			},
			"uid": {
				BpfMap:  u.objs.UidFilter,
				Bit:     bpfutil.BitUID,
				KeySize: 4,
			},
			"pid_deny": {
				BpfMap:  u.objs.PidDeny,
				Bit:     bpfutil.BitPIDDeny,
				KeySize: 4,
			},
			"uid_deny": {
				BpfMap:  u.objs.UidDeny,
				Bit:     bpfutil.BitUIDDeny,
				KeySize: 4,
			},
		},
		CfgMap: u.objs.FilterCfg,
	}
}

func (u *UprobeModule) AddFilter(mapName string, key uint64) error {
	u.updater.Mu.Lock()
	defer u.updater.Mu.Unlock()

	meta, ok := u.updater.Filters[mapName]
	if !ok {
		return fmt.Errorf("uprobe: unknown filter map %q", mapName)
	}

	if err := bpfutil.UpdateMapKey(meta.BpfMap, key, 1, meta.KeySize); err != nil {
		return fmt.Errorf("uprobe: add %s filter %d: %w", mapName, key, err)
	}

	return u.updater.SetBit(meta.Bit)
}

func (u *UprobeModule) DelFilter(mapName string, key uint64) error {
	u.updater.Mu.Lock()
	defer u.updater.Mu.Unlock()

	meta, ok := u.updater.Filters[mapName]
	if !ok {
		return fmt.Errorf("uprobe: unknown filter map %q", mapName)
	}

	if !bpfutil.LookupMapKey(meta.BpfMap, key, meta.KeySize) {
		return fmt.Errorf("uprobe: key %d not found in %s filter", key, mapName)
	}

	if err := bpfutil.DeleteMapKey(meta.BpfMap, key, meta.KeySize); err != nil {
		return fmt.Errorf("uprobe: del %s filter %d: %w", mapName, key, err)
	}

	empty, err := bpfutil.IsMapEmpty(meta.BpfMap, meta.KeySize)
	if err != nil {
		return fmt.Errorf("uprobe: check %s empty: %w", mapName, err)
	}
	if empty {
		return u.updater.ClearBit(meta.Bit)
	}

	return nil
}

func (u *UprobeModule) ListFilters(mapName string) ([]uint64, error) {
	u.updater.Mu.Lock()
	defer u.updater.Mu.Unlock()

	meta, ok := u.updater.Filters[mapName]
	if !ok {
		return nil, fmt.Errorf("uprobe: unknown filter map %q", mapName)
	}

	return bpfutil.IterateMapKeys(meta.BpfMap, meta.KeySize)
}

func (u *UprobeModule) ClearFilters(mapName string) error {
	u.updater.Mu.Lock()
	defer u.updater.Mu.Unlock()

	meta, ok := u.updater.Filters[mapName]
	if !ok {
		return fmt.Errorf("uprobe: unknown filter map %q", mapName)
	}

	if err := bpfutil.ClearAllKeys(meta.BpfMap, meta.KeySize); err != nil {
		return fmt.Errorf("uprobe: clear %s: %w", mapName, err)
	}

	return u.updater.ClearBit(meta.Bit)
}

func (u *UprobeModule) Status() string {
	u.updater.Mu.Lock()
	defer u.updater.Mu.Unlock()

	pids, _ := bpfutil.IterateMapKeys(u.updater.Filters["pid"].BpfMap, 4)
	uids, _ := bpfutil.IterateMapKeys(u.updater.Filters["uid"].BpfMap, 4)
	pidDeny, _ := bpfutil.IterateMapKeys(u.updater.Filters["pid_deny"].BpfMap, 4)
	uidDeny, _ := bpfutil.IterateMapKeys(u.updater.Filters["uid_deny"].BpfMap, 4)

	return fmt.Sprintf("uprobe: loaded, filters: pid=%s, uid=%s, pid_deny=%s, uid_deny=%s",
		bpfutil.FmtKeys(pids), bpfutil.FmtKeys(uids),
		bpfutil.FmtKeys(pidDeny), bpfutil.FmtKeys(uidDeny))
}
