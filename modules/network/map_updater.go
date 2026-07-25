package network

/*
	MapUpdater implementation for the network module.

	Wraps PidFilter, UidFilter, PortFilter, and their deny variants with
	live update, delete, list, and clear operations via bpfutil.

	Supported map names: pid, uid, port, pid_deny, uid_deny, port_deny
	Key types: pid=uint32, uid=uint32, port=uint16

	Bitmask convention:
		bit 0 = pid_filter active
		bit 1 = uid_filter active
		bit 2 = port_filter active
		bit 3 = pid_deny filter active
		bit 4 = uid_deny filter active
		bit 5 = port_deny filter active
*/

import (
	"fmt"

	"github.com/PranavRJoshi/Veil/internal/bpfutil"
)

func (n *NetworkModule) initMapUpdater() {
	n.updater = &bpfutil.MapUpdaterState{
		Filters: map[string]bpfutil.FilterMeta{
			"pid": {
				BpfMap:  n.objs.PidFilter,
				Bit:     bpfutil.BitPID,
				KeySize: 4,
			},
			"uid": {
				BpfMap:  n.objs.UidFilter,
				Bit:     bpfutil.BitUID,
				KeySize: 4,
			},
			"port": {
				BpfMap:  n.objs.PortFilter,
				Bit:     bpfutil.BitSpecific,
				KeySize: 2,
			},
			"pid_deny": {
				BpfMap:  n.objs.PidDeny,
				Bit:     bpfutil.BitPIDDeny,
				KeySize: 4,
			},
			"uid_deny": {
				BpfMap:  n.objs.UidDeny,
				Bit:     bpfutil.BitUIDDeny,
				KeySize: 4,
			},
			"port_deny": {
				BpfMap:  n.objs.PortDeny,
				Bit:     bpfutil.BitSpecificDeny,
				KeySize: 2,
			},
		},
		CfgMap: n.objs.FilterCfg,
	}
}

func (n *NetworkModule) AddFilter(mapName string, key uint64) error {
	n.updater.Mu.Lock()
	defer n.updater.Mu.Unlock()

	meta, ok := n.updater.Filters[mapName]
	if !ok {
		return fmt.Errorf("network: unknown filter map %q (valid: pid, uid, port)", mapName)
	}

	if err := bpfutil.UpdateMapKey(meta.BpfMap, key, 1, meta.KeySize); err != nil {
		return fmt.Errorf("network: add %s filter %d: %w", mapName, key, err)
	}

	return n.updater.SetBit(meta.Bit)
}

func (n *NetworkModule) DelFilter(mapName string, key uint64) error {
	n.updater.Mu.Lock()
	defer n.updater.Mu.Unlock()

	meta, ok := n.updater.Filters[mapName]
	if !ok {
		return fmt.Errorf("network: unknown filter map %q (valid: pid, uid, port)", mapName)
	}

	if !bpfutil.LookupMapKey(meta.BpfMap, key, meta.KeySize) {
		return fmt.Errorf("network: key %d not found in %s filter", key, mapName)
	}

	if err := bpfutil.DeleteMapKey(meta.BpfMap, key, meta.KeySize); err != nil {
		return fmt.Errorf("network: del %s filter %d: %w", mapName, key, err)
	}

	empty, err := bpfutil.IsMapEmpty(meta.BpfMap, meta.KeySize)
	if err != nil {
		return fmt.Errorf("network: check %s empty: %w", mapName, err)
	}
	if empty {
		return n.updater.ClearBit(meta.Bit)
	}

	return nil
}

func (n *NetworkModule) ListFilters(mapName string) ([]uint64, error) {
	n.updater.Mu.Lock()
	defer n.updater.Mu.Unlock()

	meta, ok := n.updater.Filters[mapName]
	if !ok {
		return nil, fmt.Errorf("network: unknown filter map %q (valid: pid, uid, port)", mapName)
	}

	return bpfutil.IterateMapKeys(meta.BpfMap, meta.KeySize)
}

func (n *NetworkModule) ClearFilters(mapName string) error {
	n.updater.Mu.Lock()
	defer n.updater.Mu.Unlock()

	meta, ok := n.updater.Filters[mapName]
	if !ok {
		return fmt.Errorf("network: unknown filter map %q (valid: pid, uid, port)", mapName)
	}

	if err := bpfutil.ClearAllKeys(meta.BpfMap, meta.KeySize); err != nil {
		return fmt.Errorf("network: clear %s: %w", mapName, err)
	}

	return n.updater.ClearBit(meta.Bit)
}

func (n *NetworkModule) Status() string {
	n.updater.Mu.Lock()
	defer n.updater.Mu.Unlock()

	pids, _ := bpfutil.IterateMapKeys(n.updater.Filters["pid"].BpfMap, 4)
	uids, _ := bpfutil.IterateMapKeys(n.updater.Filters["uid"].BpfMap, 4)
	ports, _ := bpfutil.IterateMapKeys(n.updater.Filters["port"].BpfMap, 2)
	pidDeny, _ := bpfutil.IterateMapKeys(n.updater.Filters["pid_deny"].BpfMap, 4)
	uidDeny, _ := bpfutil.IterateMapKeys(n.updater.Filters["uid_deny"].BpfMap, 4)
	portDeny, _ := bpfutil.IterateMapKeys(n.updater.Filters["port_deny"].BpfMap, 2)

	return fmt.Sprintf("network: loaded, filters: pid=%s, uid=%s, port=%s, pid_deny=%s, uid_deny=%s, port_deny=%s",
		bpfutil.FmtKeys(pids), bpfutil.FmtKeys(uids), bpfutil.FmtKeys(ports),
		bpfutil.FmtKeys(pidDeny), bpfutil.FmtKeys(uidDeny), bpfutil.FmtKeys(portDeny))
}
