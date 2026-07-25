package syscall

import "fmt"

/*
	ValidateFilter warns when a syscall filter targets a number the host's
	table does not know: it will never match, though it may be valid on a
	newer kernel. Only the syscall maps are checked; other maps return no
	warning. Implements control.FilterValidator.
*/
func (t *TracerModule) ValidateFilter(mapName string, key uint64) (string, error) {
	if mapName != "syscall" && mapName != "syscall_deny" {
		return "", nil
	}
	if _, ok := syscallNames[key]; ok {
		return "", nil
	}
	return fmt.Sprintf("syscall %d not in table for this architecture -- filter will never match (may be valid on a newer kernel)", key), nil
}
