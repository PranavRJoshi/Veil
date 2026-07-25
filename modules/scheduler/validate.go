package scheduler

import (
	"fmt"
	"os"
	"runtime"
)

/*
	ValidateFilter warns when a CPU filter targets an index at or beyond the
	number of logical CPUs: it will never match. A soft warning rather than
	an error, since CPU hotplug can change the count at runtime. Only the CPU
	maps are checked. Implements control.FilterValidator.
*/
func (t *SchedulerModule) ValidateFilter(mapName string, key uint64) (string, error) {
	if mapName != "cpu" && mapName != "cpu_deny" {
		return "", nil
	}
	if n := uint64(runtime.NumCPU()); key >= n {
		return fmt.Sprintf("cpu %d exceeds system CPU count (%d) -- filter may never match", key, n), nil
	}
	return "", nil
}

/*
	warnInvalidCPUs prints a launch-time warning for any configured CPU index
	the runtime cannot have, reusing ValidateFilter so the check lives in one
	place.
*/
func (t *SchedulerModule) warnInvalidCPUs() {
	check := func(mapName string, cpus []uint32) {
		for _, cpu := range cpus {
			if warn, _ := t.ValidateFilter(mapName, uint64(cpu)); warn != "" {
				fmt.Fprintf(os.Stderr, "warning: %s\n", warn)
			}
		}
	}
	check("cpu", t.filter.CPUs)
	check("cpu_deny", t.filter.DenyCPUs)
}
