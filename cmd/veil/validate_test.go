package main

import (
	"strings"
	"testing"

	"github.com/PranavRJoshi/Veil/internal/control"
)

/*
	validatingFake is a fakeMapUpdater that also implements
	control.FilterValidator, warning whenever its map is the target.
*/
type validatingFake struct {
	*fakeMapUpdater
}

func (v *validatingFake) ValidateFilter(mapName string, key uint64) (string, error) {
	return "warn on " + mapName, nil
}

func TestComposite_ValidateFilterRoutesToOwner(t *testing.T) {
	/* Only the syscall module validates. */
	syscallU := &validatingFake{newFakeMapUpdater("syscall", "pid", "uid", "syscall")}
	networkU := newFakeMapUpdater("network", "pid", "uid", "port")

	ownership := map[string][]string{
		"pid":     {"syscall", "network"},
		"uid":     {"syscall", "network"},
		"syscall": {"syscall"},
		"port":    {"network"},
	}
	c := &compositeUpdater{
		updaters: map[string]control.MapUpdater{
			"syscall": syscallU,
			"network": networkU,
		},
		mapOwnership: ownership,
	}

	/* A syscall-owned map routes to the validating module. */
	if warn, err := c.ValidateFilter("syscall", 999); err != nil || !strings.Contains(warn, "warn on syscall") {
		t.Errorf("ValidateFilter(syscall) = %q, %v; want a syscall warning", warn, err)
	}

	/* A port-only map routes to the non-validating module: no warning. */
	if warn, err := c.ValidateFilter("port", 8080); err != nil || warn != "" {
		t.Errorf("ValidateFilter(port) = %q, %v; want no warning", warn, err)
	}

	/* A shared map hits both; only the validating one contributes. */
	if warn, err := c.ValidateFilter("pid", 1); err != nil || !strings.Contains(warn, "warn on pid") {
		t.Errorf("ValidateFilter(pid) = %q, %v; want the syscall module's warning", warn, err)
	}

	/* An unknown map must not error here; AddFilter reports routing errors. */
	if warn, err := c.ValidateFilter("bogus", 1); err != nil || warn != "" {
		t.Errorf("ValidateFilter(bogus) = %q, %v; want empty, nil", warn, err)
	}
}
