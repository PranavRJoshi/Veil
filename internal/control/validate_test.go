package control

import (
	"fmt"
	"strings"
	"testing"
)

/*
	validatingUpdater is a fakeUpdater that also implements FilterValidator,
	returning a preset warning and/or hard error.
*/
type validatingUpdater struct {
	*fakeUpdater
	warn    string
	hardErr error
}

func (u *validatingUpdater) ValidateFilter(mapName string, key uint64) (string, error) {
	return u.warn, u.hardErr
}

func TestDoAdd_ValidatorSoftWarn(t *testing.T) {
	u := &validatingUpdater{fakeUpdater: newFakeUpdater(), warn: "never matches"}
	h := NewHandler(u)

	resp := h.doAdd("pid", "1234")
	if !strings.HasPrefix(resp, "WARN") || !strings.Contains(resp, "never matches") {
		t.Errorf("doAdd = %q, want WARN carrying the validator message", resp)
	}

	/* A soft warning must not block the add. */
	if keys, _ := u.ListFilters("pid"); len(keys) != 1 {
		t.Errorf("soft warn should still add the key, got %v", keys)
	}
}

func TestDoAdd_ValidatorHardError(t *testing.T) {
	u := &validatingUpdater{fakeUpdater: newFakeUpdater(), hardErr: fmt.Errorf("nope")}
	h := NewHandler(u)

	if resp := h.doAdd("pid", "1234"); !strings.HasPrefix(resp, "ERR") {
		t.Errorf("doAdd = %q, want ERR", resp)
	}

	/* A hard error must block the add. */
	if keys, _ := u.ListFilters("pid"); len(keys) != 0 {
		t.Errorf("hard error should block the add, got %v", keys)
	}
}

func TestDoAdd_NoValidator(t *testing.T) {
	h := NewHandler(newFakeUpdater())
	if resp := h.doAdd("pid", "1234"); resp != "OK" {
		t.Errorf("doAdd without a validator = %q, want OK", resp)
	}
}
