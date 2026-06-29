package bpfutil

import (
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// FmtKeys
// ---------------------------------------------------------------------------

func TestFmtKeys_Nil(t *testing.T) {
	if got := FmtKeys(nil); got != "[]" {
		t.Errorf("FmtKeys(nil) = %q, want %q", got, "[]")
	}
}

func TestFmtKeys_Empty(t *testing.T) {
	if got := FmtKeys([]uint64{}); got != "[]" {
		t.Errorf("FmtKeys([]) = %q, want %q", got, "[]")
	}
}

func TestFmtKeys_Single(t *testing.T) {
	if got := FmtKeys([]uint64{42}); got != "[42]" {
		t.Errorf("FmtKeys([42]) = %q, want %q", got, "[42]")
	}
}

func TestFmtKeys_Multiple(t *testing.T) {
	if got := FmtKeys([]uint64{1, 2, 3}); got != "[1,2,3]" {
		t.Errorf("FmtKeys([1,2,3]) = %q, want %q", got, "[1,2,3]")
	}
}

func TestFmtKeys_NoSpaces(t *testing.T) {
	got := FmtKeys([]uint64{100, 200, 300})
	if strings.Contains(got, " ") {
		t.Errorf("FmtKeys should not contain spaces, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// Unsupported key size error paths (no BPF map required)
// ---------------------------------------------------------------------------

func TestUpdateMapKey_UnsupportedKeySize(t *testing.T) {
	err := UpdateMapKey(nil, 0, 1, 99)
	if err == nil {
		t.Fatal("expected error for unsupported key size 99")
	}
	if !strings.Contains(err.Error(), "unsupported key size") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestDeleteMapKey_UnsupportedKeySize(t *testing.T) {
	err := DeleteMapKey(nil, 0, 99)
	if err == nil {
		t.Fatal("expected error for unsupported key size 99")
	}
	if !strings.Contains(err.Error(), "unsupported key size") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestIterateMapKeys_UnsupportedKeySize(t *testing.T) {
	_, err := IterateMapKeys(nil, 99)
	if err == nil {
		t.Fatal("expected error for unsupported key size 99")
	}
	if !strings.Contains(err.Error(), "unsupported key size") {
		t.Errorf("unexpected error message: %v", err)
	}
}

// ---------------------------------------------------------------------------
// FilterMeta struct
// ---------------------------------------------------------------------------

func TestFilterMeta_Fields(t *testing.T) {
	fm := FilterMeta{
		BpfMap:  nil,
		Bit:     4,
		KeySize: 4,
	}
	if fm.Bit != 4 {
		t.Errorf("Bit = %d, want 4", fm.Bit)
	}
	if fm.KeySize != 4 {
		t.Errorf("KeySize = %d, want 4", fm.KeySize)
	}
}

// ---------------------------------------------------------------------------
// MapUpdaterState struct
// ---------------------------------------------------------------------------

func TestMapUpdaterState_FiltersMap(t *testing.T) {
	s := &MapUpdaterState{
		Filters: map[string]FilterMeta{
			"pid": {Bit: 1, KeySize: 4},
			"uid": {Bit: 2, KeySize: 4},
		},
	}
	if len(s.Filters) != 2 {
		t.Fatalf("expected 2 filters, got %d", len(s.Filters))
	}
	pid, ok := s.Filters["pid"]
	if !ok {
		t.Fatal("pid filter not found")
	}
	if pid.Bit != 1 || pid.KeySize != 4 {
		t.Errorf("pid filter = %+v, want Bit=1 KeySize=4", pid)
	}
}
