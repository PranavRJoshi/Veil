package registry

import (
	"testing"
)

func TestRegisterAndGet(t *testing.T) {
	Reset()
	defer Reset()

	info := ModuleInfo{
		Name:        "test",
		Description: "a test module",
		Flags: []FlagDef{
			{Name: "pid", Short: "p", Description: "filter by PID"},
		},
		Factory: func(flags map[string]string, sink interface{}) (interface{}, error) {
			return "fake-module", nil
		},
	}
	Register(info)

	got, ok := Get("test")
	if !ok {
		t.Fatal("Get returned false for registered module")
	}
	if got.Name != "test" {
		t.Errorf("Name = %q, want %q", got.Name, "test")
	}
	if got.Description != "a test module" {
		t.Errorf("Description mismatch")
	}
}

func TestGetMissing(t *testing.T) {
	Reset()
	defer Reset()

	_, ok := Get("nonexistent")
	if ok {
		t.Error("Get returned true for unregistered module")
	}
}

func TestDuplicatePanics(t *testing.T) {
	Reset()
	defer Reset()

	info := ModuleInfo{Name: "dup", Factory: func(map[string]string, interface{}) (interface{}, error) { return nil, nil }}
	Register(info)

	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic on duplicate registration")
		}
	}()
	Register(info)
}

func TestNamesSorted(t *testing.T) {
	Reset()
	defer Reset()

	for _, n := range []string{"network", "files", "syscall"} {
		Register(ModuleInfo{
			Name:    n,
			Factory: func(map[string]string, interface{}) (interface{}, error) { return nil, nil },
		})
	}
	names := Names()
	if len(names) != 3 {
		t.Fatalf("len = %d, want 3", len(names))
	}
	if names[0] != "files" || names[1] != "network" || names[2] != "syscall" {
		t.Errorf("names not sorted: %v", names)
	}
}

func TestAllFlags_Deduplicated(t *testing.T) {
	Reset()
	defer Reset()

	// Both modules declare --pid
	Register(ModuleInfo{
		Name: "a",
		Flags: []FlagDef{
			{Name: "pid", Short: "p"},
			{Name: "uid", Short: "u"},
		},
		Factory: func(map[string]string, interface{}) (interface{}, error) { return nil, nil },
	})
	Register(ModuleInfo{
		Name: "b",
		Flags: []FlagDef{
			{Name: "pid", Short: "p"},
			{Name: "port"},
		},
		Factory: func(map[string]string, interface{}) (interface{}, error) { return nil, nil },
	})

	flags := AllFlags()
	// Should have pid, port, uid; deduplicated and sorted
	if len(flags) != 3 {
		t.Fatalf("expected 3 unique flags, got %d: %+v", len(flags), flags)
	}
	if flags[0].Name != "pid" || flags[1].Name != "port" || flags[2].Name != "uid" {
		t.Errorf("unexpected order/content: %+v", flags)
	}
}
