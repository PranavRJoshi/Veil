package main

import (
	"path/filepath"
	"testing"

	"github.com/PranavRJoshi/Veil/internal/config"
)

// Every shipped example must load against the real registry, across all of its
// profiles. This fails the moment an example references a module or flag that
// has been renamed or removed, so the docs cannot silently drift from the code.
// The blank module imports in main.go populate the registry that config
// validates against.
func TestExampleConfigsLoad(t *testing.T) {
	files, err := filepath.Glob("../../examples/*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no example configs found")
	}

	for _, f := range files {
		f := f
		t.Run(filepath.Base(f), func(t *testing.T) {
			all, err := config.LoadAll(f)
			if err != nil {
				t.Fatalf("LoadAll: %v", err)
			}
			for name, sp := range all {
				if len(sp.Modules) == 0 {
					t.Errorf("profile %q produced no modules", name)
				}
			}
		})
	}
}
