package completion

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	// Register the real modules so registry-derived candidates are populated.
	_ "github.com/PranavRJoshi/Veil/modules/files"
	_ "github.com/PranavRJoshi/Veil/modules/memory"
	_ "github.com/PranavRJoshi/Veil/modules/network"
	_ "github.com/PranavRJoshi/Veil/modules/scheduler"
	_ "github.com/PranavRJoshi/Veil/modules/syscall"
	_ "github.com/PranavRJoshi/Veil/modules/uprobe"
)

func contains(s []string, want string) bool {
	for _, v := range s {
		if v == want {
			return true
		}
	}
	return false
}

func TestModuleValueDomain(t *testing.T) {
	got := Complete([]string{"--module", ""})
	for _, name := range []string{"scheduler", "syscall", "files", "network", "memory", "uprobe"} {
		if !contains(got, name) {
			t.Errorf("--module completion missing %q; got %v", name, got)
		}
	}
	// The value domain is module names only -- no flags leak in.
	if contains(got, "--pid") {
		t.Errorf("--module completion leaked a flag: %v", got)
	}
}

func TestPrefixNarrows(t *testing.T) {
	got := Complete([]string{"--module", "sched"})
	want := []string{"scheduler"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Complete(--module sched) = %v, want %v", got, want)
	}
}

func TestEnumDomains(t *testing.T) {
	tests := []struct {
		prev string
		want []string
	}{
		{"--color", []string{"always", "auto", "never"}},
		{"--output", []string{"json", "text"}},
		{"--enrich", []string{"all", "proc", "time", "user"}},
	}
	for _, tt := range tests {
		if got := Complete([]string{tt.prev, ""}); !reflect.DeepEqual(got, tt.want) {
			t.Errorf("Complete(%s \"\") = %v, want %v", tt.prev, got, tt.want)
		}
	}
}

func TestSubcommandsOnlyFirstWord(t *testing.T) {
	first := Complete([]string{""})
	if !contains(first, "config") || !contains(first, "completion") {
		t.Errorf("first-word completion missing subcommands: %v", first)
	}
	// After a token, we are no longer at the first word: no subcommands.
	later := Complete([]string{"--yes", ""})
	if contains(later, "config") || contains(later, "completion") {
		t.Errorf("subcommands offered mid-command: %v", later)
	}
	if !contains(later, "--module") {
		t.Errorf("flags missing mid-command: %v", later)
	}
}

func TestFlagsNarrowToSelectedModule(t *testing.T) {
	got := Complete([]string{"--module", "memory", "--"})
	// memory's own flag and the shared/global ones are offered...
	for _, want := range []string{"--fault", "--pid", "--uid", "--output", "--color"} {
		if !contains(got, want) {
			t.Errorf("memory completion missing %q; got %v", want, got)
		}
	}
	// ...but flags belonging only to other modules are not.
	for _, unwanted := range []string{"--syscall", "--file", "--port", "--cpu", "--uprobe", "--latency"} {
		if contains(got, unwanted) {
			t.Errorf("memory completion leaked foreign flag %q; got %v", unwanted, got)
		}
	}
}

func TestModuleNotReofferedOnceSet(t *testing.T) {
	// After --module has a value, it must not be offered again -- repeating it
	// is not how multi-module works.
	if got := Complete([]string{"--module", "memory", "--"}); contains(got, "--module") {
		t.Errorf("--module re-offered after it was set: %v", got)
	}
	// But it is still offered while the flag name itself is being typed.
	if got := Complete([]string{"--mod"}); !contains(got, "--module") {
		t.Errorf("--module not offered before use: %v", got)
	}
}

func TestFlagsUnionMultiModule(t *testing.T) {
	got := Complete([]string{"--module", "memory,files", "--"})
	// The union of both modules' own flags is offered.
	for _, want := range []string{"--fault", "--op", "--file"} {
		if !contains(got, want) {
			t.Errorf("memory,files completion missing %q; got %v", want, got)
		}
	}
	// Flags from neither module are not.
	for _, unwanted := range []string{"--syscall", "--port", "--cpu", "--uprobe"} {
		if contains(got, unwanted) {
			t.Errorf("memory,files completion leaked %q; got %v", unwanted, got)
		}
	}
}

func TestFlagsAllWhenNoModule(t *testing.T) {
	// With no --module resolved, stay permissive: offer flags across modules.
	got := Complete([]string{"--"})
	for _, want := range []string{"--fault", "--syscall", "--port"} {
		if !contains(got, want) {
			t.Errorf("no-module completion missing %q; got %v", want, got)
		}
	}
}

func TestModuleValueCommaCompletes(t *testing.T) {
	// After a comma, complete the next module and keep the entered prefix,
	// without re-offering the one already chosen.
	got := Complete([]string{"--module", "syscall,"})
	if !contains(got, "syscall,files") || !contains(got, "syscall,memory") {
		t.Errorf("comma completion missing entries: %v", got)
	}
	if contains(got, "syscall,syscall") {
		t.Errorf("comma completion re-offered the chosen module: %v", got)
	}
	// A partial second segment narrows by prefix.
	if got := Complete([]string{"--module", "files,ne"}); !reflect.DeepEqual(got, []string{"files,network"}) {
		t.Errorf("Complete(--module files,ne) = %v, want [files,network]", got)
	}
}

func TestSubcommandGrammar(t *testing.T) {
	tests := []struct {
		name  string
		words []string
		want  []string
	}{
		{"config offers validate", []string{"config", ""}, []string{"validate"}},
		{"config validate prefix", []string{"config", "va"}, []string{"validate"}},
		{"config validate arg is a path", []string{"config", "validate", ""}, nil},
		{"config validate second path", []string{"config", "validate", "a.yaml", ""}, nil},
		{"completion offers shells", []string{"completion", ""}, []string{"bash", "zsh"}},
		{"completion shell prefix", []string{"completion", "z"}, []string{"zsh"}},
		{"completion arg is done", []string{"completion", "bash", ""}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Complete(tt.words); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Complete(%v) = %v, want %v", tt.words, got, tt.want)
			}
		})
	}
}

func TestValueFlagFallsBackToPath(t *testing.T) {
	// A value flag whose domain is a file path returns nothing, so the shell
	// wrapper can complete the path itself.
	for _, prev := range []string{"--config", "--pprof", "--control"} {
		if got := Complete([]string{prev, ""}); got != nil {
			t.Errorf("Complete(%s \"\") = %v, want nil", prev, got)
		}
	}
}

func TestValueFlagSuppressesNames(t *testing.T) {
	// --pprof takes a path we don't complete; offering flag names there would
	// be wrong (the shell should fall back to file completion instead).
	if got := Complete([]string{"--pprof", ""}); got != nil {
		t.Errorf("Complete(--pprof \"\") = %v, want nil", got)
	}
}

func TestNoDuplicateSharedFlags(t *testing.T) {
	// pid/uid/name are declared by every module; they must appear once.
	got := Complete([]string{""})
	seen := map[string]int{}
	for _, c := range got {
		seen[c]++
	}
	for _, f := range []string{"--pid", "--uid"} {
		if seen[f] > 1 {
			t.Errorf("%s appears %d times, want 1: %v", f, seen[f], got)
		}
	}
}

func TestProfileFromConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "veil.yaml")
	yaml := `default: overview
profiles:
  overview:
    modules:
      - name: syscall
  triage:
    modules:
      - name: files
`
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	got := Complete([]string{"--config", path, "--profile", ""})
	want := []string{"overview", "triage"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("--profile completion = %v, want %v", got, want)
	}
}

func TestProfileWithoutConfigIsEmpty(t *testing.T) {
	if got := Complete([]string{"--profile", ""}); got != nil {
		t.Errorf("--profile without --config = %v, want nil", got)
	}
}
