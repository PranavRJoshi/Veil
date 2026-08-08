// Package completion provides the candidate engine behind veil's shell
// completion. Given the words typed so far (the last being the word under the
// cursor, possibly empty), Complete returns the valid next tokens, keyed on
// the word before the cursor. Module flags come from the registry, so
// completion stays in step with what the parser accepts.
package completion

import (
	"sort"
	"strings"

	"github.com/PranavRJoshi/Veil/internal/config"
	"github.com/PranavRJoshi/Veil/internal/registry"
)

// subcommands are offered only for the first word after the program name.
var subcommands = []string{"completion", "config"}

// globalValueFlags and globalBoolFlags list veil's non-module flags. Keep in
// sync with cli.Parse; module flags are read from the registry.
var (
	globalValueFlags = []string{
		"--module", "--config", "--profile", "--output", "--enrich",
		"--fields", "--count-by", "--control", "--pprof", "--color",
	}
	globalBoolFlags = []string{
		"--list-modules", "--count", "--yes", "--help", "-h",
	}
)

// Complete returns the sorted, de-duplicated candidates for the last word in
// words, filtered to those that share its prefix.
func Complete(words []string) []string {
	var cur, prev string
	if n := len(words); n > 0 {
		cur = words[n-1]
		if n > 1 {
			prev = words[n-2]
		}
	}
	return filterPrefix(candidates(words, prev, cur), cur)
}

func candidates(words []string, prev, cur string) []string {
	switch prev {
	case "--module":
		return moduleCandidates(cur)
	case "--output":
		return []string{"json", "text"}
	case "--color":
		return []string{"always", "auto", "never"}
	case "--enrich":
		return []string{"all", "proc", "time", "user"}
	case "--profile":
		return profileCandidates(words)
	}
	if isValueFlag(prev) {
		return nil // a value is expected, but its domain isn't ours to complete
	}
	return nameCandidates(words, len(words) <= 1)
}

// moduleCandidates completes the --module value, including the comma-separated
// multi-module form: it completes the segment after the last comma, keeps the
// ones already entered, and does not re-offer them.
func moduleCandidates(cur string) []string {
	base := ""
	if i := strings.LastIndex(cur, ","); i >= 0 {
		base = cur[:i+1]
	}
	chosen := make(map[string]bool)
	for _, m := range strings.Split(strings.TrimSuffix(base, ","), ",") {
		if m != "" {
			chosen[m] = true
		}
	}
	var out []string
	for _, name := range registry.Names() {
		if !chosen[name] {
			out = append(out, base+name)
		}
	}
	return out
}

// nameCandidates returns flag names, plus subcommands when completing the first
// word after the program name. Flags are narrowed to the selected modules; with
// no resolvable module yet, all module flags are offered.
func nameCandidates(words []string, firstWord bool) []string {
	var out []string
	if firstWord {
		out = append(out, subcommands...)
	}
	// --module takes a single value (only the last wins), so once it is set,
	// re-offering it would wrongly suggest repeating it enables multi-module.
	moduleSet := hasWord(prior(words), "--module")
	for _, f := range globalValueFlags {
		if f == "--module" && moduleSet {
			continue
		}
		out = append(out, f)
	}
	out = append(out, globalBoolFlags...)
	for _, f := range moduleFlags(selectedModules(words)) {
		out = append(out, "--"+f.Name)
		if f.Short != "" {
			out = append(out, "-"+f.Short)
		}
	}
	return out
}

// prior returns words without the final element, the word being completed, so
// a presence check ignores a flag the user is still in the middle of typing.
func prior(words []string) []string {
	if len(words) == 0 {
		return words
	}
	return words[:len(words)-1]
}

func hasWord(words []string, w string) bool {
	for _, x := range words {
		if x == w {
			return true
		}
	}
	return false
}

// moduleFlags returns the flags declared by the given modules (their union,
// de-duplication left to the caller's prefix filter). When none resolve -- no
// --module yet, or a still-incomplete name -- it falls back to every flag.
func moduleFlags(mods []string) []registry.FlagDef {
	var flags []registry.FlagDef
	for _, m := range mods {
		if info, ok := registry.Get(m); ok {
			flags = append(flags, info.Flags...)
		}
	}
	if len(flags) == 0 {
		return registry.AllFlags()
	}
	return flags
}

// selectedModules parses the comma-separated value of an earlier --module.
func selectedModules(words []string) []string {
	var mods []string
	for _, m := range strings.Split(valueAfter(words, "--module"), ",") {
		if m = strings.TrimSpace(m); m != "" {
			mods = append(mods, m)
		}
	}
	return mods
}

// isValueFlag reports whether name is a flag that takes a value, so the token
// after it is a value rather than a fresh flag.
func isValueFlag(name string) bool {
	for _, f := range globalValueFlags {
		if f == name {
			return true
		}
	}
	for _, f := range registry.AllFlags() {
		if f.HasValue && (name == "--"+f.Name || (f.Short != "" && name == "-"+f.Short)) {
			return true
		}
	}
	return false
}

// profileCandidates lists the named profiles in the file given by an earlier
// --config, the one candidate set that depends on a token before the previous
// one. A single-profile file (its key is "") contributes no names.
func profileCandidates(words []string) []string {
	path := valueAfter(words, "--config")
	if path == "" {
		return nil
	}
	all, err := config.LoadAll(path)
	if err != nil {
		return nil
	}
	var names []string
	for name := range all {
		if name != "" {
			names = append(names, name)
		}
	}
	return names
}

func valueAfter(words []string, flag string) string {
	for i := 0; i+1 < len(words); i++ {
		if words[i] == flag {
			return words[i+1]
		}
	}
	return ""
}

func filterPrefix(cands []string, cur string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, c := range cands {
		if seen[c] || !strings.HasPrefix(c, cur) {
			continue
		}
		seen[c] = true
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}
