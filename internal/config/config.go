// Package config loads a YAML file into a spec.Spec. It is a second editor
// of the same Spec the CLI produces: modules, filters, output shaping, and
// operational settings. Module and flag names are validated against the
// registry so this package holds no per-module knowledge of its own.
//
// A file is either single-profile (top-level modules/output/run) or holds a
// map of named profiles selected with --profile. Profiles are self-contained;
// they do not inherit top-level defaults.
package config

import (
	"bytes"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/PranavRJoshi/Veil/internal/cli"
	"github.com/PranavRJoshi/Veil/internal/registry"
	"github.com/PranavRJoshi/Veil/internal/spec"
	"github.com/PranavRJoshi/Veil/internal/suggest"
)

/*
	The on-disk schema. The single-profile fields inline at the top level so
	the common case stays flat; a multi-profile file instead fills profiles
	(and optionally names a default). The two forms are mutually exclusive.
*/
type file struct {
	profile  `yaml:",inline"`
	Profiles map[string]profile `yaml:"profiles"`
	Default  string             `yaml:"default"`
}

/*
	A profile is one complete trace. Each module carries its own flags, so
	unlike the CLI (one shared flag map) a config file can filter each module
	differently. Negatable flags use a '!' prefix for deny values, as on the
	command line.
*/
type profile struct {
	Modules []moduleEntry `yaml:"modules"`
	Output  outputEntry   `yaml:"output"`
	Run     runEntry      `yaml:"run"`
}

func (p profile) isEmpty() bool { return reflect.DeepEqual(p, profile{}) }

type moduleEntry struct {
	Name  string               `yaml:"name"`
	Flags map[string]flagValue `yaml:"flags"`
}

// flagValue keeps a flag's YAML shape concrete: a scalar or list of scalars,
// or a bool tracked apart so a false toggle can be dropped.
type flagValue struct {
	parts  []string
	isBool bool
	truthy bool
}

func (v *flagValue) UnmarshalYAML(n *yaml.Node) error {
	switch n.Kind {
	case yaml.ScalarNode:
		if n.Tag == "!!bool" {
			v.isBool = true
			v.truthy = n.Value == "true"
			return nil
		}
		v.parts = []string{n.Value}
	case yaml.SequenceNode:
		for _, c := range n.Content {
			if c.Kind != yaml.ScalarNode {
				return fmt.Errorf("line %d: list values must be scalars", c.Line)
			}
			v.parts = append(v.parts, c.Value)
		}
	default:
		return fmt.Errorf("line %d: flag value must be a scalar or list", n.Line)
	}
	return nil
}

func (v flagValue) String() string { return strings.Join(v.parts, ",") }

type outputEntry struct {
	Format  string   `yaml:"format"`
	Enrich  []string `yaml:"enrich"`
	Fields  []string `yaml:"fields"`
	Count   bool     `yaml:"count"`
	CountBy string   `yaml:"count_by"`
}

type runEntry struct {
	Control string `yaml:"control"`
	Pprof   string `yaml:"pprof"`
	Yes     bool   `yaml:"yes"`
}

// Load reads path and decodes the selected profile into a spec.Spec. profile
// is "" for a single-profile file or to take the file's default. Unknown keys
// and unknown module or flag names are rejected so a typo fails loudly.
func Load(path, profile string) (spec.Spec, error) {
	f, err := parseFile(path)
	if err != nil {
		return spec.Spec{}, err
	}
	p, err := f.selectProfile(profile)
	if err != nil {
		return spec.Spec{}, fmt.Errorf("%s: %w", path, err)
	}
	sp, err := p.toSpec()
	if err != nil {
		return spec.Spec{}, fmt.Errorf("%s: %w", path, err)
	}
	return sp, nil
}

// LoadAll decodes every profile in a file, keyed by name. A single-profile
// file yields one entry under "". It is what `config validate` uses to check
// all profiles at once.
func LoadAll(path string) (map[string]spec.Spec, error) {
	f, err := parseFile(path)
	if err != nil {
		return nil, err
	}
	all, err := f.all()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return all, nil
}

func parseFile(path string) (file, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return file{}, err
	}
	f, err := parse(data)
	if err != nil {
		return file{}, fmt.Errorf("%s: %w", path, err)
	}
	return f, nil
}

func parse(data []byte) (file, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)

	var f file
	if err := dec.Decode(&f); err != nil {
		return file{}, err
	}
	return f, nil
}

// selectProfile resolves the single trace to run, enforcing that a file uses
// exactly one form (top-level or profiles) and that --profile is applied only
// where it makes sense.
func (f file) selectProfile(name string) (profile, error) {
	hasProfiles := len(f.Profiles) > 0
	hasTop := !f.profile.isEmpty()

	switch {
	case hasProfiles && hasTop:
		return profile{}, fmt.Errorf("config mixes top-level modules with profiles")
	case !hasProfiles && !hasTop:
		return profile{}, fmt.Errorf("config defines no modules")
	case !hasProfiles:
		if name != "" {
			return profile{}, fmt.Errorf("config has no profiles; --profile %q is not applicable", name)
		}
		return f.profile, nil
	}

	if name == "" {
		name = f.Default
	}
	if name == "" {
		return profile{}, fmt.Errorf("config defines profiles [%s]; select one with --profile",
			strings.Join(f.profileNames(), ", "))
	}
	p, ok := f.Profiles[name]
	if !ok {
		if hint := suggest.Hint(name, f.profileNames(), 3); hint != "" {
			return profile{}, fmt.Errorf("unknown profile %q%s", name, hint)
		}
		return profile{}, fmt.Errorf("unknown profile %q; available: %s", name, strings.Join(f.profileNames(), ", "))
	}
	return p, nil
}

// all returns every profile's spec, validating the file's form and that a
// named default exists.
func (f file) all() (map[string]spec.Spec, error) {
	hasProfiles := len(f.Profiles) > 0
	hasTop := !f.profile.isEmpty()

	switch {
	case hasProfiles && hasTop:
		return nil, fmt.Errorf("config mixes top-level modules with profiles")
	case !hasProfiles && !hasTop:
		return nil, fmt.Errorf("config defines no modules")
	case !hasProfiles:
		sp, err := f.profile.toSpec()
		if err != nil {
			return nil, err
		}
		return map[string]spec.Spec{"": sp}, nil
	}

	if f.Default != "" {
		if _, ok := f.Profiles[f.Default]; !ok {
			return nil, fmt.Errorf("default %q is not a defined profile", f.Default)
		}
	}
	out := make(map[string]spec.Spec, len(f.Profiles))
	for name, p := range f.Profiles {
		sp, err := p.toSpec()
		if err != nil {
			return nil, fmt.Errorf("profile %q: %w", name, err)
		}
		out[name] = sp
	}
	return out, nil
}

func (f file) profileNames() []string {
	names := make([]string, 0, len(f.Profiles))
	for name := range f.Profiles {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func (p profile) toSpec() (spec.Spec, error) {
	if len(p.Modules) == 0 {
		return spec.Spec{}, fmt.Errorf("config defines no modules")
	}

	var mods []spec.Module
	for _, m := range p.Modules {
		flags, err := lowerFlags(m)
		if err != nil {
			return spec.Spec{}, err
		}
		mods = append(mods, spec.Module{Name: m.Name, Flags: flags})
	}

	out := spec.Output{
		Format:   p.Output.Format,
		Enrich:   strings.Join(p.Output.Enrich, ","),
		Fields:   p.Output.Fields,
		Count:    p.Output.Count || p.Output.CountBy != "",
		CountKey: p.Output.CountBy,
	}

	return spec.Spec{
		Modules: mods,
		Output:  out,
		Run: spec.Run{
			ControlPath: p.Run.Control,
			PprofPath:   p.Run.Pprof,
			AssumeYes:   p.Run.Yes,
		},
	}, nil
}

/*
	lowerFlags validates a module's flags against the registry and reduces
	them to the key/value shape factories accept. Negatable flags split on
	'!' into <name> and <name>_deny; bool flags are emitted only when true.
*/
func lowerFlags(m moduleEntry) (map[string]string, error) {
	info, ok := registry.Get(m.Name)
	if !ok {
		return nil, fmt.Errorf("unknown module %q%s", m.Name, suggest.Hint(m.Name, registry.Names(), 5))
	}

	defs := make(map[string]registry.FlagDef, len(info.Flags))
	for _, d := range info.Flags {
		defs[d.Name] = d
	}

	names := make([]string, 0, len(defs))
	for k := range defs {
		names = append(names, k)
	}

	out := make(map[string]string)
	for name, val := range m.Flags {
		def, ok := defs[name]
		if !ok {
			return nil, fmt.Errorf("module %q: unknown flag %q%s", m.Name, name, suggest.Hint(name, names, 5))
		}
		switch {
		case val.isBool:
			if val.truthy {
				out[name] = "true"
			}
		case val.String() == "":
			continue
		case def.Negatable:
			allow, deny := cli.SplitAllowDeny(val.String())
			if allow != "" {
				out[name] = allow
			}
			if deny != "" {
				out[name+"_deny"] = deny
			}
		default:
			out[name] = val.String()
		}
	}
	return out, nil
}
