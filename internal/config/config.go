// Package config loads a YAML file into a spec.Spec. It is a second editor
// of the same Spec the CLI produces: modules, filters, output shaping, and
// operational settings. Module and flag names are validated against the
// registry so this package holds no per-module knowledge of its own.
package config

import (
	"bytes"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/PranavRJoshi/Veil/internal/cli"
	"github.com/PranavRJoshi/Veil/internal/registry"
	"github.com/PranavRJoshi/Veil/internal/spec"
)

/*
	The on-disk schema. Each module carries its own flags, so unlike the CLI
	(one shared flag map) a config file can filter each module differently.
	Negatable flags use a '!' prefix for deny values, as on the command line.
*/
type file struct {
	Modules []moduleEntry `yaml:"modules"`
	Output  outputEntry   `yaml:"output"`
	Run     runEntry      `yaml:"run"`
}

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

// Load reads path and decodes it into a spec.Spec. Unknown keys and unknown
// module or flag names are rejected so a typo fails loudly rather than being
// silently ignored.
func Load(path string) (spec.Spec, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return spec.Spec{}, err
	}
	sp, err := decode(data)
	if err != nil {
		return spec.Spec{}, fmt.Errorf("%s: %w", path, err)
	}
	return sp, nil
}

func decode(data []byte) (spec.Spec, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)

	var f file
	if err := dec.Decode(&f); err != nil {
		return spec.Spec{}, err
	}
	return f.toSpec()
}

func (f file) toSpec() (spec.Spec, error) {
	if len(f.Modules) == 0 {
		return spec.Spec{}, fmt.Errorf("config defines no modules")
	}

	var mods []spec.Module
	for _, m := range f.Modules {
		flags, err := lowerFlags(m)
		if err != nil {
			return spec.Spec{}, err
		}
		mods = append(mods, spec.Module{Name: m.Name, Flags: flags})
	}

	out := spec.Output{
		Format:   f.Output.Format,
		Enrich:   strings.Join(f.Output.Enrich, ","),
		Fields:   f.Output.Fields,
		Count:    f.Output.Count || f.Output.CountBy != "",
		CountKey: f.Output.CountBy,
	}

	return spec.Spec{
		Modules: mods,
		Output:  out,
		Run: spec.Run{
			ControlPath: f.Run.Control,
			PprofPath:   f.Run.Pprof,
			AssumeYes:   f.Run.Yes,
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
		return nil, fmt.Errorf("unknown module %q", m.Name)
	}

	defs := make(map[string]registry.FlagDef, len(info.Flags))
	for _, d := range info.Flags {
		defs[d.Name] = d
	}

	out := make(map[string]string)
	for name, val := range m.Flags {
		def, ok := defs[name]
		if !ok {
			return nil, fmt.Errorf("module %q: unknown flag %q", m.Name, name)
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
