package registry

import (
	_ "embed"
	"fmt"

	"gopkg.in/yaml.v3"

	"github.com/Maulana-anjari/wifisec/internal/model"
)

//go:embed checks.yaml
var checksYAML []byte

// CheckDefinition is the static, declarative metadata for one check
// (spec §4.6). Runtime results are model.Check, not this type.
type CheckDefinition struct {
	ID                    string        `yaml:"id"`
	Layer                 model.Layer   `yaml:"layer"`
	Title                 string        `yaml:"title"`
	Description           string        `yaml:"description"`
	ProfileRequired       model.Profile `yaml:"profile_required"`
	RequiresControlServer bool          `yaml:"requires_control_server"`
	RequiresPrivilege     bool          `yaml:"requires_privilege"`
	SelfEvident           bool          `yaml:"self_evident"`
	EstimatedPackets      int           `yaml:"estimated_packets"`
}

type Registry struct {
	Checks []CheckDefinition
}

type yamlFile struct {
	Checks []CheckDefinition `yaml:"checks"`
}

// Load parses the checks.yaml registry embedded into the binary at
// compile time (spec §6: "dimuat saat start"). Embedding avoids
// resolving checks.yaml relative to the process's working directory,
// which would break an installed binary run from outside its source
// tree.
func Load() (*Registry, error) {
	var f yamlFile
	if err := yaml.Unmarshal(checksYAML, &f); err != nil {
		return nil, fmt.Errorf("registry: parse checks.yaml: %w", err)
	}
	return &Registry{Checks: f.Checks}, nil
}

// Filter returns only the definitions runnable at the given profile
// (spec §3.2, §5.2): those the profile allows per model.Profile.Allows.
func (r *Registry) Filter(profile model.Profile) []CheckDefinition {
	var out []CheckDefinition
	for _, c := range r.Checks {
		if profile.Allows(c.ProfileRequired) {
			out = append(out, c)
		}
	}
	return out
}

// ByID looks up a single definition by its check ID.
func (r *Registry) ByID(id string) (CheckDefinition, bool) {
	for _, c := range r.Checks {
		if c.ID == id {
			return c, true
		}
	}
	return CheckDefinition{}, false
}
