package registry

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/Maulana-anjari/wifisec/internal/model"
)

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

// Load reads and parses a checks.yaml registry file (spec §6).
func Load(path string) (*Registry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("registry: read %s: %w", path, err)
	}
	var f yamlFile
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("registry: parse %s: %w", path, err)
	}
	return &Registry{Checks: f.Checks}, nil
}

// Filter returns only the definitions runnable at the given profile
// (spec §3.2, §5.2): those whose ProfileRequired.Level() <= profile.Level().
func (r *Registry) Filter(profile model.Profile) []CheckDefinition {
	var out []CheckDefinition
	for _, c := range r.Checks {
		if c.ProfileRequired.Level() <= profile.Level() {
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
