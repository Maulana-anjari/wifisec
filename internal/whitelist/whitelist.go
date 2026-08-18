// Package whitelist implements the known-networks whitelist (spec
// §5.2 G7): the only mechanism by which a network is ever considered
// "known," gating spec G5's second full-profile confirmation.
package whitelist

import (
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Entry is one whitelisted network (spec G7: "berisi hash BSSID").
// Label is an optional human-readable note, never used for matching.
type Entry struct {
	BSSIDHash string `yaml:"bssid_hash"`
	Label     string `yaml:"label,omitempty"`
}

type List struct {
	Networks []Entry `yaml:"networks"`
}

// Path returns $XDG_CONFIG_HOME/wifisec/known_networks.yaml (spec
// G7), falling back to $HOME/.config per the XDG Base Directory
// spec's own documented default when XDG_CONFIG_HOME is unset.
func Path() (string, error) {
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, "wifisec", "known_networks.yaml"), nil
}

// Load reads the whitelist file. A missing file is not an error — it
// means an empty whitelist, consistent with spec P1/G1: no prior
// state is ever assumed present.
func Load() (*List, error) {
	path, err := Path()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &List{}, nil
	}
	if err != nil {
		return nil, err
	}
	var l List
	if err := yaml.Unmarshal(data, &l); err != nil {
		return nil, err
	}
	return &l, nil
}

// Contains reports whether bssidHash (spec §4.5 "sha256:<hex>"
// format) is in the whitelist.
func (l *List) Contains(bssidHash string) bool {
	for _, e := range l.Networks {
		if e.BSSIDHash == bssidHash {
			return true
		}
	}
	return false
}

// Add appends bssidHash to the whitelist if not already present. It
// does not write to disk — call Save separately.
func (l *List) Add(bssidHash, label string) {
	if l.Contains(bssidHash) {
		return
	}
	l.Networks = append(l.Networks, Entry{BSSIDHash: bssidHash, Label: label})
}

// Save writes the whitelist to Path(), creating parent directories as
// needed. File permissions are restrictive (0600) since this file
// indirectly identifies networks the user has used, even though it
// stores only hashes, not plaintext SSIDs/BSSIDs.
func (l *List) Save() error {
	path, err := Path()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := yaml.Marshal(l)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}
