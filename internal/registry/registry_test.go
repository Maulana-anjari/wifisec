package registry

import (
	"testing"

	"github.com/Maulana-anjari/wifisec/internal/model"
)

func TestLoadParsesChecksYAML(t *testing.T) {
	r, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Checks) == 0 {
		t.Fatal("expected at least one check definition")
	}
	def, ok := r.ByID("local.trust_store")
	if !ok {
		t.Fatal("expected local.trust_store to be defined")
	}
	if !def.SelfEvident {
		t.Error("local.trust_store must be self_evident: true (spec §6.1)")
	}
	if def.ProfileRequired != model.ProfilePassive {
		t.Errorf("local.trust_store profile_required = %s, want passive", def.ProfileRequired)
	}
}

// TestRegistryCardinality asserts the registry has exactly the checks
// spec §6 defines: 13 (§6.1) + 2 (§6.2) + 9 (§6.3) + 8 (§6.4) = 32, and
// that no ID is duplicated.
func TestRegistryCardinality(t *testing.T) {
	r, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	const want = 13 + 2 + 9 + 8
	if len(r.Checks) != want {
		t.Errorf("len(r.Checks) = %d, want %d (spec §6.1-6.4)", len(r.Checks), want)
	}

	seen := make(map[string]bool, len(r.Checks))
	for _, c := range r.Checks {
		if seen[c.ID] {
			t.Errorf("duplicate check id %q", c.ID)
		}
		seen[c.ID] = true
	}
}

func TestFilterRespectsProfileLevel(t *testing.T) {
	r, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, def := range r.Filter(model.ProfileMinimal) {
		if def.ProfileRequired.Level() > model.ProfileMinimal.Level() {
			t.Errorf("Filter(minimal) returned %s which requires %s", def.ID, def.ProfileRequired)
		}
	}
	passiveOnly := r.Filter(model.ProfilePassive)
	full := r.Filter(model.ProfileFull)
	if len(passiveOnly) >= len(full) {
		t.Errorf("Filter(full) should return more checks than Filter(passive): got %d vs %d", len(full), len(passiveOnly))
	}
}
