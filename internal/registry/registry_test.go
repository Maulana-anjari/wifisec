package registry

import (
	"testing"

	"github.com/Maulana-anjari/wifisec/internal/model"
)

func TestLoadParsesChecksYAML(t *testing.T) {
	r, err := Load("checks.yaml")
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

func TestFilterRespectsProfileLevel(t *testing.T) {
	r, err := Load("checks.yaml")
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
