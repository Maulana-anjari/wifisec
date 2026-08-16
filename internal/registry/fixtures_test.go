package registry

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Maulana-anjari/wifisec/internal/model"
)

// TestFixturesValidateAgainstModel checks that every checked-in fixture
// produces structurally valid model data per the rules in
// model.ValidateCheck / ValidateFinding / ValidateVerdict (spec §4.2-4.4).
// This is the harness that finding #1 of the whole-branch review found
// missing: without it, an invalid fixture (anomalous + high confidence +
// no performed control on a non-self-evident check) can sit in the repo
// undetected.
func TestFixturesValidateAgainstModel(t *testing.T) {
	r, err := Load()
	if err != nil {
		t.Fatal(err)
	}

	fixtures, err := filepath.Glob(filepath.Join("..", "..", "testdata", "fixtures", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(fixtures) == 0 {
		t.Fatal("no fixtures found under testdata/fixtures")
	}

	for _, path := range fixtures {
		name := filepath.Base(path)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var result model.Result
		if err := json.Unmarshal(data, &result); err != nil {
			t.Fatalf("%s: %v", name, err)
		}

		checkIDs := make(map[string]bool, len(result.Checks))
		for _, c := range result.Checks {
			checkIDs[c.ID] = true
			def, ok := r.ByID(c.ID)
			if !ok {
				t.Errorf("%s: check %s not found in registry", name, c.ID)
				continue
			}
			if err := model.ValidateCheck(c, def.SelfEvident); err != nil {
				t.Errorf("%s: check %s: %v", name, c.ID, err)
			}
		}

		for _, f := range result.Findings {
			if err := model.ValidateFinding(f, checkIDs); err != nil {
				t.Errorf("%s: finding %s: %v", name, f.ID, err)
			}
		}

		if err := model.ValidateVerdict(result.Checks, result.Verdict); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}
