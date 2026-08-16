package model

import "testing"

func TestValidateFindingRequiresBasedOn(t *testing.T) {
	f := Finding{ID: "x", BasedOn: nil}
	if err := ValidateFinding(f, map[string]bool{"check.a": true}); err == nil {
		t.Error("expected error for finding with empty based_on")
	}
}

func TestValidateFindingRequiresKnownCheckIDs(t *testing.T) {
	f := Finding{ID: "x", BasedOn: []string{"check.unknown"}}
	if err := ValidateFinding(f, map[string]bool{"check.a": true}); err == nil {
		t.Error("expected error for finding based_on an ID not present in results")
	}
}

func TestValidateFindingAcceptsValid(t *testing.T) {
	f := Finding{ID: "x", BasedOn: []string{"check.a"}}
	if err := ValidateFinding(f, map[string]bool{"check.a": true}); err != nil {
		t.Errorf("expected valid finding to pass, got: %v", err)
	}
}
