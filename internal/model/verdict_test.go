package model

import "testing"

func TestValidateVerdictRejectsSkippedWithoutBlindSpots(t *testing.T) {
	checks := []Check{{ID: "a", Status: StatusSkipped}}
	v := Verdict{Safety: SafetyUnknown, BlindSpots: nil}
	if err := ValidateVerdict(checks, v); err == nil {
		t.Error("expected error: skipped check present but blind_spots is empty (P4)")
	}
}

func TestValidateVerdictAcceptsSkippedWithBlindSpots(t *testing.T) {
	checks := []Check{{ID: "a", Status: StatusSkipped}}
	v := Verdict{Safety: SafetyUnknown, BlindSpots: []string{"DNS not checked"}}
	if err := ValidateVerdict(checks, v); err != nil {
		t.Errorf("expected valid verdict to pass, got: %v", err)
	}
}

func TestValidateVerdictAcceptsNoSkippedNoBlindSpots(t *testing.T) {
	checks := []Check{{ID: "a", Status: StatusNormal}}
	v := Verdict{Safety: SafetyOK, BlindSpots: nil}
	if err := ValidateVerdict(checks, v); err != nil {
		t.Errorf("expected valid verdict to pass, got: %v", err)
	}
}
