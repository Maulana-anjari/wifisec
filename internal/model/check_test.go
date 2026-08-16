package model

import "testing"

func TestValidateCheckRejectsSkippedWithPackets(t *testing.T) {
	c := Check{ID: "x", Status: StatusSkipped, PacketsSent: 1}
	if err := ValidateCheck(c, false); err == nil {
		t.Error("expected error for skipped check with packets_sent > 0")
	}
}

func TestValidateCheckRejectsHighConfidenceAnomalousWithoutControl(t *testing.T) {
	c := Check{
		ID:         "x",
		Status:     StatusAnomalous,
		Confidence: ConfidenceHigh,
		Control:    Control{Performed: false},
	}
	if err := ValidateCheck(c, false); err == nil {
		t.Error("expected error for non-self-evident anomalous+high-confidence check without a control")
	}
	if err := ValidateCheck(c, true); err != nil {
		t.Errorf("self-evident check should be allowed: %v", err)
	}
}

func TestValidateCheckRejectsJudgmentalObservedKeys(t *testing.T) {
	for _, key := range []string{"blocked", "is_dangerous", "UNSAFE_score"} {
		c := Check{
			ID:       "x",
			Status:   StatusNormal,
			Observed: map[string]any{key: true},
		}
		if err := ValidateCheck(c, false); err == nil {
			t.Errorf("expected error for judgmental observed key %q", key)
		}
	}
}

func TestValidateCheckAcceptsValidCheck(t *testing.T) {
	c := Check{
		ID:         "x",
		Status:     StatusAnomalous,
		Confidence: ConfidenceMedium,
		Control:    Control{Performed: false},
		Observed:   map[string]any{"issuer": "Let's Encrypt R3"},
	}
	if err := ValidateCheck(c, false); err != nil {
		t.Errorf("expected valid check to pass, got: %v", err)
	}
}
