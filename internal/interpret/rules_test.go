package interpret

import (
	"testing"

	"github.com/Maulana-anjari/wifisec/internal/model"
)

func TestApplyProducesWeakEncryptionFinding(t *testing.T) {
	checks := []model.Check{
		{ID: "wifi.security", Status: model.StatusAnomalous, Confidence: model.ConfidenceHigh, Observed: map[string]any{"security": "open"}},
	}
	findings, verdict := Apply(checks)
	if len(findings) != 1 || findings[0].ID != "weak_encryption" {
		t.Fatalf("expected weak_encryption finding, got %+v", findings)
	}
	if findings[0].Severity != model.SeverityCritical {
		t.Errorf("severity = %s, want critical", findings[0].Severity)
	}
	if verdict.Safety != model.SafetyAvoid {
		t.Errorf("safety = %s, want avoid", verdict.Safety)
	}
	if verdict.Score != 60 {
		t.Errorf("score = %d, want 60 (100 - 40 for one critical)", verdict.Score)
	}
}

func TestApplyCleanChecksProduceOKVerdict(t *testing.T) {
	checks := []model.Check{
		{ID: "wifi.security", Status: model.StatusNormal, Confidence: model.ConfidenceHigh, Observed: map[string]any{"security": "WPA3"}},
		{ID: "wifi.pmf", Status: model.StatusNormal, Confidence: model.ConfidenceHigh, Observed: map[string]any{"pmf": "required"}},
	}
	findings, verdict := Apply(checks)
	if len(findings) != 0 {
		t.Errorf("expected no findings, got %+v", findings)
	}
	if verdict.Safety != model.SafetyOK || verdict.Score != 100 {
		t.Errorf("verdict = %+v, want ok/100", verdict)
	}
}

func TestApplyFillsBlindSpotsForSkippedChecks(t *testing.T) {
	checks := []model.Check{
		{ID: "dns.resolve_basic", Status: model.StatusSkipped, Title: "Resolusi DNS dasar", Control: model.Control{Reason: "profile_does_not_allow"}},
	}
	_, verdict := Apply(checks)
	if err := model.ValidateVerdict(checks, verdict); err != nil {
		t.Errorf("ValidateVerdict failed on Apply's own output: %v", err)
	}
	if len(verdict.BlindSpots) == 0 {
		t.Error("expected non-empty blind_spots for a skipped check")
	}
}

func TestApplyFindingsPassValidation(t *testing.T) {
	checks := []model.Check{
		{ID: "local.trust_store", Status: model.StatusAnomalous, Confidence: model.ConfidenceHigh, Observed: map[string]any{"non_public_ca_found": true}},
	}
	findings, _ := Apply(checks)
	ids := map[string]bool{}
	for _, c := range checks {
		ids[c.ID] = true
	}
	for _, f := range findings {
		if err := model.ValidateFinding(f, ids); err != nil {
			t.Errorf("ValidateFinding(%s) failed: %v", f.ID, err)
		}
	}
}
