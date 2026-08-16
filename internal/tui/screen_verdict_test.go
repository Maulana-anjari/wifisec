package tui

import (
	"strings"
	"testing"

	"github.com/Maulana-anjari/wifisec/internal/model"
)

func TestRenderVerdictScreenShowsHeadlineAndScore(t *testing.T) {
	r := model.Result{
		Verdict: model.Verdict{
			Safety:      model.SafetyOK,
			Score:       100,
			Headline:    "Jaringan ini aman.",
			TopFindings: []string{"finding.a"},
			BlindSpots:  []string{},
			UseCases:    map[string]string{"browsing_umum": "ok"},
		},
	}
	out := renderVerdictScreen(r, 100)
	if !strings.Contains(out, "Jaringan ini aman.") {
		t.Errorf("expected headline in output, got:\n%s", out)
	}
	if !strings.Contains(out, "100") {
		t.Errorf("expected score in output, got:\n%s", out)
	}
	if !strings.Contains(out, "finding.a") {
		t.Errorf("expected top finding in output, got:\n%s", out)
	}
}

func TestRenderVerdictScreenGivesBlindSpotsEqualWeight(t *testing.T) {
	r := model.Result{
		Verdict: model.Verdict{
			TopFindings: []string{"a", "b"},
			BlindSpots:  []string{"x"},
		},
	}
	out := renderVerdictScreen(r, 100)
	if !strings.Contains(out, "Temuan utama") || !strings.Contains(out, "Tidak diperiksa") {
		t.Errorf("expected both section headers present, got:\n%s", out)
	}
}
