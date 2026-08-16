package tui

import (
	"strings"
	"testing"

	"github.com/Maulana-anjari/wifisec/internal/model"
)

func TestRenderFindingsScreenListsAllFindings(t *testing.T) {
	r := model.Result{
		Findings: []model.Finding{
			{ID: "a", Title: "Finding A", Severity: model.SeverityCritical},
			{ID: "b", Title: "Finding B", Severity: model.SeverityInfo, FalsePositiveHints: []string{"could be a false positive"}},
		},
	}
	out := renderFindingsScreen(r, 0, 100)
	if !strings.Contains(out, "Finding A") || !strings.Contains(out, "Finding B") {
		t.Errorf("expected both findings in output, got:\n%s", out)
	}
	if !strings.Contains(out, "could be a false positive") {
		t.Errorf("expected false_positive_hints shown directly (spec §9.3), got:\n%s", out)
	}
}

func TestRenderFindingsScreenHandlesEmpty(t *testing.T) {
	out := renderFindingsScreen(model.Result{}, 0, 100)
	if !strings.Contains(out, "0") {
		t.Errorf("expected empty-count indicator, got:\n%s", out)
	}
}
