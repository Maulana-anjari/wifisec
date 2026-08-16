package tui

import (
	"testing"

	"github.com/Maulana-anjari/wifisec/internal/model"
)

func TestProfileGlyphIsDistinctPerProfile(t *testing.T) {
	seen := map[string]model.Profile{}
	for _, p := range []model.Profile{model.ProfilePassive, model.ProfileMinimal, model.ProfileStandard, model.ProfileFull} {
		g := ProfileGlyph(p)
		if prev, ok := seen[g]; ok {
			t.Errorf("glyph %q used for both %s and %s", g, prev, p)
		}
		seen[g] = p
	}
}

func TestStatusGlyphIsDistinctPerStatus(t *testing.T) {
	seen := map[string]model.CheckStatus{}
	statuses := []model.CheckStatus{
		model.StatusNormal, model.StatusAnomalous, model.StatusInconclusive,
		model.StatusSkipped, model.StatusError,
	}
	for _, s := range statuses {
		g := StatusGlyph(s)
		if prev, ok := seen[g]; ok {
			t.Errorf("glyph %q used for both %s and %s", g, prev, s)
		}
		seen[g] = s
	}
}

func TestIsNarrowBreakpoint(t *testing.T) {
	if isNarrow(70) {
		t.Error("70 columns should not be narrow (breakpoint is exclusive below 70)")
	}
	if !isNarrow(69) {
		t.Error("69 columns should be narrow")
	}
	if isNarrow(0) {
		t.Error("width 0 (unknown) should not be treated as narrow")
	}
}
