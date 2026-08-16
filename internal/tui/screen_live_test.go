package tui

import (
	"strings"
	"testing"

	"github.com/Maulana-anjari/wifisec/internal/model"
)

func TestRenderLiveScreenListsAllChecksWithGlyphs(t *testing.T) {
	r := model.Result{
		Checks: []model.Check{
			{ID: "a", Title: "Check A", Status: model.StatusNormal},
			{ID: "b", Title: "Check B", Status: model.StatusSkipped},
		},
	}
	out := renderLiveScreen(r, 100)
	if !strings.Contains(out, "Check A") || !strings.Contains(out, "Check B") {
		t.Errorf("expected both checks listed, got:\n%s", out)
	}
	if !strings.Contains(out, StatusGlyph(model.StatusSkipped)) {
		t.Errorf("expected skipped glyph present, got:\n%s", out)
	}
}
