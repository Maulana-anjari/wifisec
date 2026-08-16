package tui

import (
	"strings"
	"testing"

	"github.com/Maulana-anjari/wifisec/internal/model"
)

func TestRenderDetailScreenShowsSelectedCheck(t *testing.T) {
	r := model.Result{
		Checks: []model.Check{
			{ID: "a", Title: "Check A", Status: model.StatusNormal},
			{ID: "b", Title: "Check B", Status: model.StatusError, Error: "boom"},
		},
	}
	out := renderDetailScreen(r, 1, 100)
	if !strings.Contains(out, "Check B") {
		t.Errorf("expected selected check title, got:\n%s", out)
	}
	if !strings.Contains(out, "boom") {
		t.Errorf("expected error message shown, got:\n%s", out)
	}
	if strings.Contains(out, "Check A") {
		t.Errorf("did not expect unselected check title, got:\n%s", out)
	}
}

func TestRenderDetailScreenHandlesEmpty(t *testing.T) {
	out := renderDetailScreen(model.Result{}, 0, 100)
	if !strings.Contains(out, "0") {
		t.Errorf("expected empty-count indicator, got:\n%s", out)
	}
}
