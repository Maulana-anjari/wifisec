package tui

import (
	"strings"
	"testing"

	"github.com/Maulana-anjari/wifisec/internal/model"
)

func TestProfileDialogShowsEstimateAndWarnsOnFull(t *testing.T) {
	d := ProfileDialog{Target: model.ProfileFull, KnownNetwork: false}
	out := d.View()
	if !strings.Contains(out, "PERINGATAN") {
		t.Errorf("expected a warning for profile full, got:\n%s", out)
	}
	if !strings.Contains(out, "full") {
		t.Errorf("expected target profile named in dialog, got:\n%s", out)
	}
}

func TestProfileDialogConfirmedRequiresExactMatch(t *testing.T) {
	d := ProfileDialog{Target: model.ProfileMinimal, Typed: "minima"}
	if d.Confirmed() {
		t.Error("partial match should not confirm (spec G2: exact match required)")
	}
	d.Typed = "minimal"
	if !d.Confirmed() {
		t.Error("exact match should confirm")
	}
}
