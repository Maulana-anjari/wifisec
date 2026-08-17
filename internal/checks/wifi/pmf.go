package wifi

import (
	"context"
	"time"

	"github.com/Maulana-anjari/wifisec/internal/checks"
	"github.com/Maulana-anjari/wifisec/internal/model"
	"github.com/Maulana-anjari/wifisec/internal/registry"
)

type PMFCheck struct{ def registry.CheckDefinition }

func NewPMFCheck(def registry.CheckDefinition) checks.Checker { return PMFCheck{def} }

func (c PMFCheck) Definition() registry.CheckDefinition { return c.def }

func (c PMFCheck) Run(ctx context.Context, cc checks.CheckContext) model.Check {
	start := time.Now()
	info, err := cc.Platform.WiFiInfo()
	if err != nil {
		return checks.NewErrorCheck(c.def, err, start)
	}
	base := model.Check{
		ID: c.def.ID, Layer: c.def.Layer, Title: c.def.Title, ProfileRequired: c.def.ProfileRequired,
		Control: model.Control{Performed: false}, DurationMS: time.Since(start).Milliseconds(),
	}
	if !info.Available {
		base.Status = model.StatusInconclusive
		base.Confidence = model.ConfidenceLow
		base.Error = info.Reason
		return base
	}
	base.Observed = map[string]any{"pmf": info.PMF}
	if info.PMF == "" {
		// Not exposed by this platform's data source (spec §4.7 notes
		// this is a real gap, not a defect) — report honestly rather
		// than guessing "disabled".
		base.Status = model.StatusInconclusive
		base.Confidence = model.ConfidenceLow
		return base
	}
	if info.PMF == "disabled" {
		base.Status = model.StatusAnomalous
		base.Confidence = model.ConfidenceMedium
	} else {
		base.Status = model.StatusNormal
		base.Confidence = model.ConfidenceHigh
	}
	return base
}
