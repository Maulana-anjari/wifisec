package local

import (
	"context"
	"time"

	"github.com/Maulana-anjari/wifisec/internal/checks"
	"github.com/Maulana-anjari/wifisec/internal/model"
	"github.com/Maulana-anjari/wifisec/internal/registry"
)

const standardMTU = 1500

type MTUCheck struct{ def registry.CheckDefinition }

func NewMTUCheck(def registry.CheckDefinition) checks.Checker { return MTUCheck{def} }

func (c MTUCheck) Definition() registry.CheckDefinition { return c.def }

func (c MTUCheck) Run(ctx context.Context, cc checks.CheckContext) model.Check {
	start := time.Now()
	cfg, err := cc.Platform.NetConfig()
	if err != nil {
		return checks.NewErrorCheck(c.def, err, start)
	}
	status := model.StatusNormal
	confidence := model.ConfidenceHigh
	switch {
	case cfg.Interface == "":
		// No default route was found (spec T1's netns scenario) — there
		// is no MTU to observe, not a confident "normal" one.
		status = model.StatusInconclusive
		confidence = model.ConfidenceLow
	case cfg.MTU != 0 && cfg.MTU != standardMTU:
		status = model.StatusAnomalous
		confidence = model.ConfidenceMedium
	}
	return model.Check{
		ID:              c.def.ID,
		Layer:           c.def.Layer,
		Title:           c.def.Title,
		ProfileRequired: c.def.ProfileRequired,
		Status:          status,
		Confidence:      confidence,
		Observed:        map[string]any{"mtu": cfg.MTU, "standard_mtu": standardMTU},
		Control:         model.Control{Performed: false},
		DurationMS:      time.Since(start).Milliseconds(),
	}
}
