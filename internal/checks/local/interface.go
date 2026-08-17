package local

import (
	"context"
	"time"

	"github.com/Maulana-anjari/wifisec/internal/checks"
	"github.com/Maulana-anjari/wifisec/internal/model"
	"github.com/Maulana-anjari/wifisec/internal/registry"
)

type InterfaceCheck struct{ def registry.CheckDefinition }

func NewInterfaceCheck(def registry.CheckDefinition) checks.Checker { return InterfaceCheck{def} }

func (c InterfaceCheck) Definition() registry.CheckDefinition { return c.def }

func (c InterfaceCheck) Run(ctx context.Context, cc checks.CheckContext) model.Check {
	start := time.Now()
	cfg, err := cc.Platform.NetConfig()
	if err != nil {
		return checks.NewErrorCheck(c.def, err, start)
	}
	status := model.StatusNormal
	confidence := model.ConfidenceHigh
	if cfg.Interface == "" {
		// No default route was found (spec T1's netns scenario) — there
		// is no interface to observe, not a confident "normal" one.
		status = model.StatusInconclusive
		confidence = model.ConfidenceLow
	}
	return model.Check{
		ID:              c.def.ID,
		Layer:           c.def.Layer,
		Title:           c.def.Title,
		ProfileRequired: c.def.ProfileRequired,
		Status:          status,
		Confidence:      confidence,
		Observed: map[string]any{
			"interface": cfg.Interface,
			"ip":        cfg.IP,
			"netmask":   cfg.Netmask,
			"mtu":       cfg.MTU,
		},
		Control:    model.Control{Performed: false},
		DurationMS: time.Since(start).Milliseconds(),
	}
}
