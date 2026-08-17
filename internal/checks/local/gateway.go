package local

import (
	"context"
	"net"
	"time"

	"github.com/Maulana-anjari/wifisec/internal/checks"
	"github.com/Maulana-anjari/wifisec/internal/model"
	"github.com/Maulana-anjari/wifisec/internal/registry"
)

type GatewayCheck struct{ def registry.CheckDefinition }

func NewGatewayCheck(def registry.CheckDefinition) checks.Checker { return GatewayCheck{def} }

func (c GatewayCheck) Definition() registry.CheckDefinition { return c.def }

func (c GatewayCheck) Run(ctx context.Context, cc checks.CheckContext) model.Check {
	start := time.Now()
	cfg, err := cc.Platform.NetConfig()
	if err != nil {
		return checks.NewErrorCheck(c.def, err, start)
	}
	ip := net.ParseIP(cfg.Gateway)
	isPrivate := ip != nil && ip.IsPrivate()
	status := model.StatusNormal
	confidence := model.ConfidenceHigh
	if cfg.Interface == "" {
		// No default route was found (spec T1's netns scenario) — there
		// is no gateway to observe, not a confident "normal" gateway.
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
			"gateway":    cfg.Gateway,
			"is_private": isPrivate,
		},
		Control:    model.Control{Performed: false},
		DurationMS: time.Since(start).Milliseconds(),
	}
}
