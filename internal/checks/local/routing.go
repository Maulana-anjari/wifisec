package local

import (
	"context"
	"time"

	"github.com/Maulana-anjari/wifisec/internal/checks"
	"github.com/Maulana-anjari/wifisec/internal/model"
	"github.com/Maulana-anjari/wifisec/internal/registry"
)

type RoutingCheck struct{ def registry.CheckDefinition }

func NewRoutingCheck(def registry.CheckDefinition) checks.Checker { return RoutingCheck{def} }

func (c RoutingCheck) Definition() registry.CheckDefinition { return c.def }

func (c RoutingCheck) Run(ctx context.Context, cc checks.CheckContext) model.Check {
	start := time.Now()
	routes, err := cc.Platform.RoutingTable()
	if err != nil {
		return checks.NewErrorCheck(c.def, err, start)
	}
	hasDefault := false
	for _, r := range routes {
		if r.Default {
			hasDefault = true
			break
		}
	}
	status := model.StatusNormal
	confidence := model.ConfidenceHigh
	if !hasDefault {
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
		Observed:        map[string]any{"route_count": len(routes), "has_default_route": hasDefault},
		Control:         model.Control{Performed: false},
		DurationMS:      time.Since(start).Milliseconds(),
	}
}
