package wifi

import (
	"context"
	"time"

	"github.com/Maulana-anjari/wifisec/internal/checks"
	"github.com/Maulana-anjari/wifisec/internal/model"
	"github.com/Maulana-anjari/wifisec/internal/registry"
)

type LinkSpeedCheck struct{ def registry.CheckDefinition }

func NewLinkSpeedCheck(def registry.CheckDefinition) checks.Checker { return LinkSpeedCheck{def} }

func (c LinkSpeedCheck) Definition() registry.CheckDefinition { return c.def }

func (c LinkSpeedCheck) Run(ctx context.Context, cc checks.CheckContext) model.Check {
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
	base.Observed = map[string]any{"mbps": info.LinkSpeed}
	base.Status = model.StatusNormal
	base.Confidence = model.ConfidenceHigh
	return base
}
