package wifi

import (
	"context"
	"time"

	"github.com/Maulana-anjari/wifisec/internal/checks"
	"github.com/Maulana-anjari/wifisec/internal/model"
	"github.com/Maulana-anjari/wifisec/internal/registry"
)

type ChannelCheck struct{ def registry.CheckDefinition }

func NewChannelCheck(def registry.CheckDefinition) checks.Checker { return ChannelCheck{def} }

func (c ChannelCheck) Definition() registry.CheckDefinition { return c.def }

func (c ChannelCheck) Run(ctx context.Context, cc checks.CheckContext) model.Check {
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
	base.Observed = map[string]any{"channel": info.Channel, "band": info.Band}
	base.Status = model.StatusNormal
	base.Confidence = model.ConfidenceHigh
	return base
}
