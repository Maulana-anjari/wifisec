package wifi

import (
	"context"
	"time"

	"github.com/Maulana-anjari/wifisec/internal/checks"
	"github.com/Maulana-anjari/wifisec/internal/model"
	"github.com/Maulana-anjari/wifisec/internal/registry"
)

type SignalCheck struct{ def registry.CheckDefinition }

func NewSignalCheck(def registry.CheckDefinition) checks.Checker { return SignalCheck{def} }

func (c SignalCheck) Definition() registry.CheckDefinition { return c.def }

func (c SignalCheck) Run(ctx context.Context, cc checks.CheckContext) model.Check {
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
	quality := "good"
	if info.RSSI < -80 {
		quality = "poor"
	} else if info.RSSI < -67 {
		quality = "fair"
	}
	base.Observed = map[string]any{"rssi": info.RSSI, "quality": quality}
	base.Status = model.StatusNormal
	base.Confidence = model.ConfidenceMedium // RSSI is an approximation, see platform/linux.go
	return base
}
