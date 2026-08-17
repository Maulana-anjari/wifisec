package wifi

import (
	"context"
	"strings"
	"time"

	"github.com/Maulana-anjari/wifisec/internal/checks"
	"github.com/Maulana-anjari/wifisec/internal/model"
	"github.com/Maulana-anjari/wifisec/internal/registry"
)

type SecurityCheck struct{ def registry.CheckDefinition }

func NewSecurityCheck(def registry.CheckDefinition) checks.Checker { return SecurityCheck{def} }

func (c SecurityCheck) Definition() registry.CheckDefinition { return c.def }

func (c SecurityCheck) Run(ctx context.Context, cc checks.CheckContext) model.Check {
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
	sec := strings.ToLower(info.Security)
	base.Observed = map[string]any{"security": info.Security}
	switch {
	case sec == "open" || sec == "" || strings.Contains(sec, "wep"):
		base.Status = model.StatusAnomalous
		base.Confidence = model.ConfidenceHigh
	default:
		base.Status = model.StatusNormal
		base.Confidence = model.ConfidenceHigh
	}
	return base
}
