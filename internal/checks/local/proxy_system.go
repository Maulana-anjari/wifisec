package local

import (
	"context"
	"time"

	"github.com/Maulana-anjari/wifisec/internal/checks"
	"github.com/Maulana-anjari/wifisec/internal/model"
	"github.com/Maulana-anjari/wifisec/internal/registry"
)

type ProxySystemCheck struct{ def registry.CheckDefinition }

func NewProxySystemCheck(def registry.CheckDefinition) checks.Checker { return ProxySystemCheck{def} }

func (c ProxySystemCheck) Definition() registry.CheckDefinition { return c.def }

func (c ProxySystemCheck) Run(ctx context.Context, cc checks.CheckContext) model.Check {
	start := time.Now()
	proxy, err := cc.Platform.ProxyConfig()
	if err != nil {
		return checks.NewErrorCheck(c.def, err, start)
	}
	status := model.StatusNormal
	confidence := model.ConfidenceHigh
	if proxy.Enabled {
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
		Observed: map[string]any{
			"enabled":     proxy.Enabled,
			"http_proxy":  proxy.HTTPProxy,
			"https_proxy": proxy.HTTPSProxy,
			"pac_url":     proxy.PACUrl,
		},
		Control:    model.Control{Performed: false},
		DurationMS: time.Since(start).Milliseconds(),
	}
}
