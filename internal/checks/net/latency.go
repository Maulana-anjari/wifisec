package net

import (
	stdcontext "context"
	"time"

	"github.com/Maulana-anjari/wifisec/internal/checks"
	"github.com/Maulana-anjari/wifisec/internal/model"
	"github.com/Maulana-anjari/wifisec/internal/registry"
)

// controlDomain is the control domain approved for M4 (see plan
// Global Constraints — spec §13 required asking, not guessing).
const controlDomain = "example.com"

// internetTarget is the control domain with port for internet reachability tests.
const internetTarget = controlDomain + ":443"

type LatencyGatewayCheck struct{ def registry.CheckDefinition }

func NewLatencyGatewayCheck(def registry.CheckDefinition) checks.Checker { return LatencyGatewayCheck{def} }
func (c LatencyGatewayCheck) Definition() registry.CheckDefinition       { return c.def }

func (c LatencyGatewayCheck) Run(ctx stdcontext.Context, cc checks.CheckContext) model.Check {
	start := time.Now()
	cfg, err := cc.Platform.NetConfig()
	if err != nil {
		return checks.NewErrorCheck(c.def, err, start)
	}
	if cfg.Gateway == "" {
		return model.Check{
			ID: c.def.ID, Layer: c.def.Layer, Title: c.def.Title, ProfileRequired: c.def.ProfileRequired,
			Status: model.StatusInconclusive, Confidence: model.ConfidenceLow,
			Control:    model.Control{Performed: false, Reason: "no_default_route"},
			DurationMS: time.Since(start).Milliseconds(),
		}
	}
	if err := cc.Counter.Add(c.def.ID, c.def.EstimatedPackets); err != nil {
		return checks.NewErrorCheck(c.def, err, start)
	}
	// Most consumer APs don't expose a web UI on the LAN side of every
	// port; try 80 first, fall back to 443. Neither responding cleanly
	// means "no TCP service to time against", not "gateway unreachable"
	// — the gateway answered ARP/routing just fine, it's just not
	// listening on either port. That's an honest inconclusive, not an
	// error (spec P3).
	samples, sent, lost := sampleTCP(ctx, cfg.Gateway+":80", c.def.EstimatedPackets, 2*time.Second)
	if len(samples) == 0 {
		// Reserve packets for fallback to port 443.
		if err := cc.Counter.Add(c.def.ID, c.def.EstimatedPackets); err != nil {
			return checks.NewErrorCheck(c.def, err, start)
		}
		samples443, sent443, lost443 := sampleTCP(ctx, cfg.Gateway+":443", c.def.EstimatedPackets, 2*time.Second)
		samples = samples443
		sent += sent443
		lost += lost443
	}
	if len(samples) == 0 {
		return model.Check{
			ID: c.def.ID, Layer: c.def.Layer, Title: c.def.Title, ProfileRequired: c.def.ProfileRequired,
			Status: model.StatusInconclusive, Confidence: model.ConfidenceLow,
			Observed:    map[string]any{"gateway": cfg.Gateway},
			Control:     model.Control{Performed: false, Reason: "gateway_no_tcp_service"},
			PacketsSent: sent, DurationMS: time.Since(start).Milliseconds(),
		}
	}
	msSamples := msFloats(samples)
	return model.Check{
		ID: c.def.ID, Layer: c.def.Layer, Title: c.def.Title, ProfileRequired: c.def.ProfileRequired,
		Status: model.StatusNormal, Confidence: model.ConfidenceMedium,
		Observed:    map[string]any{"rtt_samples_ms": msSamples, "sent": sent, "lost": lost, "mean_ms": meanMS(msSamples)},
		Control:     model.Control{Performed: false},
		PacketsSent: sent, DurationMS: time.Since(start).Milliseconds(),
	}
}

type LatencyInternetCheck struct{ def registry.CheckDefinition }

func NewLatencyInternetCheck(def registry.CheckDefinition) checks.Checker { return LatencyInternetCheck{def} }
func (c LatencyInternetCheck) Definition() registry.CheckDefinition       { return c.def }

func (c LatencyInternetCheck) Run(ctx stdcontext.Context, cc checks.CheckContext) model.Check {
	start := time.Now()
	if err := cc.Counter.Add(c.def.ID, c.def.EstimatedPackets); err != nil {
		return checks.NewErrorCheck(c.def, err, start)
	}
	samples, sent, lost := sampleTCP(ctx, internetTarget, c.def.EstimatedPackets, 3*time.Second)
	if len(samples) == 0 {
		return model.Check{
			ID: c.def.ID, Layer: c.def.Layer, Title: c.def.Title, ProfileRequired: c.def.ProfileRequired,
			Status: model.StatusInconclusive, Confidence: model.ConfidenceLow,
			Observed:    map[string]any{"target": internetTarget, "sent": sent, "lost": lost},
			Control:     model.Control{Performed: false, Reason: "internet_unreachable"},
			PacketsSent: sent, DurationMS: time.Since(start).Milliseconds(),
		}
	}
	msSamples := msFloats(samples)
	return model.Check{
		ID: c.def.ID, Layer: c.def.Layer, Title: c.def.Title, ProfileRequired: c.def.ProfileRequired,
		Status: model.StatusNormal, Confidence: model.ConfidenceMedium,
		Observed:    map[string]any{"rtt_samples_ms": msSamples, "sent": sent, "lost": lost, "mean_ms": meanMS(msSamples), "target": internetTarget},
		Control:     model.Control{Performed: false},
		PacketsSent: sent, DurationMS: time.Since(start).Milliseconds(),
	}
}
