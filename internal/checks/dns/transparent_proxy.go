package dns

import (
	stdcontext "context"
	"time"

	"github.com/Maulana-anjari/wifisec/internal/checks"
	"github.com/Maulana-anjari/wifisec/internal/model"
	"github.com/Maulana-anjari/wifisec/internal/registry"
)

// directResolver is queried straight over UDP:53, bypassing whatever
// resolver the OS/DHCP configured, to check whether port-53 traffic
// gets rewritten regardless of destination (spec §6.3
// "dns.transparent_proxy"). Same operator as doh.go's DoH endpoint —
// a legitimate answer from 1.1.1.1 must agree with Cloudflare's DoH
// answer for the same name.
const directResolver = "1.1.1.1"

type TransparentProxyCheck struct{ def registry.CheckDefinition }

func NewTransparentProxyCheck(def registry.CheckDefinition) checks.Checker { return TransparentProxyCheck{def} }
func (c TransparentProxyCheck) Definition() registry.CheckDefinition       { return c.def }

func (c TransparentProxyCheck) Run(ctx stdcontext.Context, cc checks.CheckContext) model.Check {
	start := time.Now()
	if err := cc.Counter.Add(c.def.ID, c.def.EstimatedPackets); err != nil {
		return checks.NewErrorCheck(c.def, err, start)
	}
	directAddrs, directErr := queryA(ctx, directResolver)
	dohAddrs, dohErr := queryDoH(ctx, "example.com")
	if directErr != nil {
		return model.Check{
			ID: c.def.ID, Layer: c.def.Layer, Title: c.def.Title, ProfileRequired: c.def.ProfileRequired,
			Status: model.StatusInconclusive, Confidence: model.ConfidenceLow,
			Control:     model.Control{Performed: false, Reason: "port53_unreachable"},
			PacketsSent: c.def.EstimatedPackets, DurationMS: time.Since(start).Milliseconds(),
		}
	}
	if dohErr != nil || len(dohAddrs) == 0 {
		return model.Check{
			ID: c.def.ID, Layer: c.def.Layer, Title: c.def.Title, ProfileRequired: c.def.ProfileRequired,
			Status: model.StatusInconclusive, Confidence: model.ConfidenceLow,
			Observed:    map[string]any{"direct_addresses": directAddrs},
			Control:     model.Control{Performed: false, Reason: "doh_unreachable"},
			PacketsSent: c.def.EstimatedPackets, DurationMS: time.Since(start).Milliseconds(),
		}
	}
	match := sameAddressSet(directAddrs, dohAddrs)
	status := model.StatusNormal
	confidence := model.ConfidenceHigh
	if !match {
		status = model.StatusAnomalous
	}
	return model.Check{
		ID: c.def.ID, Layer: c.def.Layer, Title: c.def.Title, ProfileRequired: c.def.ProfileRequired,
		Status: status, Confidence: confidence,
		Observed:    map[string]any{"direct_addresses": directAddrs, "doh_addresses": dohAddrs, "match": match},
		Control:     model.Control{Performed: true, Result: "direct query to 1.1.1.1:53 vs Cloudflare DoH"},
		PacketsSent: c.def.EstimatedPackets, DurationMS: time.Since(start).Milliseconds(),
	}
}
