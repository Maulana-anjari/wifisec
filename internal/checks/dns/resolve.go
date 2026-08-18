// Package dns implements the wifisec "dns"-layer active checks (spec
// §6.2, §6.3): a basic control-domain resolution, a network-resolver
// vs DNS-over-HTTPS comparison, and a port-53-interception probe.
// Uses github.com/miekg/dns for direct, precisely-controlled UDP
// queries (spec §3.3) instead of the OS resolver, so exactly one
// query is sent per "packet" the guard.PacketCounter accounts for.
package dns

import (
	stdcontext "context"
	"time"

	"github.com/miekg/dns"

	"github.com/Maulana-anjari/wifisec/internal/checks"
	"github.com/Maulana-anjari/wifisec/internal/model"
	"github.com/Maulana-anjari/wifisec/internal/registry"
)

// controlDomain is the M4 control domain, user-approved per spec §13
// (see plan Global Constraints — not guessed).
const controlDomain = "example.com."

// queryA sends one A-record query for controlDomain to server (host,
// no port — ":53" is appended here) and returns the resolved
// addresses as strings.
func queryA(ctx stdcontext.Context, server string) ([]string, error) {
	m := new(dns.Msg)
	m.SetQuestion(controlDomain, dns.TypeA)
	c := new(dns.Client)
	c.Timeout = 3 * time.Second
	resp, _, err := c.ExchangeContext(ctx, m, server+":53")
	if err != nil {
		return nil, err
	}
	var addrs []string
	for _, rr := range resp.Answer {
		if a, ok := rr.(*dns.A); ok {
			addrs = append(addrs, a.A.String())
		}
	}
	return addrs, nil
}

type ResolveBasicCheck struct{ def registry.CheckDefinition }

func NewResolveBasicCheck(def registry.CheckDefinition) checks.Checker { return ResolveBasicCheck{def} }
func (c ResolveBasicCheck) Definition() registry.CheckDefinition       { return c.def }

func (c ResolveBasicCheck) Run(ctx stdcontext.Context, cc checks.CheckContext) model.Check {
	start := time.Now()
	cfg, err := cc.Platform.NetConfig()
	if err != nil {
		return checks.NewErrorCheck(c.def, err, start)
	}
	if len(cfg.DNSServers) == 0 {
		return model.Check{
			ID: c.def.ID, Layer: c.def.Layer, Title: c.def.Title, ProfileRequired: c.def.ProfileRequired,
			Status: model.StatusInconclusive, Confidence: model.ConfidenceLow,
			Control:    model.Control{Performed: false, Reason: "no_dns_server_configured"},
			DurationMS: time.Since(start).Milliseconds(),
		}
	}
	if err := cc.Counter.Add(c.def.ID, c.def.EstimatedPackets); err != nil {
		return checks.NewErrorCheck(c.def, err, start)
	}
	addrs, err := queryA(ctx, cfg.DNSServers[0])
	if err != nil {
		return model.Check{
			ID: c.def.ID, Layer: c.def.Layer, Title: c.def.Title, ProfileRequired: c.def.ProfileRequired,
			Status: model.StatusInconclusive, Confidence: model.ConfidenceLow,
			Observed:    map[string]any{"resolver": cfg.DNSServers[0]},
			Control:     model.Control{Performed: false, Reason: "no_response"},
			PacketsSent: c.def.EstimatedPackets, DurationMS: time.Since(start).Milliseconds(),
		}
	}
	status := model.StatusNormal
	confidence := model.ConfidenceMedium
	if len(addrs) == 0 {
		status = model.StatusAnomalous
	}
	return model.Check{
		ID: c.def.ID, Layer: c.def.Layer, Title: c.def.Title, ProfileRequired: c.def.ProfileRequired,
		Status: status, Confidence: confidence,
		Observed:    map[string]any{"domain": controlDomain, "addresses": addrs, "resolver": cfg.DNSServers[0]},
		Control:     model.Control{Performed: false},
		PacketsSent: c.def.EstimatedPackets, DurationMS: time.Since(start).Milliseconds(),
	}
}
