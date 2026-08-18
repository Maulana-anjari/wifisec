package dns

import (
	stdcontext "context"
	"sort"
	"time"

	"github.com/Maulana-anjari/wifisec/internal/checks"
	"github.com/Maulana-anjari/wifisec/internal/model"
	"github.com/Maulana-anjari/wifisec/internal/registry"
)

func sameAddressSet(a, b []string) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	sa, sb := append([]string{}, a...), append([]string{}, b...)
	sort.Strings(sa)
	sort.Strings(sb)
	if len(sa) != len(sb) {
		return false
	}
	for i := range sa {
		if sa[i] != sb[i] {
			return false
		}
	}
	return true
}

type CompareDoHCheck struct{ def registry.CheckDefinition }

func NewCompareDoHCheck(def registry.CheckDefinition) checks.Checker { return CompareDoHCheck{def} }
func (c CompareDoHCheck) Definition() registry.CheckDefinition       { return c.def }

func (c CompareDoHCheck) Run(ctx stdcontext.Context, cc checks.CheckContext) model.Check {
	start := time.Now()
	cfg, err := cc.Platform.NetConfig()
	if err != nil || len(cfg.DNSServers) == 0 {
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
	networkAddrs, netErr := queryAFunc(ctx, cfg.DNSServers[0])
	dohAddrs, dohErr := queryDoH(ctx, controlDomainNoFQDN)
	if netErr != nil || dohErr != nil || len(dohAddrs) == 0 {
		reason := "doh_unreachable"
		if netErr != nil {
			reason = "network_resolver_unreachable"
		}
		return model.Check{
			ID: c.def.ID, Layer: c.def.Layer, Title: c.def.Title, ProfileRequired: c.def.ProfileRequired,
			Status: model.StatusInconclusive, Confidence: model.ConfidenceLow,
			Observed:    map[string]any{"network_addresses": networkAddrs},
			Control:     model.Control{Performed: false, Reason: reason},
			PacketsSent: c.def.EstimatedPackets, DurationMS: time.Since(start).Milliseconds(),
		}
	}
	match := sameAddressSet(networkAddrs, dohAddrs)
	status := model.StatusNormal
	confidence := model.ConfidenceHigh
	if !match {
		status = model.StatusAnomalous
	}
	return model.Check{
		ID: c.def.ID, Layer: c.def.Layer, Title: c.def.Title, ProfileRequired: c.def.ProfileRequired,
		Status: status, Confidence: confidence,
		Observed:    map[string]any{"network_addresses": networkAddrs, "doh_addresses": dohAddrs, "match": match},
		Control:     model.Control{Performed: true, Result: "network resolver vs Cloudflare DoH"},
		PacketsSent: c.def.EstimatedPackets, DurationMS: time.Since(start).Milliseconds(),
	}
}
