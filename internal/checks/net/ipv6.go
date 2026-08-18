package net

import (
	stdcontext "context"
	stdnet "net"
	"time"

	"github.com/Maulana-anjari/wifisec/internal/checks"
	"github.com/Maulana-anjari/wifisec/internal/model"
	"github.com/Maulana-anjari/wifisec/internal/registry"
)

type IPv6Check struct{ def registry.CheckDefinition }

func NewIPv6Check(def registry.CheckDefinition) checks.Checker { return IPv6Check{def} }
func (c IPv6Check) Definition() registry.CheckDefinition       { return c.def }

// Run reports whether the control domain is reachable over IPv6. This
// is purely observational (spec P2) — plenty of legitimate networks
// have no IPv6 at all, so "unavailable" is Normal, not Anomalous.
// Spec §7.2's required-findings list has no ipv6-derived finding, so
// there is nothing for the interpret layer to key off besides the raw
// observation.
func (c IPv6Check) Run(ctx stdcontext.Context, cc checks.CheckContext) model.Check {
	start := time.Now()
	if err := cc.Counter.Add(c.def.ID, c.def.EstimatedPackets); err != nil {
		return checks.NewErrorCheck(c.def, err, start)
	}
	resolver := stdnet.Resolver{PreferGo: true}
	ips, err := resolver.LookupIP(ctx, "ip6", controlDomain)
	available := err == nil && len(ips) > 0
	if available {
		dialer := stdnet.Dialer{Timeout: 2 * time.Second}
		conn, dialErr := dialer.DialContext(ctx, "tcp", "["+ips[0].String()+"]:443")
		available = dialErr == nil
		if conn != nil {
			conn.Close()
		}
	}
	return model.Check{
		ID: c.def.ID, Layer: c.def.Layer, Title: c.def.Title, ProfileRequired: c.def.ProfileRequired,
		Status: model.StatusNormal, Confidence: model.ConfidenceMedium,
		Observed:    map[string]any{"ipv6_available": available},
		Control:     model.Control{Performed: false},
		PacketsSent: c.def.EstimatedPackets, DurationMS: time.Since(start).Milliseconds(),
	}
}
