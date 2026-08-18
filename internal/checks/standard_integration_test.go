// internal/checks/standard_integration_test.go
package checks_test

import (
	"context"
	"testing"
	"time"

	"github.com/Maulana-anjari/wifisec/internal/checks"
	dnschecks "github.com/Maulana-anjari/wifisec/internal/checks/dns"
	netchecks "github.com/Maulana-anjari/wifisec/internal/checks/net"
	tlschecks "github.com/Maulana-anjari/wifisec/internal/checks/tls"
	"github.com/Maulana-anjari/wifisec/internal/guard"
	"github.com/Maulana-anjari/wifisec/internal/model"
	"github.com/Maulana-anjari/wifisec/internal/platform"
	"github.com/Maulana-anjari/wifisec/internal/registry"
)

// T-equivalent for M4: "captive portal detection works and produces no
// false positive on a real network" (spec §11 M4 completion
// criterion). This test needs real internet access — same category as
// T1's real-network-namespace half, but the opposite direction (it
// requires a route, not the absence of one). Skips cleanly if there is
// none, rather than failing the build in an offline sandbox.
func TestCaptivePortalNoFalsePositiveOnRealNetwork(t *testing.T) {
	def := registry.CheckDefinition{ID: "net.captive_portal", ProfileRequired: model.ProfileStandard, EstimatedPackets: 2}
	c := netchecks.NewCaptivePortalCheck(def)
	cc := checks.CheckContext{Counter: guard.NewPacketCounter(100), Timeout: 5 * time.Second}
	got := c.Run(context.Background(), cc)
	if got.Status == model.StatusInconclusive {
		t.Skip("no real network route available in this environment")
	}
	if got.Status != model.StatusNormal {
		t.Errorf("false positive: Status = %v on a real, non-portal network: %#v", got.Status, got.Observed)
	}
}

// Proves the Task 7 budget fix: running every minimal+standard checker
// for real against a live network must not exhaust
// guard.PacketCounter's limit before the last one runs (regression
// test for the estimatedPackets[ProfileStandard] off-by-2 fixed in
// Task 7 Step 1).
func TestStandardProfileStaysWithinRealPacketBudget(t *testing.T) {
	reg, err := registry.Load()
	if err != nil {
		t.Fatal(err)
	}
	defs := reg.Filter(model.ProfileStandard)
	factory := map[string]func(registry.CheckDefinition) checks.Checker{
		"dns.resolve_basic":     func(d registry.CheckDefinition) checks.Checker { return dnschecks.NewResolveBasicCheck(d) },
		"tls.cert_issuer":       func(d registry.CheckDefinition) checks.Checker { return tlschecks.NewCertIssuerCheck(d) },
		"net.captive_portal":    func(d registry.CheckDefinition) checks.Checker { return netchecks.NewCaptivePortalCheck(d) },
		"net.latency_gateway":   func(d registry.CheckDefinition) checks.Checker { return netchecks.NewLatencyGatewayCheck(d) },
		"net.latency_internet":  func(d registry.CheckDefinition) checks.Checker { return netchecks.NewLatencyInternetCheck(d) },
		"dns.compare_doh":       func(d registry.CheckDefinition) checks.Checker { return dnschecks.NewCompareDoHCheck(d) },
		"dns.transparent_proxy": func(d registry.CheckDefinition) checks.Checker { return dnschecks.NewTransparentProxyCheck(d) },
		"net.bufferbloat":       func(d registry.CheckDefinition) checks.Checker { return netchecks.NewBufferbloatCheck(d) },
		"net.ipv6":              func(d registry.CheckDefinition) checks.Checker { return netchecks.NewIPv6Check(d) },
	}
	var built []checks.Checker
	for _, d := range defs {
		if ctor, ok := factory[d.ID]; ok {
			built = append(built, ctor(d))
		}
	}
	if len(built) != len(factory) {
		t.Fatalf("built %d checkers from factory of %d (factory/registry desynced?); some expected checks missing", len(built), len(factory))
	}
	cc := checks.CheckContext{
		Platform: platform.New(),
		Counter:  guard.NewPacketCounter(model.ProfileStandard.EstimatedPackets()),
		Timeout:  10 * time.Second,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for c := range checks.Run(ctx, built, cc) {
		if c.Status == model.StatusError && c.Error != "" {
			t.Errorf("check %s errored (possible budget exhaustion): %s", c.ID, c.Error)
		}
	}
}
