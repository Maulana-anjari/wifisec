package checks_test

import (
	"context"
	"testing"
	"time"

	"github.com/Maulana-anjari/wifisec/internal/checks"
	"github.com/Maulana-anjari/wifisec/internal/checks/local"
	"github.com/Maulana-anjari/wifisec/internal/checks/wifi"
	"github.com/Maulana-anjari/wifisec/internal/guard"
	"github.com/Maulana-anjari/wifisec/internal/model"
	"github.com/Maulana-anjari/wifisec/internal/platform"
	"github.com/Maulana-anjari/wifisec/internal/registry"
)

// TestT1PassiveProfileSendsZeroPackets is spec's own most important
// test (§8.1: "Ini test terpenting di seluruh proyek"): every §6.1
// check, run for real against this machine, must send exactly zero
// packets.
func TestT1PassiveProfileSendsZeroPackets(t *testing.T) {
	reg, err := registry.Load()
	if err != nil {
		t.Fatalf("registry.Load: %v", err)
	}
	defs := reg.Filter(model.ProfilePassive)
	if len(defs) == 0 {
		t.Fatal("no passive-profile checks found in registry")
	}

	factory := map[string]func(registry.CheckDefinition) checks.Checker{
		"local.interface":    func(d registry.CheckDefinition) checks.Checker { return local.NewInterfaceCheck(d) },
		"local.gateway":      func(d registry.CheckDefinition) checks.Checker { return local.NewGatewayCheck(d) },
		"local.dns_servers":  func(d registry.CheckDefinition) checks.Checker { return local.NewDNSServersCheck(d) },
		"local.routing":      func(d registry.CheckDefinition) checks.Checker { return local.NewRoutingCheck(d) },
		"local.mtu":          func(d registry.CheckDefinition) checks.Checker { return local.NewMTUCheck(d) },
		"local.proxy_system": func(d registry.CheckDefinition) checks.Checker { return local.NewProxySystemCheck(d) },
		"local.trust_store":  func(d registry.CheckDefinition) checks.Checker { return local.NewTrustStoreCheck(d) },
		"wifi.security":      func(d registry.CheckDefinition) checks.Checker { return wifi.NewSecurityCheck(d) },
		"wifi.pmf":           func(d registry.CheckDefinition) checks.Checker { return wifi.NewPMFCheck(d) },
		"wifi.signal":        func(d registry.CheckDefinition) checks.Checker { return wifi.NewSignalCheck(d) },
		"wifi.channel":       func(d registry.CheckDefinition) checks.Checker { return wifi.NewChannelCheck(d) },
		"wifi.bssid_vendor":  func(d registry.CheckDefinition) checks.Checker { return wifi.NewBSSIDVendorCheck(d) },
		"wifi.link_speed":    func(d registry.CheckDefinition) checks.Checker { return wifi.NewLinkSpeedCheck(d) },
	}

	var checkers []checks.Checker
	for _, def := range defs {
		ctor, ok := factory[def.ID]
		if !ok {
			t.Fatalf("no implementation registered for passive check %q — T1 must exercise every §6.1 check", def.ID)
		}
		checkers = append(checkers, ctor(def))
	}

	counter := guard.NewPacketCounter(model.ProfilePassive.EstimatedPackets()) // 0
	cc := checks.CheckContext{Platform: platform.New(), Counter: counter, Timeout: 10 * time.Second}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var results []model.Check
	for c := range checks.Run(ctx, checkers, cc) {
		results = append(results, c)
		if c.Status == model.StatusError {
			t.Logf("check %s errored (informational, not a T1 failure by itself): %s", c.ID, c.Error)
		}
	}

	if got := counter.Total(); got != 0 {
		t.Errorf("counter.Total() = %d, want 0 (passive profile must send zero packets)", got)
	}
	for _, c := range results {
		if c.PacketsSent != 0 {
			t.Errorf("check %s reported PacketsSent = %d, want 0", c.ID, c.PacketsSent)
		}
	}
}
