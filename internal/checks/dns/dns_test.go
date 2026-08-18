package dns

import (
	"context"
	"testing"
	"time"

	"github.com/Maulana-anjari/wifisec/internal/checks"
	"github.com/Maulana-anjari/wifisec/internal/guard"
	"github.com/Maulana-anjari/wifisec/internal/model"
	"github.com/Maulana-anjari/wifisec/internal/platform"
	"github.com/Maulana-anjari/wifisec/internal/registry"
)

type fakeAdapter struct {
	platform.Adapter
	netConfig platform.NetConfig
}

func (f fakeAdapter) NetConfig() (platform.NetConfig, error) { return f.netConfig, nil }

func testCC(dnsServers []string) checks.CheckContext {
	return checks.CheckContext{
		Platform: fakeAdapter{netConfig: platform.NetConfig{DNSServers: dnsServers}},
		Counter:  guard.NewPacketCounter(1000),
		Timeout:  5 * time.Second,
	}
}

func TestResolveBasicInconclusiveWhenNoDNSServers(t *testing.T) {
	def := registry.CheckDefinition{ID: "dns.resolve_basic", EstimatedPackets: 1}
	c := NewResolveBasicCheck(def)
	got := c.Run(context.Background(), testCC(nil))
	if got.Status != model.StatusInconclusive {
		t.Errorf("Status = %v, want inconclusive with no configured DNS server", got.Status)
	}
}

func TestResolveBasicNormalAgainstPublicResolver(t *testing.T) {
	def := registry.CheckDefinition{ID: "dns.resolve_basic", EstimatedPackets: 1}
	c := NewResolveBasicCheck(def)
	got := c.Run(context.Background(), testCC([]string{"1.1.1.1"}))
	if got.Status != model.StatusNormal {
		t.Errorf("Status = %v, want normal resolving example.com via 1.1.1.1: %#v", got.Status, got.Observed)
	}
	addrs, ok := got.Observed["addresses"].([]string)
	if !ok || len(addrs) == 0 {
		t.Errorf("Observed[addresses] missing or empty: %#v", got.Observed["addresses"])
	}
}

func TestCompareDoHNormalWhenConsistent(t *testing.T) {
	def := registry.CheckDefinition{ID: "dns.compare_doh", EstimatedPackets: 4}
	c := NewCompareDoHCheck(def)
	got := c.Run(context.Background(), testCC([]string{"1.1.1.1"}))
	if got.Status != model.StatusNormal && got.Status != model.StatusInconclusive {
		t.Errorf("Status = %v, want normal or inconclusive (never anomalous against a real public resolver): %#v", got.Status, got.Observed)
	}
}

func TestTransparentProxyNormalOnCleanNetwork(t *testing.T) {
	def := registry.CheckDefinition{ID: "dns.transparent_proxy", EstimatedPackets: 2}
	c := NewTransparentProxyCheck(def)
	got := c.Run(context.Background(), testCC([]string{"1.1.1.1"}))
	if got.Status != model.StatusNormal && got.Status != model.StatusInconclusive {
		t.Errorf("Status = %v, want normal or inconclusive: %#v", got.Status, got.Observed)
	}
}
