package local

import (
	"context"
	"testing"

	"github.com/Maulana-anjari/wifisec/internal/checks"
	"github.com/Maulana-anjari/wifisec/internal/model"
	"github.com/Maulana-anjari/wifisec/internal/platform"
	"github.com/Maulana-anjari/wifisec/internal/registry"
)

type fakeAdapter struct {
	netConfig    platform.NetConfig
	netConfigErr error
	routes       []platform.Route
	proxy        platform.ProxyConfig
	cas          []platform.CACert
}

func (f fakeAdapter) WiFiInfo() (platform.WiFiInfo, error)       { return platform.WiFiInfo{}, nil }
func (f fakeAdapter) NetConfig() (platform.NetConfig, error)     { return f.netConfig, f.netConfigErr }
func (f fakeAdapter) ProxyConfig() (platform.ProxyConfig, error) { return f.proxy, nil }
func (f fakeAdapter) TrustStoreCAs() ([]platform.CACert, error)  { return f.cas, nil }
func (f fakeAdapter) RoutingTable() ([]platform.Route, error)    { return f.routes, nil }

func testDef(id string) registry.CheckDefinition {
	return registry.CheckDefinition{ID: id, Layer: model.LayerLocal, Title: id, ProfileRequired: model.ProfilePassive, SelfEvident: id == "local.trust_store"}
}

func TestInterfaceCheckReportsNetConfig(t *testing.T) {
	a := fakeAdapter{netConfig: platform.NetConfig{Interface: "eth0", IP: "10.0.0.5", Netmask: "255.255.255.0", MTU: 1500}}
	c := NewInterfaceCheck(testDef("local.interface")).Run(context.Background(), checks.CheckContext{Platform: a})
	if c.Status != model.StatusNormal {
		t.Errorf("Status = %s, want normal", c.Status)
	}
	if c.Observed["interface"] != "eth0" {
		t.Errorf("Observed[interface] = %v, want eth0", c.Observed["interface"])
	}
	if c.PacketsSent != 0 {
		t.Errorf("PacketsSent = %d, want 0", c.PacketsSent)
	}
}

func TestInterfaceCheckInconclusiveWithNoDefaultRoute(t *testing.T) {
	a := fakeAdapter{netConfig: platform.NetConfig{}}
	c := NewInterfaceCheck(testDef("local.interface")).Run(context.Background(), checks.CheckContext{Platform: a})
	if c.Status != model.StatusInconclusive {
		t.Errorf("Status = %s, want inconclusive with no default route", c.Status)
	}
	if c.Confidence != model.ConfidenceLow {
		t.Errorf("Confidence = %s, want low with no default route", c.Confidence)
	}
}

func TestGatewayCheckClassifiesPrivateIP(t *testing.T) {
	a := fakeAdapter{netConfig: platform.NetConfig{Interface: "eth0", Gateway: "192.168.1.1"}}
	c := NewGatewayCheck(testDef("local.gateway")).Run(context.Background(), checks.CheckContext{Platform: a})
	if c.Observed["is_private"] != true {
		t.Errorf("Observed[is_private] = %v, want true for 192.168.1.1", c.Observed["is_private"])
	}
	if c.Status != model.StatusNormal {
		t.Errorf("Status = %s, want normal when a default route exists", c.Status)
	}
}

func TestGatewayCheckInconclusiveWithNoDefaultRoute(t *testing.T) {
	a := fakeAdapter{netConfig: platform.NetConfig{}}
	c := NewGatewayCheck(testDef("local.gateway")).Run(context.Background(), checks.CheckContext{Platform: a})
	if c.Status != model.StatusInconclusive {
		t.Errorf("Status = %s, want inconclusive with no default route", c.Status)
	}
	if c.Confidence != model.ConfidenceLow {
		t.Errorf("Confidence = %s, want low with no default route", c.Confidence)
	}
}

func TestDNSServersCheckClassifiesPublicResolver(t *testing.T) {
	a := fakeAdapter{netConfig: platform.NetConfig{DNSServers: []string{"8.8.8.8", "192.168.1.1"}}}
	c := NewDNSServersCheck(testDef("local.dns_servers")).Run(context.Background(), checks.CheckContext{Platform: a})
	servers, ok := c.Observed["servers"].([]map[string]any)
	if !ok || len(servers) != 2 {
		t.Fatalf("expected 2 classified servers, got %v", c.Observed["servers"])
	}
	// No loopback stub present: existing anomalous-on-internal-resolver
	// behavior must still hold.
	if c.Status != model.StatusAnomalous {
		t.Errorf("Status = %s, want anomalous (192.168.1.1 is an internal resolver)", c.Status)
	}
}

func TestDNSServersCheckFlagsLoopbackStubAsInconclusive(t *testing.T) {
	a := fakeAdapter{netConfig: platform.NetConfig{DNSServers: []string{"8.8.8.8", "192.168.1.1", "127.0.0.53"}}}
	c := NewDNSServersCheck(testDef("local.dns_servers")).Run(context.Background(), checks.CheckContext{Platform: a})
	servers, ok := c.Observed["servers"].([]map[string]any)
	if !ok || len(servers) != 3 {
		t.Fatalf("expected 3 classified servers, got %v", c.Observed["servers"])
	}
	byAddr := make(map[string]map[string]any, len(servers))
	for _, s := range servers {
		byAddr[s["address"].(string)] = s
	}
	if byAddr["8.8.8.8"]["is_internal"] != false || byAddr["8.8.8.8"]["is_loopback_stub"] == true {
		t.Errorf("8.8.8.8 = %v, want is_internal=false, is_loopback_stub absent-or-false", byAddr["8.8.8.8"])
	}
	if byAddr["192.168.1.1"]["is_internal"] != true {
		t.Errorf("192.168.1.1 = %v, want is_internal=true", byAddr["192.168.1.1"])
	}
	if byAddr["127.0.0.53"]["is_loopback_stub"] != true {
		t.Errorf("127.0.0.53 = %v, want is_loopback_stub=true", byAddr["127.0.0.53"])
	}
	if c.Status != model.StatusInconclusive {
		t.Errorf("Status = %s, want inconclusive when a loopback stub resolver is present", c.Status)
	}
	if c.Confidence != model.ConfidenceLow {
		t.Errorf("Confidence = %s, want low when a loopback stub resolver is present", c.Confidence)
	}
}

func TestRoutingCheckReportsDefaultRoute(t *testing.T) {
	a := fakeAdapter{routes: []platform.Route{{Destination: "default", Gateway: "10.0.0.1", Default: true}}}
	c := NewRoutingCheck(testDef("local.routing")).Run(context.Background(), checks.CheckContext{Platform: a})
	if c.Status != model.StatusNormal {
		t.Errorf("Status = %s, want normal", c.Status)
	}
}

func TestMTUCheckFlagsNonStandard(t *testing.T) {
	a := fakeAdapter{netConfig: platform.NetConfig{Interface: "eth0", MTU: 1400}}
	c := NewMTUCheck(testDef("local.mtu")).Run(context.Background(), checks.CheckContext{Platform: a})
	if c.Status != model.StatusAnomalous {
		t.Errorf("Status = %s, want anomalous for non-standard MTU 1400", c.Status)
	}
}

func TestMTUCheckAcceptsStandard(t *testing.T) {
	a := fakeAdapter{netConfig: platform.NetConfig{Interface: "eth0", MTU: 1500}}
	c := NewMTUCheck(testDef("local.mtu")).Run(context.Background(), checks.CheckContext{Platform: a})
	if c.Status != model.StatusNormal {
		t.Errorf("Status = %s, want normal for standard MTU 1500", c.Status)
	}
}

func TestMTUCheckInconclusiveWithNoDefaultRoute(t *testing.T) {
	a := fakeAdapter{netConfig: platform.NetConfig{}}
	c := NewMTUCheck(testDef("local.mtu")).Run(context.Background(), checks.CheckContext{Platform: a})
	if c.Status != model.StatusInconclusive {
		t.Errorf("Status = %s, want inconclusive with no default route", c.Status)
	}
	if c.Confidence != model.ConfidenceLow {
		t.Errorf("Confidence = %s, want low with no default route", c.Confidence)
	}
}

func TestProxySystemCheckReportsEnabled(t *testing.T) {
	a := fakeAdapter{proxy: platform.ProxyConfig{Enabled: true, HTTPProxy: "http://proxy:8080"}}
	c := NewProxySystemCheck(testDef("local.proxy_system")).Run(context.Background(), checks.CheckContext{Platform: a})
	if c.Status != model.StatusAnomalous {
		t.Errorf("Status = %s, want anomalous when a system proxy is configured", c.Status)
	}
}

func TestTrustStoreCheckFindsNonPublicCA(t *testing.T) {
	a := fakeAdapter{cas: []platform.CACert{{Subject: "Acme Corp Proxy CA", Issuer: "Acme Corp Root CA", Fingerprint: "sha256:not-in-bundle"}}}
	c := NewTrustStoreCheck(testDef("local.trust_store")).Run(context.Background(), checks.CheckContext{Platform: a})
	if c.Status != model.StatusAnomalous {
		t.Errorf("Status = %s, want anomalous for a CA not in the bundled public list", c.Status)
	}
	if c.Confidence != model.ConfidenceHigh {
		t.Errorf("Confidence = %s, want high (self_evident per spec §6.1)", c.Confidence)
	}
	if err := model.ValidateCheck(c, true); err != nil {
		t.Errorf("ValidateCheck(selfEvident=true) failed: %v", err)
	}
}

func TestTrustStoreCheckAcceptsEmptyStore(t *testing.T) {
	a := fakeAdapter{cas: nil}
	c := NewTrustStoreCheck(testDef("local.trust_store")).Run(context.Background(), checks.CheckContext{Platform: a})
	if c.Status != model.StatusNormal {
		t.Errorf("Status = %s, want normal for no non-public CAs found", c.Status)
	}
}
