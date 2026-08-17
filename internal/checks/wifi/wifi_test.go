package wifi

import (
	"context"
	"testing"

	"github.com/Maulana-anjari/wifisec/internal/checks"
	"github.com/Maulana-anjari/wifisec/internal/model"
	"github.com/Maulana-anjari/wifisec/internal/platform"
	"github.com/Maulana-anjari/wifisec/internal/registry"
)

type fakeAdapter struct{ info platform.WiFiInfo }

func (f fakeAdapter) WiFiInfo() (platform.WiFiInfo, error)       { return f.info, nil }
func (f fakeAdapter) NetConfig() (platform.NetConfig, error)     { return platform.NetConfig{}, nil }
func (f fakeAdapter) ProxyConfig() (platform.ProxyConfig, error) { return platform.ProxyConfig{}, nil }
func (f fakeAdapter) TrustStoreCAs() ([]platform.CACert, error)  { return nil, nil }
func (f fakeAdapter) RoutingTable() ([]platform.Route, error)    { return nil, nil }

func testDef(id string) registry.CheckDefinition {
	return registry.CheckDefinition{ID: id, Layer: model.LayerWiFi, Title: id, ProfileRequired: model.ProfilePassive}
}

func TestSecurityCheckFlagsOpenNetwork(t *testing.T) {
	a := fakeAdapter{info: platform.WiFiInfo{Available: true, Security: "open"}}
	c := NewSecurityCheck(testDef("wifi.security")).Run(context.Background(), checks.CheckContext{Platform: a})
	if c.Status != model.StatusAnomalous {
		t.Errorf("Status = %s, want anomalous for open network", c.Status)
	}
}

func TestSecurityCheckAcceptsWPA3(t *testing.T) {
	a := fakeAdapter{info: platform.WiFiInfo{Available: true, Security: "WPA3"}}
	c := NewSecurityCheck(testDef("wifi.security")).Run(context.Background(), checks.CheckContext{Platform: a})
	if c.Status != model.StatusNormal {
		t.Errorf("Status = %s, want normal for WPA3", c.Status)
	}
}

func TestSecurityCheckInconclusiveWhenWiFiUnavailable(t *testing.T) {
	a := fakeAdapter{info: platform.WiFiInfo{Available: false, Reason: "not connected"}}
	c := NewSecurityCheck(testDef("wifi.security")).Run(context.Background(), checks.CheckContext{Platform: a})
	if c.Status != model.StatusInconclusive {
		t.Errorf("Status = %s, want inconclusive when WiFi is unavailable", c.Status)
	}
}

func TestPMFCheckReportsUnknownWhenEmpty(t *testing.T) {
	a := fakeAdapter{info: platform.WiFiInfo{Available: true, PMF: ""}}
	c := NewPMFCheck(testDef("wifi.pmf")).Run(context.Background(), checks.CheckContext{Platform: a})
	if c.Status != model.StatusInconclusive {
		t.Errorf("Status = %s, want inconclusive when PMF is not exposed by the platform", c.Status)
	}
}

func TestSignalCheckReportsRSSI(t *testing.T) {
	a := fakeAdapter{info: platform.WiFiInfo{Available: true, RSSI: -45}}
	c := NewSignalCheck(testDef("wifi.signal")).Run(context.Background(), checks.CheckContext{Platform: a})
	if c.Observed["rssi"] != -45 {
		t.Errorf("Observed[rssi] = %v, want -45", c.Observed["rssi"])
	}
}

func TestChannelCheckReportsBand(t *testing.T) {
	a := fakeAdapter{info: platform.WiFiInfo{Available: true, Channel: 149, Band: "5GHz"}}
	c := NewChannelCheck(testDef("wifi.channel")).Run(context.Background(), checks.CheckContext{Platform: a})
	if c.Observed["band"] != "5GHz" {
		t.Errorf("Observed[band] = %v, want 5GHz", c.Observed["band"])
	}
}

func TestBSSIDVendorCheckExtractsOUI(t *testing.T) {
	a := fakeAdapter{info: platform.WiFiInfo{Available: true, BSSID: "90:9A:4A:23:F9:92"}}
	c := NewBSSIDVendorCheck(testDef("wifi.bssid_vendor")).Run(context.Background(), checks.CheckContext{Platform: a})
	if c.Observed["oui"] != "90:9A:4A" {
		t.Errorf("Observed[oui] = %v, want 90:9A:4A", c.Observed["oui"])
	}
}

func TestLinkSpeedCheckReportsMbps(t *testing.T) {
	a := fakeAdapter{info: platform.WiFiInfo{Available: true, LinkSpeed: 270}}
	c := NewLinkSpeedCheck(testDef("wifi.link_speed")).Run(context.Background(), checks.CheckContext{Platform: a})
	if c.Observed["mbps"] != 270 {
		t.Errorf("Observed[mbps] = %v, want 270", c.Observed["mbps"])
	}
}
