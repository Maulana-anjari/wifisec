//go:build linux

package platform

import "testing"

// These tests run against the real local machine — they assert the
// adapter never errors and returns internally-consistent data, not
// specific values (the CI/dev machine's actual network state is
// unknown ahead of time).

func TestLinuxNetConfigDoesNotError(t *testing.T) {
	a := New()
	cfg, err := a.NetConfig()
	if err != nil {
		t.Fatalf("NetConfig() error: %v", err)
	}
	if cfg.MTU < 0 {
		t.Errorf("MTU = %d, want >= 0", cfg.MTU)
	}
}

func TestLinuxRoutingTableDoesNotError(t *testing.T) {
	a := New()
	if _, err := a.RoutingTable(); err != nil {
		t.Fatalf("RoutingTable() error: %v", err)
	}
}

func TestLinuxProxyConfigDoesNotError(t *testing.T) {
	a := New()
	if _, err := a.ProxyConfig(); err != nil {
		t.Fatalf("ProxyConfig() error: %v", err)
	}
}

func TestLinuxTrustStoreCAsDoesNotError(t *testing.T) {
	a := New()
	cas, err := a.TrustStoreCAs()
	if err != nil {
		t.Fatalf("TrustStoreCAs() error: %v", err)
	}
	if len(cas) == 0 {
		t.Error("expected at least one CA from /etc/ssl/certs on this dev machine")
	}
	for _, c := range cas[:1] {
		if c.Subject == "" {
			t.Error("expected a non-empty Subject on the first parsed CA")
		}
	}
}

func TestLinuxWiFiInfoDoesNotError(t *testing.T) {
	a := New()
	if _, err := a.WiFiInfo(); err != nil {
		t.Fatalf("WiFiInfo() error: %v", err)
	}
}
