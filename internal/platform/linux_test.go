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
		t.Fatal("expected at least one CA from /etc/ssl/certs on this dev machine")
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

// firstField backs the FREQ/RATE parsing in WiFiInfo. nmcli can report
// those fields as empty for some driver/entry states (e.g. a hidden or
// transiently-unassociated network); firstField must not panic on that,
// so strconv.Atoi can fail gracefully instead of indexing an empty slice.
func TestFirstField(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"normal", "2412 MHz", "2412"},
		{"empty", "", ""},
		{"whitespace only", "   ", ""},
		{"no unit suffix", "130", "130"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := firstField(c.in); got != c.want {
				t.Errorf("firstField(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}
