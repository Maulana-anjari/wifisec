package net

import (
	"context"
	"net"
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

func testCC() checks.CheckContext {
	return checks.CheckContext{Counter: guard.NewPacketCounter(1000), Timeout: 5 * time.Second}
}

func TestSampleTCPCountsSuccessesAndFailures(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	samples, sent, lost := sampleTCP(context.Background(), ln.Addr().String(), 5, time.Second)
	if sent != 5 {
		t.Errorf("sent = %d, want 5", sent)
	}
	if lost != 0 {
		t.Errorf("lost = %d, want 0", lost)
	}
	if len(samples) != 5 {
		t.Errorf("len(samples) = %d, want 5", len(samples))
	}
}

func TestSampleTCPUnreachableCountsAllLost(t *testing.T) {
	// Port 1 on loopback: nothing listens there, connection refused fast.
	_, sent, lost := sampleTCP(context.Background(), "127.0.0.1:1", 3, 200*time.Millisecond)
	if sent != 3 {
		t.Errorf("sent = %d, want 3", sent)
	}
	if lost != 3 {
		t.Errorf("lost = %d, want 3 (nothing listening)", lost)
	}
}

func TestLatencyGatewayInconclusiveWhenNoRoute(t *testing.T) {
	def := registry.CheckDefinition{ID: "net.latency_gateway", ProfileRequired: model.ProfileStandard}
	c := NewLatencyGatewayCheck(def)
	cc := testCC()
	cc.Platform = fakeAdapter{netConfig: platform.NetConfig{Gateway: ""}}
	got := c.Run(context.Background(), cc)
	if got.Status != model.StatusInconclusive {
		t.Errorf("Status = %v, want inconclusive when Gateway is empty", got.Status)
	}
}

func TestLatencyInternetReachesRealTarget(t *testing.T) {
	def := registry.CheckDefinition{ID: "net.latency_internet", ProfileRequired: model.ProfileStandard, EstimatedPackets: 10}
	c := NewLatencyInternetCheck(def)
	cc := testCC()
	cc.Platform = fakeAdapter{}
	got := c.Run(context.Background(), cc)
	if got.Status != model.StatusNormal {
		t.Errorf("Status = %v, want normal (example.com:443 must be reachable)", got.Status)
	}
	samples, ok := got.Observed["rtt_samples_ms"].([]float64)
	if !ok || len(samples) == 0 {
		t.Errorf("Observed[rtt_samples_ms] missing or empty: %#v", got.Observed["rtt_samples_ms"])
	}
	if got.PacketsSent != 10 {
		t.Errorf("PacketsSent = %d, want 10", got.PacketsSent)
	}
}

func TestIPv6CheckDoesNotErrorWhenAAAAAbsent(t *testing.T) {
	def := registry.CheckDefinition{ID: "net.ipv6", ProfileRequired: model.ProfileStandard, EstimatedPackets: 2}
	c := NewIPv6Check(def)
	cc := testCC()
	cc.Platform = fakeAdapter{}
	got := c.Run(context.Background(), cc)
	if got.Status == model.StatusError {
		t.Errorf("Status = error, want normal regardless of actual IPv6 availability: %s", got.Error)
	}
	if _, ok := got.Observed["ipv6_available"].(bool); !ok {
		t.Errorf("Observed[ipv6_available] missing or not a bool: %#v", got.Observed)
	}
}

// TestLatencyGatewayAccumulatesPacketsCrossRounds exercises the real
// port-80-then-443 fallback in latency.go: cfg.Gateway is a bare host
// (net.JoinHostPort builds "127.0.0.1:80" and "127.0.0.1:443" from it,
// per Fix 1 — a plain string-concat would have produced the malformed,
// parse-time-failing "127.0.0.1:80:80"). Both are privileged ports this
// unprivileged test process cannot itself be listening on, so both
// rounds are genuinely refused, the fallback genuinely fires, and we
// can assert packets/samples accumulate across both rounds rather than
// resetting.
func TestLatencyGatewayAccumulatesPacketsCrossRounds(t *testing.T) {
	def := registry.CheckDefinition{ID: "net.latency_gateway", ProfileRequired: model.ProfileStandard, EstimatedPackets: 4}
	c := NewLatencyGatewayCheck(def)
	cc := testCC()

	cc.Platform = fakeAdapter{netConfig: platform.NetConfig{Gateway: "127.0.0.1"}}

	got := c.Run(context.Background(), cc)

	// Nothing listens on 127.0.0.1:80 or 127.0.0.1:443 in the test
	// environment, so both rounds fail and the check is inconclusive.
	if got.Status != model.StatusInconclusive {
		t.Errorf("Status = %v, want inconclusive when both ports fail", got.Status)
	}

	// Verify packets accumulated: 4 for the port-80 round + 4 for the
	// port-443 fallback round = 8, not reset to 4.
	if got.PacketsSent != 8 {
		t.Errorf("PacketsSent = %d, want 8 (4 + 4 from two fallback rounds)", got.PacketsSent)
	}

	// The counter must reflect both Counter.Add calls (one per round),
	// which is exactly why net.latency_gateway reserves double its
	// registry EstimatedPackets in the worst case (see
	// TestStandardProfileBudgetCoversRealWorstCaseDemand).
	if totalCounter := cc.Counter.Total(); totalCounter != 8 {
		t.Errorf("Counter.Total() = %d, want 8", totalCounter)
	}
}

func TestCaptivePortalCleanNetworkIsNormal(t *testing.T) {
	def := registry.CheckDefinition{ID: "net.captive_portal", ProfileRequired: model.ProfileStandard, EstimatedPackets: 2}
	c := NewCaptivePortalCheck(def)
	cc := testCC()
	got := c.Run(context.Background(), cc)
	if got.Status != model.StatusNormal {
		t.Errorf("Status = %v, want normal on a clean network (example.com must be reachable): %#v", got.Status, got.Observed)
	}
}

func TestBufferbloatDoesNotError(t *testing.T) {
	def := registry.CheckDefinition{ID: "net.bufferbloat", ProfileRequired: model.ProfileStandard, EstimatedPackets: 20}
	c := NewBufferbloatCheck(def)
	cc := testCC()
	got := c.Run(context.Background(), cc)
	if got.Status == model.StatusError {
		t.Errorf("Status = error: %s", got.Error)
	}
}
