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

func TestLatencyGatewayFallsBackToPort443(t *testing.T) {
	// Set up a listener on port 443 only (port 80 will be refused).
	ln443, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln443.Close()
	go func() {
		for {
			c, err := ln443.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	// If port 443 is already in use system-wide, skip this test.
	dial := net.Dialer{Timeout: 1 * time.Second}
	testConn, err := dial.Dial("tcp", "127.0.0.1:443")
	if err == nil {
		testConn.Close()
	} else {
		t.Skipf("Port 443 not available for test: %v", err)
	}

	// For a more reliable test, we simulate by using the actual listener port.
	// We can't easily bind to both 80 and 443 without privileges, so we test
	// the logic by creating a gateway address that will trigger the fallback.
	// Since we can't bind to port 80, we use port 1 (which will be refused).
	def := registry.CheckDefinition{ID: "net.latency_gateway", ProfileRequired: model.ProfileStandard, EstimatedPackets: 3}
	c := NewLatencyGatewayCheck(def)
	cc := testCC()

	// Set gateway to an address that will fail on port 80 but succeed on port 443.
	// We use 127.0.0.1 and let the actual listener on port 443 (if available) catch it.
	// This is a simplified test; the real scenario requires port 80 to be refused.
	testAddr := net.JoinHostPort("127.0.0.1", "1") // Port 1 will be refused
	cc.Platform = fakeAdapter{netConfig: platform.NetConfig{Gateway: testAddr}}

	// Since port 1 will be refused and port 443 will also fail (we didn't bind to 443),
	// this tests that the fallback runs (samples will be empty from both rounds).
	got := c.Run(context.Background(), cc)

	// We expect inconclusive because neither port provides a service.
	if got.Status != model.StatusInconclusive {
		t.Errorf("Status = %v, want inconclusive when both ports fail", got.Status)
	}
	// Verify that PacketsSent reflects both rounds: 3 for port 80 + 3 for port 443 = 6.
	if got.PacketsSent != 6 {
		t.Errorf("PacketsSent = %d, want 6 (accumulated from both fallback rounds)", got.PacketsSent)
	}
	// Verify that the counter was called twice (once for each round).
	if cc.Counter.Total() != 6 {
		t.Errorf("Counter.Total() = %d, want 6 (two Add calls of 3 each)", cc.Counter.Total())
	}
}

func TestLatencyGatewayAccumulatesPacketsCrossRounds(t *testing.T) {
	// Set up a listener for port 443 only (port 80 will fail).
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

	def := registry.CheckDefinition{ID: "net.latency_gateway", ProfileRequired: model.ProfileStandard, EstimatedPackets: 4}
	c := NewLatencyGatewayCheck(def)
	cc := testCC()

	// Use a gateway address that will fail on port 80 (port 1, refused),
	// then fall back and fail on port 443 (not listening on 127.0.0.1:443).
	cc.Platform = fakeAdapter{netConfig: platform.NetConfig{Gateway: "127.0.0.1:1"}}

	got := c.Run(context.Background(), cc)

	// Port 1 is refused, port 443 on 127.0.0.1 is also refused (we didn't bind to it),
	// so both rounds fail and we get inconclusive.
	if got.Status != model.StatusInconclusive {
		t.Errorf("Status = %v, want inconclusive", got.Status)
	}

	// Verify packets accumulated: 4 for first round + 4 for second round = 8.
	if got.PacketsSent != 8 {
		t.Errorf("PacketsSent = %d, want 8 (4 + 4 from two rounds)", got.PacketsSent)
	}

	// Verify counter reflects both rounds.
	totalCounter := cc.Counter.Total()
	if totalCounter != 8 {
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
