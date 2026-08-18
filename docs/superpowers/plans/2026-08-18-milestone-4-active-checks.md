# Milestone 4 — Active Checks (minimal + standard) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement every `minimal`- and `standard`-profile check from spec §6.2/§6.3 (11 checks total), wire them into `cmd/wifisec`, add the missing interpret rules that depend on them, and prove captive-portal detection has no false positive on a real network (M4's spec §11 completion criterion).

**Architecture:** Three new `internal/checks/*` packages (`dns`, `tls`, `net`), mirroring the existing `local`/`wifi` package pattern exactly (one `Checker` type per check ID, `NewXCheck(def) checks.Checker` constructor, `Definition()`/`Run()` methods). Two cross-cutting pieces of new orchestration machinery live in `internal/checks` itself, generic and independently testable: `RunGated` (captive-portal-gates-the-rest-of-standard, spec §6.3) and `DeriveLatencyChecks` (jitter/packet_loss computed from `net.latency_internet`'s samples with **zero** additional packets, spec §6.3 table). `cmd/wifisec/main.go` wires all of this together and fixes a real pre-existing budget bug (see Global Constraints).

**Tech Stack:** Go stdlib (`net`, `net/http`, `crypto/tls`, `encoding/json`), `github.com/miekg/dns` (new dependency — pre-approved, spec §3.3, "precise DNS query control").

**Spec:** `/home/maul/Kerjaan/personal-project/wifisec/SPEC-wifisec.md` — this plan implements §6.2, §6.3, and the seven still-missing rules from §7.2. §6.4 (`full` profile) is explicitly **out of scope**: spec §11 says "Profil `full` menyusul" (follows later) and M4's own completion criterion only names captive-portal detection.

## Global Constraints

- **Control domain: `example.com`.** User-approved (not guessed — spec §13 required asking). Used by `dns.resolve_basic`, `tls.cert_issuer`, `dns.compare_doh`, `net.latency_internet`, `net.captive_portal`. IANA-managed, extremely stable, plain HTTP on port 80 serves 200 OK directly (no forced HTTPS redirect), so it also works as the captive-portal probe target.
- **DoH resolver: Cloudflare (`https://cloudflare-dns.com/dns-query`), JSON format (`Accept: application/dns-json`).** Used by `dns.compare_doh` and `dns.transparent_proxy`.
- **Direct-resolver probe target for `dns.transparent_proxy`: `1.1.1.1:53`** (Cloudflare, same operator as the DoH endpoint above — makes the two answers a valid apples-to-apples comparison).
- **No ICMP.** CLAUDE.md forbids adding third-party ICMP libraries, and raw ICMP sockets need root on most systems. Every latency measurement in this plan uses **TCP connect-time RTT** instead (`net.DialTimeout`, timed by hand) — zero privilege, zero new dependency.
- **Zero enumeration of other devices, zero spoofed headers, zero credential storage.** Every check in this plan talks to either (a) the current machine's own configured gateway/DNS server, or (b) a fixed, well-known third-party server (`example.com`, `1.1.1.1`, `cloudflare-dns.com`) that any browser talks to routinely — never to other devices on the local network. This is ordinary client traffic, not the scanning/enumeration/security-testing CLAUDE.md §0.1 prohibits.
- **Packet budget bug (pre-flight fix, Task 7):** `internal/model/profile.go`'s `estimatedPackets[ProfileStandard]` is currently `50` — the sum of the 7 non-zero rows in spec §6.3's own table (2+10+10+4+2+20+2=50). But `guard.NewPacketCounter(effective.EstimatedPackets())` in `main.go` is the **real runtime limit**, and `registry.Filter(ProfileStandard)` also returns the 2 `minimal`-tier checks (spec §4.1: profiles are cumulative), which **also** call `Counter.Add` for real when they run at `effective == standard`. Real total demand is therefore 52, not 50 — the last standard-tier check to grab counter budget would spuriously fail with `StatusError` on a clean network purely from this off-by-2, which is a real bug, not a hypothetical. Task 7 fixes `estimatedPackets[ProfileStandard]` to `52`.
- **`model.Check.Observed` keys must never contain `blocked`, `dangerous`, or `unsafe`** (substring match, `model.ValidateCheck`, P2). Every Observed key chosen below avoids these.
- **`Status == StatusAnomalous` with `Control.Performed == false` requires `Confidence != ConfidenceHigh`** unless the check is `self_evident` in the registry (spec §4.2). None of this milestone's checks are marked `self_evident` — every one that can report `Anomalous` performs a real control comparison (`Control.Performed: true`) first, so this rule is satisfied structurally, not by confidence-capping.
- Every checker follows the existing `local`/`wifi` package shape exactly: `type XCheck struct{ def registry.CheckDefinition }`, `func NewXCheck(def registry.CheckDefinition) checks.Checker { return XCheck{def} }`, `func (c XCheck) Definition() registry.CheckDefinition { return c.def }`, `func (c XCheck) Run(ctx context.Context, cc checks.CheckContext) model.Check`.
- Every checker that sends anything over the network calls `cc.Counter.Add(c.def.ID, n)` **before** sending, and returns `checks.NewErrorCheck(c.def, err, start)` if `Add` itself errors (budget exceeded) — same pattern T3/`counter_integration_test.go` already exercises.

---

### Task 1: `internal/checks/net` — TCP RTT sampler + `net.latency_gateway` + `net.latency_internet` + `net.ipv6`

**Files:**
- Create: `internal/checks/net/sample.go`
- Create: `internal/checks/net/latency.go`
- Create: `internal/checks/net/ipv6.go`
- Create: `internal/checks/net/net_test.go`

**Interfaces:**
- Consumes: `checks.Checker`, `checks.CheckContext`, `checks.NewErrorCheck` (`internal/checks`); `registry.CheckDefinition` (`internal/registry`); `model.Check`/`model.Status*`/`model.Confidence*` (`internal/model`).
- Produces: `func NewLatencyGatewayCheck(def registry.CheckDefinition) checks.Checker`, `func NewLatencyInternetCheck(def registry.CheckDefinition) checks.Checker`, `func NewIPv6Check(def registry.CheckDefinition) checks.Checker`. Also `func sampleTCP(ctx context.Context, addr string, n int, perDialTimeout time.Duration) (samples []time.Duration, sent, lost int)` (unexported). `net.latency_internet`'s `Check.Observed` MUST contain keys `rtt_samples_ms []float64`, `sent int`, `lost int` exactly — Task 3's `DeriveLatencyChecks` reads these three keys back out of the returned `model.Check.Observed` map.

- [ ] **Step 1: Write the failing tests**

```go
// internal/checks/net/net_test.go
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/checks/net/... -run . -v`
Expected: FAIL — package `internal/checks/net` doesn't exist yet (compile error: `undefined: sampleTCP`, `NewLatencyGatewayCheck`, etc).

- [ ] **Step 3: Implement `sample.go`**

```go
// internal/checks/net/sample.go

// Package net implements the wifisec "net" and "perf"-layer active
// checks (spec §6.3): TCP-RTT-based latency/jitter/packet-loss,
// captive-portal detection, bufferbloat, and IPv6 reachability.
//
// No ICMP: CLAUDE.md forbids adding a third-party ICMP library, and raw
// ICMP sockets need root on most systems this tool targets. Every
// latency measurement here uses TCP connect-time instead — dial, time
// how long the handshake takes, close. Cheap, privilege-free, and
// "packet" (in the guard.PacketCounter sense) maps 1:1 to one dial
// attempt.
package net

import (
	stdcontext "context"
	"net"
	"time"
)

// sampleTCP dials addr n times sequentially (a small gap between
// attempts avoids a connection burst that could look like a port
// scan), and returns each successful dial's connect duration plus how
// many attempts succeeded/failed. A failed dial (refused, timeout,
// no route) counts toward lost, not toward samples — there is no RTT
// for a connection that never completed.
func sampleTCP(ctx stdcontext.Context, addr string, n int, perDialTimeout time.Duration) (samples []time.Duration, sent, lost int) {
	dialer := net.Dialer{Timeout: perDialTimeout}
	for i := 0; i < n; i++ {
		sent++
		start := time.Now()
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			lost++
		} else {
			samples = append(samples, time.Since(start))
			conn.Close()
		}
		if i < n-1 {
			select {
			case <-ctx.Done():
				return samples, sent, lost
			case <-time.After(50 * time.Millisecond):
			}
		}
	}
	return samples, sent, lost
}

func msFloats(d []time.Duration) []float64 {
	out := make([]float64, len(d))
	for i, v := range d {
		out[i] = float64(v.Microseconds()) / 1000.0
	}
	return out
}

func meanMS(samples []float64) float64 {
	if len(samples) == 0 {
		return 0
	}
	var sum float64
	for _, s := range samples {
		sum += s
	}
	return sum / float64(len(samples))
}
```

- [ ] **Step 4: Implement `latency.go`**

```go
// internal/checks/net/latency.go
package net

import (
	stdcontext "context"
	"time"

	"github.com/Maulana-anjari/wifisec/internal/checks"
	"github.com/Maulana-anjari/wifisec/internal/model"
	"github.com/Maulana-anjari/wifisec/internal/registry"
)

// internetTarget is the control domain approved for M4 (see plan
// Global Constraints — spec §13 required asking, not guessing).
const internetTarget = "example.com:443"

type LatencyGatewayCheck struct{ def registry.CheckDefinition }

func NewLatencyGatewayCheck(def registry.CheckDefinition) checks.Checker { return LatencyGatewayCheck{def} }
func (c LatencyGatewayCheck) Definition() registry.CheckDefinition       { return c.def }

func (c LatencyGatewayCheck) Run(ctx stdcontext.Context, cc checks.CheckContext) model.Check {
	start := time.Now()
	cfg, err := cc.Platform.NetConfig()
	if err != nil {
		return checks.NewErrorCheck(c.def, err, start)
	}
	if cfg.Gateway == "" {
		return model.Check{
			ID: c.def.ID, Layer: c.def.Layer, Title: c.def.Title, ProfileRequired: c.def.ProfileRequired,
			Status: model.StatusInconclusive, Confidence: model.ConfidenceLow,
			Control:    model.Control{Performed: false, Reason: "no_default_route"},
			DurationMS: time.Since(start).Milliseconds(),
		}
	}
	if err := cc.Counter.Add(c.def.ID, c.def.EstimatedPackets); err != nil {
		return checks.NewErrorCheck(c.def, err, start)
	}
	// Most consumer APs don't expose a web UI on the LAN side of every
	// port; try 80 first, fall back to 443. Neither responding cleanly
	// means "no TCP service to time against", not "gateway unreachable"
	// — the gateway answered ARP/routing just fine, it's just not
	// listening on either port. That's an honest inconclusive, not an
	// error (spec P3).
	samples, sent, lost := sampleTCP(ctx, cfg.Gateway+":80", c.def.EstimatedPackets, 2*time.Second)
	if len(samples) == 0 {
		samples, sent, lost = sampleTCP(ctx, cfg.Gateway+":443", c.def.EstimatedPackets, 2*time.Second)
	}
	if len(samples) == 0 {
		return model.Check{
			ID: c.def.ID, Layer: c.def.Layer, Title: c.def.Title, ProfileRequired: c.def.ProfileRequired,
			Status: model.StatusInconclusive, Confidence: model.ConfidenceLow,
			Observed:    map[string]any{"gateway": cfg.Gateway},
			Control:     model.Control{Performed: false, Reason: "gateway_no_tcp_service"},
			PacketsSent: sent, DurationMS: time.Since(start).Milliseconds(),
		}
	}
	msSamples := msFloats(samples)
	return model.Check{
		ID: c.def.ID, Layer: c.def.Layer, Title: c.def.Title, ProfileRequired: c.def.ProfileRequired,
		Status: model.StatusNormal, Confidence: model.ConfidenceMedium,
		Observed:    map[string]any{"rtt_samples_ms": msSamples, "sent": sent, "lost": lost, "mean_ms": meanMS(msSamples)},
		Control:     model.Control{Performed: false},
		PacketsSent: sent, DurationMS: time.Since(start).Milliseconds(),
	}
}

type LatencyInternetCheck struct{ def registry.CheckDefinition }

func NewLatencyInternetCheck(def registry.CheckDefinition) checks.Checker { return LatencyInternetCheck{def} }
func (c LatencyInternetCheck) Definition() registry.CheckDefinition       { return c.def }

func (c LatencyInternetCheck) Run(ctx stdcontext.Context, cc checks.CheckContext) model.Check {
	start := time.Now()
	if err := cc.Counter.Add(c.def.ID, c.def.EstimatedPackets); err != nil {
		return checks.NewErrorCheck(c.def, err, start)
	}
	samples, sent, lost := sampleTCP(ctx, internetTarget, c.def.EstimatedPackets, 3*time.Second)
	if len(samples) == 0 {
		return model.Check{
			ID: c.def.ID, Layer: c.def.Layer, Title: c.def.Title, ProfileRequired: c.def.ProfileRequired,
			Status: model.StatusInconclusive, Confidence: model.ConfidenceLow,
			Observed:    map[string]any{"target": internetTarget, "sent": sent, "lost": lost},
			Control:     model.Control{Performed: false, Reason: "internet_unreachable"},
			PacketsSent: sent, DurationMS: time.Since(start).Milliseconds(),
		}
	}
	msSamples := msFloats(samples)
	return model.Check{
		ID: c.def.ID, Layer: c.def.Layer, Title: c.def.Title, ProfileRequired: c.def.ProfileRequired,
		Status: model.StatusNormal, Confidence: model.ConfidenceMedium,
		Observed:    map[string]any{"rtt_samples_ms": msSamples, "sent": sent, "lost": lost, "mean_ms": meanMS(msSamples), "target": internetTarget},
		Control:     model.Control{Performed: false},
		PacketsSent: sent, DurationMS: time.Since(start).Milliseconds(),
	}
}
```

- [ ] **Step 5: Implement `ipv6.go`**

```go
// internal/checks/net/ipv6.go
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
	ips, err := resolver.LookupIP(ctx, "ip6", "example.com")
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
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `go test ./internal/checks/net/... -race -v`
Expected: PASS (note: `TestLatencyInternetReachesRealTarget` and `TestIPv6CheckDoesNotErrorWhenAAAAAbsent` need real internet access — same category as `local.trust_store`'s embedded-bundle tests, but this is the first milestone with a genuinely network-dependent test; if the sandbox has no route, this test failing is expected and not a code bug).

- [ ] **Step 7: Commit**

```bash
git add internal/checks/net/sample.go internal/checks/net/latency.go internal/checks/net/ipv6.go internal/checks/net/net_test.go
git commit -m "feat(checks/net): TCP-RTT sampler, net.latency_gateway, net.latency_internet, net.ipv6"
```

---

### Task 2: `internal/checks` — `RunGated` orchestration + `internal/checks/net` — `net.captive_portal`

**Files:**
- Create: `internal/checks/gate.go`
- Create: `internal/checks/gate_test.go`
- Create: `internal/checks/net/captive_portal.go`
- Modify: `internal/checks/net/net_test.go` (add captive-portal test)

**Interfaces:**
- Consumes: `checks.Checker`, `checks.CheckContext`, `model.Check`, `model.StatusAnomalous`/`StatusInconclusive`.
- Produces: `func RunGated(ctx context.Context, checkers []Checker, cc CheckContext, gateID string, isTripped func(model.Check) bool, gatedReason string) <-chan model.Check` in package `checks` (lives here, not in `net`, because it's generic orchestration over the `Checker` interface with no dependency on any concrete check package — same reasoning as `Run` itself). `func NewCaptivePortalCheck(def registry.CheckDefinition) checks.Checker` in package `net`.

- [ ] **Step 1: Write the failing tests**

```go
// internal/checks/gate_test.go
package checks

import (
	"context"
	"testing"
	"time"

	"github.com/Maulana-anjari/wifisec/internal/guard"
	"github.com/Maulana-anjari/wifisec/internal/model"
	"github.com/Maulana-anjari/wifisec/internal/registry"
)

type stubChecker struct {
	def registry.CheckDefinition
	run func(ctx context.Context, cc CheckContext) model.Check
}

func (s stubChecker) Definition() registry.CheckDefinition                 { return s.def }
func (s stubChecker) Run(ctx context.Context, cc CheckContext) model.Check { return s.run(ctx, cc) }

func normalCheck(id string) func(context.Context, CheckContext) model.Check {
	return func(context.Context, CheckContext) model.Check {
		return model.Check{ID: id, Status: model.StatusNormal, Confidence: model.ConfidenceMedium}
	}
}

func TestRunGatedRunsEverythingWhenGateClean(t *testing.T) {
	gate := stubChecker{def: registry.CheckDefinition{ID: "gate"}, run: normalCheck("gate")}
	other := stubChecker{def: registry.CheckDefinition{ID: "other"}, run: normalCheck("other")}
	cc := CheckContext{Counter: guard.NewPacketCounter(100), Timeout: time.Second}

	var got []model.Check
	for c := range RunGated(context.Background(), []Checker{gate, other}, cc, "gate",
		func(c model.Check) bool { return c.Status == model.StatusAnomalous }, "gate_tripped") {
		got = append(got, c)
	}
	if len(got) != 2 {
		t.Fatalf("got %d checks, want 2", len(got))
	}
	for _, c := range got {
		if c.Status != model.StatusNormal {
			t.Errorf("check %s: Status = %v, want normal (gate was clean)", c.ID, c.Status)
		}
	}
}

func TestRunGatedShortCircuitsWhenGateTrips(t *testing.T) {
	gate := stubChecker{def: registry.CheckDefinition{ID: "gate"}, run: func(context.Context, CheckContext) model.Check {
		return model.Check{ID: "gate", Status: model.StatusAnomalous, Confidence: model.ConfidenceHigh, Control: model.Control{Performed: true}}
	}}
	other := stubChecker{def: registry.CheckDefinition{ID: "other", Layer: model.LayerPerf, Title: "Other"}, run: func(context.Context, CheckContext) model.Check {
		t.Error("other checker's Run must not be called when the gate trips")
		return model.Check{}
	}}
	cc := CheckContext{Counter: guard.NewPacketCounter(100), Timeout: time.Second}

	var got []model.Check
	for c := range RunGated(context.Background(), []Checker{gate, other}, cc, "gate",
		func(c model.Check) bool { return c.Status == model.StatusAnomalous }, "gate_tripped") {
		got = append(got, c)
	}
	if len(got) != 2 {
		t.Fatalf("got %d checks, want 2", len(got))
	}
	for _, c := range got {
		if c.ID == "other" {
			if c.Status != model.StatusInconclusive {
				t.Errorf("other.Status = %v, want inconclusive", c.Status)
			}
			if c.Control.Reason != "gate_tripped" {
				t.Errorf("other.Control.Reason = %q, want %q", c.Control.Reason, "gate_tripped")
			}
			if c.PacketsSent != 0 {
				t.Errorf("other.PacketsSent = %d, want 0 (never ran)", c.PacketsSent)
			}
		}
	}
}
```

```go
// internal/checks/net/net_test.go — append
func TestCaptivePortalCleanNetworkIsNormal(t *testing.T) {
	def := registry.CheckDefinition{ID: "net.captive_portal", ProfileRequired: model.ProfileStandard, EstimatedPackets: 2}
	c := NewCaptivePortalCheck(def)
	cc := testCC()
	got := c.Run(context.Background(), cc)
	if got.Status != model.StatusNormal {
		t.Errorf("Status = %v, want normal on a clean network (example.com must be reachable): %#v", got.Status, got.Observed)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/checks/... -run . -v`
Expected: FAIL — `RunGated` and `NewCaptivePortalCheck` undefined.

- [ ] **Step 3: Implement `internal/checks/gate.go`**

```go
// internal/checks/gate.go
package checks

import (
	"context"

	"github.com/Maulana-anjari/wifisec/internal/model"
)

// RunGated runs gateID's checker first, synchronously, and waits for
// it to finish before anything else starts. If isTripped(gateResult)
// is true, every other checker is short-circuited to
// StatusInconclusive (Control.Reason: gatedReason) instead of
// actually running — spec §6.3: "net.captive_portal harus berjalan
// dan selesai sebelum check lain di profil ini. Jika portal
// terdeteksi, seluruh check lain berstatus inconclusive." If gateID
// is not present in checkers, RunGated behaves exactly like Run.
func RunGated(ctx context.Context, checkers []Checker, cc CheckContext, gateID string, isTripped func(model.Check) bool, gatedReason string) <-chan model.Check {
	var gate Checker
	rest := make([]Checker, 0, len(checkers))
	for _, c := range checkers {
		if c.Definition().ID == gateID {
			gate = c
			continue
		}
		rest = append(rest, c)
	}
	if gate == nil {
		return Run(ctx, checkers, cc)
	}

	out := make(chan model.Check)
	go func() {
		defer close(out)
		gateResult := gate.Run(ctx, cc)
		out <- gateResult
		if isTripped(gateResult) {
			for _, c := range rest {
				def := c.Definition()
				out <- model.Check{
					ID: def.ID, Layer: def.Layer, Title: def.Title, ProfileRequired: def.ProfileRequired,
					Status: model.StatusInconclusive, Confidence: model.ConfidenceLow,
					Control: model.Control{Performed: false, Reason: gatedReason},
				}
			}
			return
		}
		for c := range Run(ctx, rest, cc) {
			out <- c
		}
	}()
	return out
}
```

- [ ] **Step 4: Implement `internal/checks/net/captive_portal.go`**

```go
// internal/checks/net/captive_portal.go
package net

import (
	stdcontext "context"
	"io"
	stdhttp "net/http"
	"strings"
	"time"

	"github.com/Maulana-anjari/wifisec/internal/checks"
	"github.com/Maulana-anjari/wifisec/internal/model"
	"github.com/Maulana-anjari/wifisec/internal/registry"
)

const (
	captivePortalURL    = "http://example.com/"
	captivePortalMarker = "Example Domain"
)

type CaptivePortalCheck struct{ def registry.CheckDefinition }

func NewCaptivePortalCheck(def registry.CheckDefinition) checks.Checker { return CaptivePortalCheck{def} }
func (c CaptivePortalCheck) Definition() registry.CheckDefinition       { return c.def }

// Run fetches the control domain over plain HTTP with redirects
// disabled: a captive portal typically either 30x-redirects the
// request elsewhere or serves its own login page instead of the real
// site (spec §6.3, "net.captive_portal"). A clean network gets a 200
// with the expected page content.
func (c CaptivePortalCheck) Run(ctx stdcontext.Context, cc checks.CheckContext) model.Check {
	start := time.Now()
	if err := cc.Counter.Add(c.def.ID, c.def.EstimatedPackets); err != nil {
		return checks.NewErrorCheck(c.def, err, start)
	}
	client := stdhttp.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *stdhttp.Request, via []*stdhttp.Request) error {
			return stdhttp.ErrUseLastResponse
		},
	}
	req, err := stdhttp.NewRequestWithContext(ctx, stdhttp.MethodGet, captivePortalURL, nil)
	if err != nil {
		return checks.NewErrorCheck(c.def, err, start)
	}
	resp, err := client.Do(req)
	if err != nil {
		return model.Check{
			ID: c.def.ID, Layer: c.def.Layer, Title: c.def.Title, ProfileRequired: c.def.ProfileRequired,
			Status: model.StatusInconclusive, Confidence: model.ConfidenceLow,
			Control:     model.Control{Performed: false, Reason: "http_unreachable"},
			PacketsSent: c.def.EstimatedPackets, DurationMS: time.Since(start).Milliseconds(),
		}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))

	redirected := resp.StatusCode >= 300 && resp.StatusCode < 400
	contentMatches := strings.Contains(string(body), captivePortalMarker)
	portalDetected := redirected || (resp.StatusCode == 200 && !contentMatches)

	observed := map[string]any{"status_code": resp.StatusCode, "portal_detected": portalDetected}
	if redirected {
		observed["redirect_location"] = resp.Header.Get("Location")
	}

	status := model.StatusNormal
	confidence := model.ConfidenceMedium
	if portalDetected {
		status = model.StatusAnomalous
		confidence = model.ConfidenceHigh
	}
	return model.Check{
		ID: c.def.ID, Layer: c.def.Layer, Title: c.def.Title, ProfileRequired: c.def.ProfileRequired,
		Status: status, Confidence: confidence,
		Observed:    observed,
		Control:     model.Control{Performed: true, Result: "compared against known example.com response"},
		PacketsSent: c.def.EstimatedPackets, DurationMS: time.Since(start).Milliseconds(),
	}
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/checks/... -race -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/checks/gate.go internal/checks/gate_test.go internal/checks/net/captive_portal.go internal/checks/net/net_test.go
git commit -m "feat(checks): RunGated orchestration; net.captive_portal check"
```

---

### Task 3: `internal/checks/net` — `net.bufferbloat` + `internal/checks` — `DeriveLatencyChecks` (jitter/packet_loss)

**Files:**
- Create: `internal/checks/net/bufferbloat.go`
- Create: `internal/checks/derive.go`
- Create: `internal/checks/derive_test.go`
- Modify: `internal/checks/net/net_test.go` (add bufferbloat test)

**Interfaces:**
- Consumes: `net.latency_internet`'s `Check.Observed["rtt_samples_ms"]`/`["sent"]`/`["lost"]` (Task 1's exact contract).
- Produces: `func DeriveLatencyChecks(latency model.Check, jitterDef, packetLossDef registry.CheckDefinition) (jitter, packetLoss model.Check)` in package `checks`. `func NewBufferbloatCheck(def registry.CheckDefinition) checks.Checker` in package `net`.

- [ ] **Step 1: Write the failing tests**

```go
// internal/checks/derive_test.go
package checks

import (
	"testing"

	"github.com/Maulana-anjari/wifisec/internal/model"
	"github.com/Maulana-anjari/wifisec/internal/registry"
)

func TestDeriveLatencyChecksNormalOnStableSamples(t *testing.T) {
	latency := model.Check{
		ID: "net.latency_internet", Status: model.StatusNormal,
		Observed: map[string]any{"rtt_samples_ms": []float64{20, 21, 19, 20, 22}, "sent": 5, "lost": 0},
	}
	jitterDef := registry.CheckDefinition{ID: "net.jitter", Layer: model.LayerPerf, Title: "Jitter"}
	lossDef := registry.CheckDefinition{ID: "net.packet_loss", Layer: model.LayerPerf, Title: "Packet loss"}

	jitter, loss := DeriveLatencyChecks(latency, jitterDef, lossDef)

	if jitter.Status != model.StatusNormal {
		t.Errorf("jitter.Status = %v, want normal for stable samples", jitter.Status)
	}
	if jitter.PacketsSent != 0 {
		t.Errorf("jitter.PacketsSent = %d, want 0 (derived, no new packets)", jitter.PacketsSent)
	}
	if loss.Status != model.StatusNormal {
		t.Errorf("loss.Status = %v, want normal for 0 lost", loss.Status)
	}
	if loss.PacketsSent != 0 {
		t.Errorf("loss.PacketsSent = %d, want 0", loss.PacketsSent)
	}
}

func TestDeriveLatencyChecksAnomalousOnHighJitterAndLoss(t *testing.T) {
	latency := model.Check{
		ID: "net.latency_internet", Status: model.StatusNormal,
		Observed: map[string]any{"rtt_samples_ms": []float64{10, 90, 15, 120, 20}, "sent": 10, "lost": 3},
	}
	jitterDef := registry.CheckDefinition{ID: "net.jitter", Layer: model.LayerPerf, Title: "Jitter"}
	lossDef := registry.CheckDefinition{ID: "net.packet_loss", Layer: model.LayerPerf, Title: "Packet loss"}

	jitter, loss := DeriveLatencyChecks(latency, jitterDef, lossDef)

	if jitter.Status != model.StatusAnomalous {
		t.Errorf("jitter.Status = %v, want anomalous for high-variance samples", jitter.Status)
	}
	if loss.Status != model.StatusAnomalous {
		t.Errorf("loss.Status = %v, want anomalous for 30%% loss", loss.Status)
	}
}

func TestDeriveLatencyChecksInconclusiveWhenLatencyInconclusive(t *testing.T) {
	latency := model.Check{ID: "net.latency_internet", Status: model.StatusInconclusive, Observed: nil}
	jitterDef := registry.CheckDefinition{ID: "net.jitter"}
	lossDef := registry.CheckDefinition{ID: "net.packet_loss"}

	jitter, loss := DeriveLatencyChecks(latency, jitterDef, lossDef)
	if jitter.Status != model.StatusInconclusive || loss.Status != model.StatusInconclusive {
		t.Errorf("want both inconclusive when source is inconclusive, got jitter=%v loss=%v", jitter.Status, loss.Status)
	}
}
```

```go
// internal/checks/net/net_test.go — append
func TestBufferbloatDoesNotError(t *testing.T) {
	def := registry.CheckDefinition{ID: "net.bufferbloat", ProfileRequired: model.ProfileStandard, EstimatedPackets: 20}
	c := NewBufferbloatCheck(def)
	cc := testCC()
	got := c.Run(context.Background(), cc)
	if got.Status == model.StatusError {
		t.Errorf("Status = error: %s", got.Error)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/checks/... -run . -v`
Expected: FAIL — `DeriveLatencyChecks`, `NewBufferbloatCheck` undefined.

- [ ] **Step 3: Implement `internal/checks/derive.go`**

```go
// internal/checks/derive.go
package checks

import (
	"math"

	"github.com/Maulana-anjari/wifisec/internal/model"
	"github.com/Maulana-anjari/wifisec/internal/registry"
)

const (
	jitterThresholdMS   = 30.0
	packetLossThreshold = 0.05 // 5%
)

// DeriveLatencyChecks computes net.jitter and net.packet_loss purely
// from net.latency_internet's already-collected samples (spec §6.3:
// both are "dari latency" — 0 additional packets). They must NOT
// re-measure the network themselves: doing so would both double the
// standard profile's real packet spend past its budget and violate
// spec §5.1 (every packet-sending check must call Counter.Add, and
// these two are specified to send none).
func DeriveLatencyChecks(latency model.Check, jitterDef, lossDef registry.CheckDefinition) (jitter, packetLoss model.Check) {
	base := func(def registry.CheckDefinition) model.Check {
		return model.Check{ID: def.ID, Layer: def.Layer, Title: def.Title, ProfileRequired: def.ProfileRequired}
	}
	if latency.Status != model.StatusNormal {
		j, l := base(jitterDef), base(lossDef)
		j.Status, l.Status = model.StatusInconclusive, model.StatusInconclusive
		j.Confidence, l.Confidence = model.ConfidenceLow, model.ConfidenceLow
		j.Control = model.Control{Performed: false, Reason: "latency_internet_" + string(latency.Status)}
		l.Control = j.Control
		return j, l
	}

	samples, _ := latency.Observed["rtt_samples_ms"].([]float64)
	sent, _ := latency.Observed["sent"].(int)
	lost, _ := latency.Observed["lost"].(int)

	j := base(jitterDef)
	stddev := stddevMS(samples)
	j.Observed = map[string]any{"stddev_ms": stddev}
	j.Control = model.Control{Performed: true, Result: "computed from net.latency_internet samples"}
	j.Confidence = model.ConfidenceMedium
	if stddev > jitterThresholdMS {
		j.Status = model.StatusAnomalous
	} else {
		j.Status = model.StatusNormal
	}

	l := base(lossDef)
	lossPct := 0.0
	if sent > 0 {
		lossPct = float64(lost) / float64(sent)
	}
	l.Observed = map[string]any{"loss_ratio": lossPct, "sent": sent, "lost": lost}
	l.Control = model.Control{Performed: true, Result: "computed from net.latency_internet samples"}
	l.Confidence = model.ConfidenceMedium
	if lossPct > packetLossThreshold {
		l.Status = model.StatusAnomalous
	} else {
		l.Status = model.StatusNormal
	}

	return j, l
}

func stddevMS(samples []float64) float64 {
	if len(samples) < 2 {
		return 0
	}
	var mean float64
	for _, s := range samples {
		mean += s
	}
	mean /= float64(len(samples))
	var variance float64
	for _, s := range samples {
		variance += (s - mean) * (s - mean)
	}
	variance /= float64(len(samples))
	return math.Sqrt(variance)
}
```

- [ ] **Step 4: Implement `internal/checks/net/bufferbloat.go`**

```go
// internal/checks/net/bufferbloat.go
package net

import (
	stdcontext "context"
	stdnet "net"
	"sync"
	"time"

	"github.com/Maulana-anjari/wifisec/internal/checks"
	"github.com/Maulana-anjari/wifisec/internal/model"
	"github.com/Maulana-anjari/wifisec/internal/registry"
)

const bufferbloatIncreaseThresholdMS = 200.0

type BufferbloatCheck struct{ def registry.CheckDefinition }

func NewBufferbloatCheck(def registry.CheckDefinition) checks.Checker { return BufferbloatCheck{def} }
func (c BufferbloatCheck) Definition() registry.CheckDefinition       { return c.def }

// Run compares idle RTT (a handful of sequential dials) against RTT
// measured while N connections fire concurrently (spec §6.3:
// "Latency saat dibebani" — latency while loaded). This deliberately
// uses connection concurrency, not a bulk data transfer, to induce
// load: generating heavy sustained traffic on someone else's network
// to test for bufferbloat would look uncomfortably close to the kind
// of traffic pattern this tool exists to avoid (CLAUDE.md's
// intrusiveness principle), and spec's own "~20 paket" budget for
// this check reads as 20 connection attempts, not a data volume.
func (c BufferbloatCheck) Run(ctx stdcontext.Context, cc checks.CheckContext) model.Check {
	start := time.Now()
	if err := cc.Counter.Add(c.def.ID, c.def.EstimatedPackets); err != nil {
		return checks.NewErrorCheck(c.def, err, start)
	}
	idleN := 5
	loadedN := c.def.EstimatedPackets - idleN
	if loadedN < 1 {
		loadedN = 1
	}

	idleSamples, _, _ := sampleTCP(ctx, internetTarget, idleN, 3*time.Second)
	loadedSamples := sampleConcurrent(ctx, internetTarget, loadedN, 3*time.Second)

	if len(idleSamples) == 0 || len(loadedSamples) == 0 {
		return model.Check{
			ID: c.def.ID, Layer: c.def.Layer, Title: c.def.Title, ProfileRequired: c.def.ProfileRequired,
			Status: model.StatusInconclusive, Confidence: model.ConfidenceLow,
			Control:     model.Control{Performed: false, Reason: "internet_unreachable"},
			PacketsSent: c.def.EstimatedPackets, DurationMS: time.Since(start).Milliseconds(),
		}
	}

	idleMean := meanMS(msFloats(idleSamples))
	loadedMean := meanMS(msFloats(loadedSamples))
	increase := loadedMean - idleMean

	status := model.StatusNormal
	if increase > bufferbloatIncreaseThresholdMS {
		status = model.StatusAnomalous
	}
	return model.Check{
		ID: c.def.ID, Layer: c.def.Layer, Title: c.def.Title, ProfileRequired: c.def.ProfileRequired,
		Status: status, Confidence: model.ConfidenceMedium,
		Observed:    map[string]any{"idle_rtt_ms": idleMean, "loaded_rtt_ms": loadedMean, "increase_ms": increase},
		Control:     model.Control{Performed: true, Result: "idle vs loaded RTT to same target"},
		PacketsSent: c.def.EstimatedPackets, DurationMS: time.Since(start).Milliseconds(),
	}
}

// sampleConcurrent dials addr n times in parallel and returns the
// connect duration of each successful dial — used to generate the
// "loaded" side of the idle-vs-loaded comparison above.
func sampleConcurrent(ctx stdcontext.Context, addr string, n int, perDialTimeout time.Duration) []time.Duration {
	dialer := stdnet.Dialer{Timeout: perDialTimeout}
	var mu sync.Mutex
	var samples []time.Duration
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			start := time.Now()
			conn, err := dialer.DialContext(ctx, "tcp", addr)
			if err == nil {
				mu.Lock()
				samples = append(samples, time.Since(start))
				mu.Unlock()
				conn.Close()
			}
		}()
	}
	wg.Wait()
	return samples
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/checks/... -race -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/checks/derive.go internal/checks/derive_test.go internal/checks/net/bufferbloat.go internal/checks/net/net_test.go
git commit -m "feat(checks): DeriveLatencyChecks (jitter/packet_loss); net.bufferbloat check"
```

---

### Task 4: `internal/checks/dns` — `dns.resolve_basic`, `dns.compare_doh`, `dns.transparent_proxy`

**Files:**
- Create: `internal/checks/dns/resolve.go`
- Create: `internal/checks/dns/doh.go`
- Create: `internal/checks/dns/compare.go`
- Create: `internal/checks/dns/transparent_proxy.go`
- Create: `internal/checks/dns/dns_test.go`
- Modify: `go.mod`, `go.sum` (add `github.com/miekg/dns`)

**Interfaces:**
- Consumes: `platform.Adapter.NetConfig().DNSServers` for the network's own resolver address.
- Produces: `func NewResolveBasicCheck(def registry.CheckDefinition) checks.Checker`, `func NewCompareDoHCheck(def registry.CheckDefinition) checks.Checker`, `func NewTransparentProxyCheck(def registry.CheckDefinition) checks.Checker`, all package `dns`.

- [ ] **Step 1: Add the dependency**

```bash
go get github.com/miekg/dns@latest
go mod tidy
```

- [ ] **Step 2: Write the failing tests**

```go
// internal/checks/dns/dns_test.go
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
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `go test ./internal/checks/dns/... -run . -v`
Expected: FAIL — package doesn't exist.

- [ ] **Step 4: Implement `resolve.go`**

```go
// internal/checks/dns/resolve.go

// Package dns implements the wifisec "dns"-layer active checks (spec
// §6.2, §6.3): a basic control-domain resolution, a network-resolver
// vs DNS-over-HTTPS comparison, and a port-53-interception probe.
// Uses github.com/miekg/dns for direct, precisely-controlled UDP
// queries (spec §3.3) instead of the OS resolver, so exactly one
// query is sent per "packet" the guard.PacketCounter accounts for.
package dns

import (
	stdcontext "context"
	"time"

	"github.com/miekg/dns"

	"github.com/Maulana-anjari/wifisec/internal/checks"
	"github.com/Maulana-anjari/wifisec/internal/model"
	"github.com/Maulana-anjari/wifisec/internal/registry"
)

// controlDomain is the M4 control domain, user-approved per spec §13
// (see plan Global Constraints — not guessed).
const controlDomain = "example.com."

// queryA sends one A-record query for controlDomain to server (host,
// no port — ":53" is appended here) and returns the resolved
// addresses as strings.
func queryA(ctx stdcontext.Context, server string) ([]string, error) {
	m := new(dns.Msg)
	m.SetQuestion(controlDomain, dns.TypeA)
	c := new(dns.Client)
	c.Timeout = 3 * time.Second
	resp, _, err := c.ExchangeContext(ctx, m, server+":53")
	if err != nil {
		return nil, err
	}
	var addrs []string
	for _, rr := range resp.Answer {
		if a, ok := rr.(*dns.A); ok {
			addrs = append(addrs, a.A.String())
		}
	}
	return addrs, nil
}

type ResolveBasicCheck struct{ def registry.CheckDefinition }

func NewResolveBasicCheck(def registry.CheckDefinition) checks.Checker { return ResolveBasicCheck{def} }
func (c ResolveBasicCheck) Definition() registry.CheckDefinition       { return c.def }

func (c ResolveBasicCheck) Run(ctx stdcontext.Context, cc checks.CheckContext) model.Check {
	start := time.Now()
	cfg, err := cc.Platform.NetConfig()
	if err != nil {
		return checks.NewErrorCheck(c.def, err, start)
	}
	if len(cfg.DNSServers) == 0 {
		return model.Check{
			ID: c.def.ID, Layer: c.def.Layer, Title: c.def.Title, ProfileRequired: c.def.ProfileRequired,
			Status: model.StatusInconclusive, Confidence: model.ConfidenceLow,
			Control:    model.Control{Performed: false, Reason: "no_dns_server_configured"},
			DurationMS: time.Since(start).Milliseconds(),
		}
	}
	if err := cc.Counter.Add(c.def.ID, c.def.EstimatedPackets); err != nil {
		return checks.NewErrorCheck(c.def, err, start)
	}
	addrs, err := queryA(ctx, cfg.DNSServers[0])
	if err != nil {
		return model.Check{
			ID: c.def.ID, Layer: c.def.Layer, Title: c.def.Title, ProfileRequired: c.def.ProfileRequired,
			Status: model.StatusInconclusive, Confidence: model.ConfidenceLow,
			Observed:    map[string]any{"resolver": cfg.DNSServers[0]},
			Control:     model.Control{Performed: false, Reason: "no_response"},
			PacketsSent: c.def.EstimatedPackets, DurationMS: time.Since(start).Milliseconds(),
		}
	}
	status := model.StatusNormal
	confidence := model.ConfidenceMedium
	if len(addrs) == 0 {
		status = model.StatusAnomalous
	}
	return model.Check{
		ID: c.def.ID, Layer: c.def.Layer, Title: c.def.Title, ProfileRequired: c.def.ProfileRequired,
		Status: status, Confidence: confidence,
		Observed:    map[string]any{"domain": controlDomain, "addresses": addrs, "resolver": cfg.DNSServers[0]},
		Control:     model.Control{Performed: false},
		PacketsSent: c.def.EstimatedPackets, DurationMS: time.Since(start).Milliseconds(),
	}
}
```

- [ ] **Step 5: Implement `doh.go`**

```go
// internal/checks/dns/doh.go
package dns

import (
	stdcontext "context"
	"encoding/json"
	stdnet "net"
	stdhttp "net/http"
	"time"
)

const dohEndpoint = "https://cloudflare-dns.com/dns-query"

type dohResponse struct {
	Answer []struct {
		Type int    `json:"type"`
		Data string `json:"data"`
	} `json:"Answer"`
}

// queryDoH resolves domain's A records via Cloudflare's DNS-over-HTTPS
// JSON API (spec §6.3 "dns.compare_doh" needs an out-of-band control
// independent of the local network's own resolver).
func queryDoH(ctx stdcontext.Context, domain string) ([]string, error) {
	req, err := stdhttp.NewRequestWithContext(ctx, stdhttp.MethodGet, dohEndpoint+"?name="+domain+"&type=A", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-json")
	client := stdhttp.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var parsed dohResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, err
	}
	var addrs []string
	for _, a := range parsed.Answer {
		if a.Type == 1 && stdnet.ParseIP(a.Data) != nil { // type 1 = A
			addrs = append(addrs, a.Data)
		}
	}
	return addrs, nil
}
```

- [ ] **Step 6: Implement `compare.go`**

```go
// internal/checks/dns/compare.go
package dns

import (
	stdcontext "context"
	"sort"
	"time"

	"github.com/Maulana-anjari/wifisec/internal/checks"
	"github.com/Maulana-anjari/wifisec/internal/model"
	"github.com/Maulana-anjari/wifisec/internal/registry"
)

func sameAddressSet(a, b []string) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	sa, sb := append([]string{}, a...), append([]string{}, b...)
	sort.Strings(sa)
	sort.Strings(sb)
	if len(sa) != len(sb) {
		return false
	}
	for i := range sa {
		if sa[i] != sb[i] {
			return false
		}
	}
	return true
}

type CompareDoHCheck struct{ def registry.CheckDefinition }

func NewCompareDoHCheck(def registry.CheckDefinition) checks.Checker { return CompareDoHCheck{def} }
func (c CompareDoHCheck) Definition() registry.CheckDefinition       { return c.def }

func (c CompareDoHCheck) Run(ctx stdcontext.Context, cc checks.CheckContext) model.Check {
	start := time.Now()
	cfg, err := cc.Platform.NetConfig()
	if err != nil || len(cfg.DNSServers) == 0 {
		return model.Check{
			ID: c.def.ID, Layer: c.def.Layer, Title: c.def.Title, ProfileRequired: c.def.ProfileRequired,
			Status: model.StatusInconclusive, Confidence: model.ConfidenceLow,
			Control:    model.Control{Performed: false, Reason: "no_dns_server_configured"},
			DurationMS: time.Since(start).Milliseconds(),
		}
	}
	if err := cc.Counter.Add(c.def.ID, c.def.EstimatedPackets); err != nil {
		return checks.NewErrorCheck(c.def, err, start)
	}
	networkAddrs, netErr := queryA(ctx, cfg.DNSServers[0])
	dohAddrs, dohErr := queryDoH(ctx, "example.com")
	if netErr != nil || dohErr != nil || len(dohAddrs) == 0 {
		return model.Check{
			ID: c.def.ID, Layer: c.def.Layer, Title: c.def.Title, ProfileRequired: c.def.ProfileRequired,
			Status: model.StatusInconclusive, Confidence: model.ConfidenceLow,
			Observed:    map[string]any{"network_addresses": networkAddrs},
			Control:     model.Control{Performed: false, Reason: "doh_unreachable"},
			PacketsSent: c.def.EstimatedPackets, DurationMS: time.Since(start).Milliseconds(),
		}
	}
	match := sameAddressSet(networkAddrs, dohAddrs)
	status := model.StatusNormal
	confidence := model.ConfidenceHigh
	if !match {
		status = model.StatusAnomalous
	}
	return model.Check{
		ID: c.def.ID, Layer: c.def.Layer, Title: c.def.Title, ProfileRequired: c.def.ProfileRequired,
		Status: status, Confidence: confidence,
		Observed:    map[string]any{"network_addresses": networkAddrs, "doh_addresses": dohAddrs, "match": match},
		Control:     model.Control{Performed: true, Result: "network resolver vs Cloudflare DoH"},
		PacketsSent: c.def.EstimatedPackets, DurationMS: time.Since(start).Milliseconds(),
	}
}
```

- [ ] **Step 7: Implement `transparent_proxy.go`**

```go
// internal/checks/dns/transparent_proxy.go
package dns

import (
	stdcontext "context"
	"time"

	"github.com/Maulana-anjari/wifisec/internal/checks"
	"github.com/Maulana-anjari/wifisec/internal/model"
	"github.com/Maulana-anjari/wifisec/internal/registry"
)

// directResolver is queried straight over UDP:53, bypassing whatever
// resolver the OS/DHCP configured, to check whether port-53 traffic
// gets rewritten regardless of destination (spec §6.3
// "dns.transparent_proxy"). Same operator as doh.go's DoH endpoint —
// a legitimate answer from 1.1.1.1 must agree with Cloudflare's DoH
// answer for the same name.
const directResolver = "1.1.1.1"

type TransparentProxyCheck struct{ def registry.CheckDefinition }

func NewTransparentProxyCheck(def registry.CheckDefinition) checks.Checker { return TransparentProxyCheck{def} }
func (c TransparentProxyCheck) Definition() registry.CheckDefinition       { return c.def }

func (c TransparentProxyCheck) Run(ctx stdcontext.Context, cc checks.CheckContext) model.Check {
	start := time.Now()
	if err := cc.Counter.Add(c.def.ID, c.def.EstimatedPackets); err != nil {
		return checks.NewErrorCheck(c.def, err, start)
	}
	directAddrs, directErr := queryA(ctx, directResolver)
	dohAddrs, dohErr := queryDoH(ctx, "example.com")
	if directErr != nil {
		return model.Check{
			ID: c.def.ID, Layer: c.def.Layer, Title: c.def.Title, ProfileRequired: c.def.ProfileRequired,
			Status: model.StatusInconclusive, Confidence: model.ConfidenceLow,
			Control:     model.Control{Performed: false, Reason: "port53_unreachable"},
			PacketsSent: c.def.EstimatedPackets, DurationMS: time.Since(start).Milliseconds(),
		}
	}
	if dohErr != nil || len(dohAddrs) == 0 {
		return model.Check{
			ID: c.def.ID, Layer: c.def.Layer, Title: c.def.Title, ProfileRequired: c.def.ProfileRequired,
			Status: model.StatusInconclusive, Confidence: model.ConfidenceLow,
			Observed:    map[string]any{"direct_addresses": directAddrs},
			Control:     model.Control{Performed: false, Reason: "doh_unreachable"},
			PacketsSent: c.def.EstimatedPackets, DurationMS: time.Since(start).Milliseconds(),
		}
	}
	match := sameAddressSet(directAddrs, dohAddrs)
	status := model.StatusNormal
	confidence := model.ConfidenceHigh
	if !match {
		status = model.StatusAnomalous
	}
	return model.Check{
		ID: c.def.ID, Layer: c.def.Layer, Title: c.def.Title, ProfileRequired: c.def.ProfileRequired,
		Status: status, Confidence: confidence,
		Observed:    map[string]any{"direct_addresses": directAddrs, "doh_addresses": dohAddrs, "match": match},
		Control:     model.Control{Performed: true, Result: "direct query to 1.1.1.1:53 vs Cloudflare DoH"},
		PacketsSent: c.def.EstimatedPackets, DurationMS: time.Since(start).Milliseconds(),
	}
}
```

- [ ] **Step 8: Run tests to verify they pass**

Run: `go test ./internal/checks/dns/... -race -v`
Expected: PASS (network-dependent, same caveat as Task 1).

- [ ] **Step 9: Commit**

```bash
git add internal/checks/dns/ go.mod go.sum
git commit -m "feat(checks/dns): dns.resolve_basic, dns.compare_doh, dns.transparent_proxy"
```

---

### Task 5: `internal/checks/tls` — `tls.cert_issuer`

**Files:**
- Create: `internal/checks/tls/cert_issuer.go`
- Create: `internal/checks/tls/cert_issuer_test.go`

**Interfaces:**
- Consumes: `cc.Platform.TrustStoreCAs()` (cross-checks a mismatched issuer against locally-installed CAs, spec §7.1's worked example).
- Produces: `func NewCertIssuerCheck(def registry.CheckDefinition) checks.Checker`, package `tls`.

**Baseline fingerprint (captured live 2026-08-18, valid until 2026-10-27 — needs periodic refresh, same treatment as `local/publicroots.pem`'s provenance note from M2):**
```
sha256 Fingerprint = 61:53:A9:6F:D1:A6:AB:7F:4D:43:8F:C3:49:32:48:42:99:D0:72:9D:91:40:B3:A1:26:BB:2F:9C:07:B0:22:00
issuer  = C=US, O=SSL Corporation, CN=Cloudflare TLS Issuing ECC CA 3
subject = CN=example.com
```

- [ ] **Step 1: Write the failing tests**

```go
// internal/checks/tls/cert_issuer_test.go
package tls

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
	cas []platform.CACert
}

func (f fakeAdapter) TrustStoreCAs() ([]platform.CACert, error) { return f.cas, nil }

func TestCertIssuerNormalWhenFingerprintMatchesBaseline(t *testing.T) {
	def := registry.CheckDefinition{ID: "tls.cert_issuer", EstimatedPackets: 1}
	c := NewCertIssuerCheck(def)
	cc := checks.CheckContext{Platform: fakeAdapter{}, Counter: guard.NewPacketCounter(100), Timeout: 5 * time.Second}
	got := c.Run(context.Background(), cc)
	if got.Status != model.StatusNormal {
		t.Errorf("Status = %v, want normal (example.com's live cert must match the bundled baseline as of the plan's capture date): %#v", got.Status, got.Observed)
	}
	if got.PacketsSent != 1 {
		t.Errorf("PacketsSent = %d, want 1", got.PacketsSent)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/checks/tls/... -run . -v`
Expected: FAIL — package doesn't exist.

- [ ] **Step 3: Implement `cert_issuer.go`**

```go
// internal/checks/tls/cert_issuer.go

// Package tls implements the wifisec "tls"-layer active check (spec
// §6.2): tls.cert_issuer.
package tls

import (
	crypto_tls "crypto/tls"
	"crypto/sha256"
	"crypto/x509"
	stdcontext "context"
	"encoding/hex"
	"time"

	"github.com/Maulana-anjari/wifisec/internal/checks"
	"github.com/Maulana-anjari/wifisec/internal/model"
	"github.com/Maulana-anjari/wifisec/internal/registry"
)

const (
	certTarget = "example.com:443"
	certSNI    = "example.com"
	// baselineFingerprint is example.com's leaf certificate SHA-256
	// fingerprint, captured live 2026-08-18 (cert valid through
	// 2026-10-27). This needs periodic manual refresh as the
	// certificate rotates — same provenance caveat as
	// internal/checks/local/publicroots.pem (deferred to M5 in that
	// package's case; here it's an expected, spec-anticipated
	// occurrence: spec §6.2 says a mismatch is Anomalous at Confidence
	// medium precisely *because* normal rotation happens).
	baselineFingerprint = "6153a96fd1a6ab7f4d438fc34932484299d0729d9140b3a126bb2f9c07b02200"
)

type CertIssuerCheck struct{ def registry.CheckDefinition }

func NewCertIssuerCheck(def registry.CheckDefinition) checks.Checker { return CertIssuerCheck{def} }
func (c CertIssuerCheck) Definition() registry.CheckDefinition       { return c.def }

// Run dials the control domain with InsecureSkipVerify and a custom
// VerifyPeerCertificate that unconditionally accepts (spec §6.2: "the
// certificate must not be rejected — the point is to see exactly what
// the network hands back").
func (c CertIssuerCheck) Run(ctx stdcontext.Context, cc checks.CheckContext) model.Check {
	start := time.Now()
	if err := cc.Counter.Add(c.def.ID, c.def.EstimatedPackets); err != nil {
		return checks.NewErrorCheck(c.def, err, start)
	}
	var captured []*x509.Certificate
	cfg := &crypto_tls.Config{
		ServerName:         certSNI,
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			for _, raw := range rawCerts {
				if cert, err := x509.ParseCertificate(raw); err == nil {
					captured = append(captured, cert)
				}
			}
			return nil
		},
	}
	dialer := &crypto_tls.Dialer{Config: cfg}
	conn, err := dialer.DialContext(ctx, "tcp", certTarget)
	if err != nil {
		return model.Check{
			ID: c.def.ID, Layer: c.def.Layer, Title: c.def.Title, ProfileRequired: c.def.ProfileRequired,
			Status: model.StatusInconclusive, Confidence: model.ConfidenceLow,
			Control:     model.Control{Performed: false, Reason: "tls_handshake_failed"},
			PacketsSent: c.def.EstimatedPackets, DurationMS: time.Since(start).Milliseconds(),
		}
	}
	defer conn.Close()
	if len(captured) == 0 {
		return model.Check{
			ID: c.def.ID, Layer: c.def.Layer, Title: c.def.Title, ProfileRequired: c.def.ProfileRequired,
			Status: model.StatusInconclusive, Confidence: model.ConfidenceLow,
			Control:     model.Control{Performed: false, Reason: "no_certificate_presented"},
			PacketsSent: c.def.EstimatedPackets, DurationMS: time.Since(start).Milliseconds(),
		}
	}
	leaf := captured[0]
	sum := sha256.Sum256(leaf.Raw)
	fingerprint := hex.EncodeToString(sum[:])

	match := fingerprint == baselineFingerprint
	status := model.StatusNormal
	confidence := model.ConfidenceHigh
	if !match {
		status = model.StatusAnomalous
		confidence = model.ConfidenceMedium
		if foundInTrustStore(cc, leaf.Issuer.String()) {
			confidence = model.ConfidenceHigh
		}
	}
	return model.Check{
		ID: c.def.ID, Layer: c.def.Layer, Title: c.def.Title, ProfileRequired: c.def.ProfileRequired,
		Status: status, Confidence: confidence,
		Observed: map[string]any{
			"issuer": leaf.Issuer.String(), "subject": leaf.Subject.String(),
			"fingerprint": "sha256:" + fingerprint, "chain_length": len(captured),
		},
		Expected:    map[string]any{"fingerprint": "sha256:" + baselineFingerprint, "source": "baseline_bundled"},
		Control:     model.Control{Performed: true, Result: "compared against bundled baseline fingerprint"},
		PacketsSent: c.def.EstimatedPackets, DurationMS: time.Since(start).Milliseconds(),
	}
}

func foundInTrustStore(cc checks.CheckContext, issuer string) bool {
	cas, err := cc.Platform.TrustStoreCAs()
	if err != nil {
		return false
	}
	for _, ca := range cas {
		if ca.Subject == issuer {
			return true
		}
	}
	return false
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/checks/tls/... -race -v`
Expected: PASS if example.com's live cert still matches the baseline fingerprint above (true as of this plan's capture date; if the implementer runs this task noticeably later than 2026-08-18 and the cert has since rotated, the test will legitimately fail — re-capture the fingerprint with `echo | openssl s_client -connect example.com:443 -servername example.com 2>/dev/null | openssl x509 -noout -fingerprint -sha256`, update `baselineFingerprint`, and note the new capture date in the comment).

- [ ] **Step 5: Commit**

```bash
git add internal/checks/tls/
git commit -m "feat(checks/tls): tls.cert_issuer check with bundled example.com baseline"
```

---

### Task 6: `internal/interpret` — seven missing rules

**Files:**
- Modify: `internal/interpret/rules.yaml`
- Modify: `internal/interpret/rules_test.go`

**Interfaces:**
- Consumes: `Check.ID`/`Check.Status`/`Check.Observed` from every checker built in Tasks 1-5, plus the pre-existing `local.trust_store`/`local.proxy_system`.
- Produces: nothing new — this task only adds YAML rule entries the existing `interpret.Apply`/rule evaluator (built in M2) already knows how to consume.

- [ ] **Step 1: Write the failing tests**

First check whether `internal/interpret/rules_test.go` already has a `hasFinding(findings []model.Finding, id string) bool` helper from M2 — if it does, reuse it and skip adding a duplicate.

```go
// internal/interpret/rules_test.go — append
func TestTLSInterceptionRequiresBothCertMismatchAndForeignCA(t *testing.T) {
	checks := []model.Check{
		{ID: "tls.cert_issuer", Status: model.StatusAnomalous},
		{ID: "local.trust_store", Status: model.StatusAnomalous, Observed: map[string]any{"non_public_ca_found": true}},
	}
	findings, _ := Apply(checks)
	if !hasFinding(findings, "tls_interception") {
		t.Error("expected tls_interception finding when both conditions hold")
	}
}

func TestTLSInterceptionAbsentWhenOnlyCertMismatches(t *testing.T) {
	checks := []model.Check{{ID: "tls.cert_issuer", Status: model.StatusAnomalous}}
	findings, _ := Apply(checks)
	if hasFinding(findings, "tls_interception") {
		t.Error("tls_interception must require local.trust_store corroboration too")
	}
}

func TestDNSManipulationFromCompareDoH(t *testing.T) {
	checks := []model.Check{{ID: "dns.compare_doh", Status: model.StatusAnomalous}}
	findings, _ := Apply(checks)
	if !hasFinding(findings, "dns_manipulation") {
		t.Error("expected dns_manipulation finding")
	}
}

func TestTransparentDNSProxyFromTransparentProxyCheck(t *testing.T) {
	checks := []model.Check{{ID: "dns.transparent_proxy", Status: model.StatusAnomalous}}
	findings, _ := Apply(checks)
	if !hasFinding(findings, "transparent_dns_proxy") {
		t.Error("expected transparent_dns_proxy finding")
	}
}

func TestSystemProxyForcedFromProxySystemCheck(t *testing.T) {
	checks := []model.Check{{ID: "local.proxy_system", Status: model.StatusAnomalous}}
	findings, _ := Apply(checks)
	if !hasFinding(findings, "system_proxy_forced") {
		t.Error("expected system_proxy_forced finding")
	}
}

func TestCaptivePortalFindingFromCaptivePortalCheck(t *testing.T) {
	checks := []model.Check{{ID: "net.captive_portal", Status: model.StatusAnomalous}}
	findings, _ := Apply(checks)
	if !hasFinding(findings, "captive_portal") {
		t.Error("expected captive_portal finding")
	}
}

func TestPoorQualityFromEitherJitterOrPacketLoss(t *testing.T) {
	jitterOnly := []model.Check{{ID: "net.jitter", Status: model.StatusAnomalous}, {ID: "net.packet_loss", Status: model.StatusNormal}}
	if findings, _ := Apply(jitterOnly); !hasFinding(findings, "poor_quality") {
		t.Error("expected poor_quality from jitter alone")
	}
	lossOnly := []model.Check{{ID: "net.jitter", Status: model.StatusNormal}, {ID: "net.packet_loss", Status: model.StatusAnomalous}}
	if findings, _ := Apply(lossOnly); !hasFinding(findings, "poor_quality") {
		t.Error("expected poor_quality from packet_loss alone")
	}
}

func TestBufferbloatFindingFromBufferbloatCheck(t *testing.T) {
	checks := []model.Check{{ID: "net.bufferbloat", Status: model.StatusAnomalous}}
	findings, _ := Apply(checks)
	if !hasFinding(findings, "bufferbloat") {
		t.Error("expected bufferbloat finding")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/interpret/... -v`
Expected: FAIL — the 7 new finding IDs never appear (rules don't exist yet).

- [ ] **Step 3: Append the seven rules to `rules.yaml`**

```yaml
  - id: tls_interception
    severity: critical
    when:
      all:
        - check: tls.cert_issuer
          status: anomalous
        - check: local.trust_store
          observed:
            non_public_ca_found: true
    title: "Trafik HTTPS kemungkinan besar dibaca oleh operator jaringan"
    explanation: |
      Sertifikat diterbitkan tidak cocok dengan baseline yang dibundel,
      dan CA yang tidak dikenal publik terpasang di trust store
      perangkat ini. Artinya isi koneksi HTTPS dapat didekripsi di
      jaringan.
    impact: [password, email, chat, internal_docs]
    recommendation: "Hindari login ke akun pribadi. Gunakan koneksi seluler untuk hal sensitif."
    false_positive_hints:
      - "Umum dan sah pada perangkat milik perusahaan dengan MDM."

  - id: dns_manipulation
    severity: critical
    when:
      check: dns.compare_doh
      status: anomalous
    title: "Resolusi DNS jaringan berbeda dari DNS-over-HTTPS independen"
    explanation: |
      Domain kontrol di-resolve ke alamat berbeda antara resolver
      jaringan dan DNS-over-HTTPS independen. Ini indikasi kuat DNS
      dimanipulasi di jaringan.
    impact: [password, email, chat]
    recommendation: "Gunakan DNS-over-HTTPS atau VPN sebelum mengakses layanan sensitif."

  - id: transparent_dns_proxy
    severity: warning
    when:
      check: dns.transparent_proxy
      status: anomalous
    title: "Query DNS ke resolver lain tetap dijawab jaringan"
    explanation: |
      Query DNS langsung ke resolver publik lain tidak mendapat
      jawaban yang konsisten dengan DNS-over-HTTPS — kemungkinan port
      53 dicegat terlepas dari tujuan yang diminta.
    recommendation: "Gunakan DNS-over-HTTPS atau DNS-over-TLS agar query tidak dapat dicegat di port 53."

  - id: system_proxy_forced
    severity: warning
    when:
      check: local.proxy_system
      status: anomalous
    title: "Proxy sistem dipaksakan oleh jaringan"
    explanation: |
      Perangkat ini terkonfigurasi memakai HTTP/HTTPS proxy sistem.
      Operator jaringan dapat mengamati atau memodifikasi trafik yang
      melalui proxy tersebut.
    recommendation: "Periksa asal konfigurasi proxy ini sebelum mengakses layanan sensitif."

  - id: captive_portal
    severity: info
    when:
      check: net.captive_portal
      status: anomalous
    title: "Jaringan ini memerlukan login melalui captive portal"
    explanation: |
      Permintaan ke domain kontrol dialihkan atau diganti, ciri khas
      captive portal yang belum login. Check lain di profil ini
      ditandai inconclusive sampai portal ini dilalui.
    recommendation: "Selesaikan proses login captive portal, lalu jalankan pemeriksaan ulang."

  - id: poor_quality
    severity: info
    when:
      any:
        - check: net.jitter
          status: anomalous
        - check: net.packet_loss
          status: anomalous
    title: "Kualitas koneksi jaringan ini buruk"
    explanation: |
      Variasi latency atau tingkat kehilangan paket ke internet cukup
      tinggi. Ini masalah kualitas, bukan indikasi keamanan.
    recommendation: "Panggilan video atau streaming mungkin terganggu di jaringan ini."

  - id: bufferbloat
    severity: info
    when:
      check: net.bufferbloat
      status: anomalous
    title: "Latency melonjak signifikan saat jaringan dibebani"
    explanation: |
      Latency ke internet naik jauh saat ada beban koneksi bersamaan,
      ciri khas bufferbloat pada perangkat jaringan.
    recommendation: "Aktivitas real-time (video call, gaming) mungkin terasa lag di jaringan ini saat ramai."
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/interpret/... -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/interpret/rules.yaml internal/interpret/rules_test.go
git commit -m "feat(interpret): add tls_interception, dns_manipulation, transparent_dns_proxy, system_proxy_forced, captive_portal, poor_quality, bufferbloat rules"
```

---

### Task 7: `cmd/wifisec/main.go` — wire minimal + standard checkers, captive-portal gate, latency derivation, budget fix

**Files:**
- Modify: `cmd/wifisec/main.go`
- Modify: `internal/model/profile.go`

**Interfaces:**
- Consumes: every `NewXCheck` constructor from Tasks 1-5; `checks.RunGated`; `checks.DeriveLatencyChecks`.
- Produces: an updated `runReal` that actually runs `minimal`/`standard` checks instead of reporting them `not_implemented`.

- [ ] **Step 1: Fix the packet-budget bug**

In `internal/model/profile.go`, change:

```go
	ProfileStandard: 50,
```

to:

```go
	// 52 = the 7 non-zero rows in spec §6.3's own table (2+10+10+4+2+20+2)
	// PLUS the 2 minimal-tier checks (dns.resolve_basic, tls.cert_issuer)
	// that also run — for real, calling Counter.Add — whenever the
	// active profile is standard or above, since profiles are
	// cumulative (spec §4.1). The pre-M4 value of 50 excluded those 2
	// and would have made the last standard-tier check to claim budget
	// spuriously fail with StatusError on a perfectly clean network.
	ProfileStandard: 52,
```

- [ ] **Step 2: Extend `buildCheckers`' factory map**

In `cmd/wifisec/main.go`, add the new imports:

```go
	"github.com/Maulana-anjari/wifisec/internal/checks/dns"
	netchecks "github.com/Maulana-anjari/wifisec/internal/checks/net"
	"github.com/Maulana-anjari/wifisec/internal/checks/tls"
```

(`netchecks` avoids colliding with stdlib `net`, which `main.go` will need to reference directly once this task's code is in place.)

Add to the `factory` map inside `buildCheckers`, right after the existing `wifi.link_speed` entry:

```go
		"dns.resolve_basic":     func(d registry.CheckDefinition) checks.Checker { return dns.NewResolveBasicCheck(d) },
		"tls.cert_issuer":       func(d registry.CheckDefinition) checks.Checker { return tls.NewCertIssuerCheck(d) },
		"net.captive_portal":    func(d registry.CheckDefinition) checks.Checker { return netchecks.NewCaptivePortalCheck(d) },
		"net.latency_gateway":   func(d registry.CheckDefinition) checks.Checker { return netchecks.NewLatencyGatewayCheck(d) },
		"net.latency_internet":  func(d registry.CheckDefinition) checks.Checker { return netchecks.NewLatencyInternetCheck(d) },
		"dns.compare_doh":       func(d registry.CheckDefinition) checks.Checker { return dns.NewCompareDoHCheck(d) },
		"dns.transparent_proxy": func(d registry.CheckDefinition) checks.Checker { return dns.NewTransparentProxyCheck(d) },
		"net.bufferbloat":       func(d registry.CheckDefinition) checks.Checker { return netchecks.NewBufferbloatCheck(d) },
		"net.ipv6":              func(d registry.CheckDefinition) checks.Checker { return netchecks.NewIPv6Check(d) },
```

Deliberately **not** added: `net.jitter`, `net.packet_loss` — these are derived (Task 3), handled separately below, never dispatched through the normal factory/`Checker` path.

- [ ] **Step 3: Replace the run section of `runReal`**

Replace this block (the `defs := reg.Filter(effective)` line through the `for c := range checks.Run(ctx, builtCheckers, cc)` loop) with:

```go
	defs := reg.Filter(effective)

	// net.jitter and net.packet_loss are derived from net.latency_internet
	// (spec §6.3: "dari latency", 0 additional packets) — they never go
	// through buildCheckers/the normal Checker dispatch path. Pull their
	// definitions out of defs (if the profile allows them) before handing
	// the rest to buildCheckers, so they don't show up as "unimplemented".
	var jitterDef, packetLossDef registry.CheckDefinition
	haveJitter, havePacketLoss := false, false
	var remainingDefs []registry.CheckDefinition
	for _, d := range defs {
		switch d.ID {
		case "net.jitter":
			jitterDef, haveJitter = d, true
		case "net.packet_loss":
			packetLossDef, havePacketLoss = d, true
		default:
			remainingDefs = append(remainingDefs, d)
		}
	}

	builtCheckers, unimplemented := buildCheckers(remainingDefs)
	for _, id := range unimplemented {
		fmt.Fprintf(os.Stderr, "warning: %s has no implementation yet, skipping\n", id)
	}

	unimplementedIDs := make(map[string]bool, len(unimplemented))
	for _, id := range unimplemented {
		unimplementedIDs[id] = true
	}
	handledIDs := make(map[string]bool, len(defs))
	for _, d := range remainingDefs {
		if !unimplementedIDs[d.ID] {
			handledIDs[d.ID] = true
		}
	}
	handledIDs["net.jitter"] = haveJitter
	handledIDs["net.packet_loss"] = havePacketLoss
	var skipped []model.Check
	for _, def := range reg.Checks {
		if handledIDs[def.ID] {
			continue
		}
		reason := "profile_does_not_allow"
		if unimplementedIDs[def.ID] {
			reason = "not_implemented"
		}
		skipped = append(skipped, model.Check{
			ID: def.ID, Layer: def.Layer, Title: def.Title, ProfileRequired: def.ProfileRequired,
			Status: model.StatusSkipped, Confidence: model.ConfidenceLow,
			Control: model.Control{Performed: false, Reason: reason},
		})
	}

	cc := checks.CheckContext{
		Platform: adapter,
		Counter:  guard.NewPacketCounter(effective.EstimatedPackets()),
		Timeout:  10 * time.Second,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var downgraded atomic.Bool
	if wifiInfo.Available && effective != model.ProfilePassive {
		go guard.Watch(ctx, adapter, wifiInfo.BSSID, 2*time.Second, func(string) {
			downgraded.Store(true)
			cancel()
		})
	}

	start := time.Now()
	results := append([]model.Check{}, skipped...)
	// net.captive_portal, if present, gates the rest of the standard
	// profile (spec §6.3) — RunGated runs it first and short-circuits
	// everything else to inconclusive if it trips. Checks outside the
	// standard tier (passive/minimal) are NOT part of "check lain di
	// profil ini" and must keep running normally even if the portal is
	// up, so they're excluded from the gated batch and run separately.
	var gatedBatch, ungatedBatch []checks.Checker
	for _, checker := range builtCheckers {
		if checker.Definition().ProfileRequired == model.ProfileStandard {
			gatedBatch = append(gatedBatch, checker)
		} else {
			ungatedBatch = append(ungatedBatch, checker)
		}
	}
	var latencyResult model.Check
	haveLatencyResult := false
	for c := range checks.RunGated(ctx, gatedBatch, cc, "net.captive_portal",
		func(c model.Check) bool { return c.Status == model.StatusAnomalous }, "captive_portal_detected") {
		if c.ID == "net.latency_internet" {
			latencyResult, haveLatencyResult = c, true
		}
		results = append(results, c)
	}
	for c := range checks.Run(ctx, ungatedBatch, cc) {
		results = append(results, c)
	}
	if haveJitter && havePacketLoss {
		if !haveLatencyResult {
			latencyResult = model.Check{ID: "net.latency_internet", Status: model.StatusInconclusive}
		}
		jitter, packetLoss := checks.DeriveLatencyChecks(latencyResult, jitterDef, packetLossDef)
		results = append(results, jitter, packetLoss)
	}
```

The rest of `runReal` (from `cancel()` onward) is unchanged.

- [ ] **Step 4: Bump `ToolVersion`**

```go
		ToolVersion:   "0.4.0-m4",
```

- [ ] **Step 5: Run the full suite**

Run: `go build ./... && go vet ./... && go test ./... -race`
Expected: PASS across every package.

- [ ] **Step 6: Commit**

```bash
git add cmd/wifisec/main.go internal/model/profile.go
git commit -m "feat(cmd): wire minimal+standard checkers, captive-portal gate, latency derivation, fix standard-profile packet budget"
```

---

### Task 8: Real-network validation (M4's spec §11 completion criterion) + budget regression test

**Files:**
- Create: `internal/checks/standard_integration_test.go`

**Interfaces:**
- Consumes: everything wired in Task 7 — this task adds no new production code, only tests proving M4's specific completion bar: *"deteksi captive portal berjalan benar dan tidak menghasilkan false positive pada jaringan uji"* (captive portal detection works correctly and produces no false positive on a test network).

- [ ] **Step 1: Write the integration test**

```go
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
```

- [ ] **Step 2: Run the tests**

Run: `go test ./internal/checks/... -run TestCaptivePortalNoFalsePositiveOnRealNetwork -v` and `go test ./internal/checks/... -run TestStandardProfileStaysWithinRealPacketBudget -v`

Then, separately, run the actual CLI against a real network by hand as the final milestone sign-off (not part of the automated suite — this is the literal "jaringan uji" spec §11 asks for):

```bash
go run ./cmd/wifisec --profile standard --i-own-this-network
```

Confirm in the TUI output: `net.captive_portal` reports `normal`, and no other standard-tier check is `inconclusive` with reason `captive_portal_detected`.

Expected: automated tests PASS (or skip cleanly if offline); manual run shows a clean captive-portal result on a real, non-portal network.

- [ ] **Step 3: Commit**

```bash
git add internal/checks/standard_integration_test.go
git commit -m "test(checks): real-network captive-portal false-positive check; standard-profile packet-budget regression test"
```
