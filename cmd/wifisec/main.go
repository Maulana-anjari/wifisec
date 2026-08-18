package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	pflag "github.com/spf13/pflag"

	"github.com/Maulana-anjari/wifisec/internal/checks"
	"github.com/Maulana-anjari/wifisec/internal/checks/dns"
	"github.com/Maulana-anjari/wifisec/internal/checks/local"
	netchecks "github.com/Maulana-anjari/wifisec/internal/checks/net"
	"github.com/Maulana-anjari/wifisec/internal/checks/tls"
	"github.com/Maulana-anjari/wifisec/internal/checks/wifi"
	"github.com/Maulana-anjari/wifisec/internal/guard"
	"github.com/Maulana-anjari/wifisec/internal/interpret"
	"github.com/Maulana-anjari/wifisec/internal/model"
	"github.com/Maulana-anjari/wifisec/internal/platform"
	"github.com/Maulana-anjari/wifisec/internal/registry"
	"github.com/Maulana-anjari/wifisec/internal/tui"
	"github.com/Maulana-anjari/wifisec/internal/whitelist"
)

// main has three modes:
//
//	wifisec <result.json>              loads a saved/fixture Result and renders it (M1, kept for manual TUI review)
//	wifisec known-networks add         adds the current network to the whitelist (M3, spec §9.1/G7)
//	wifisec [--profile P] [--i-own-this-network]  runs real checks at the requested profile (M2/M3)
func main() {
	if len(os.Args) >= 2 && !strings.HasPrefix(os.Args[1], "-") {
		switch os.Args[1] {
		case "known-networks":
			if len(os.Args) >= 3 && os.Args[2] == "add" {
				runKnownNetworksAdd()
				return
			}
			fmt.Fprintln(os.Stderr, "usage: wifisec known-networks add")
			os.Exit(4)
		default:
			runFromFile(os.Args[1])
			return
		}
	}

	// pflag's default CommandLine uses ExitOnError, which calls
	// os.Exit(2) on any parse failure (e.g. a typo'd flag name). Exit
	// code 2 is already spec §9.2's "critical finding" code, so a typo
	// would be indistinguishable from a real critical-severity network
	// finding to any script checking the exit code. Switch to
	// ContinueOnError and pick an exit code that doesn't collide.
	pflag.CommandLine.Init("wifisec", pflag.ContinueOnError)
	profileFlag := pflag.String("profile", "passive", "profile to run: passive, minimal, standard, full")
	ownsNetwork := pflag.Bool("i-own-this-network", false, "confirm non-interactively that you own/administer this network (required above standard)")
	if err := pflag.CommandLine.Parse(os.Args[1:]); err != nil {
		if err == pflag.ErrHelp {
			os.Exit(0)
		}
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(4)
	}

	requested, err := parseProfile(*profileFlag)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(4)
	}
	runReal(requested, *ownsNetwork)
}

// parseProfile validates a --profile flag value against the four
// known profiles (spec §4.1) — no other string is accepted.
func parseProfile(s string) (model.Profile, error) {
	switch model.Profile(s) {
	case model.ProfilePassive, model.ProfileMinimal, model.ProfileStandard, model.ProfileFull:
		return model.Profile(s), nil
	default:
		return "", fmt.Errorf("invalid --profile %q: must be one of passive, minimal, standard, full", s)
	}
}

func runFromFile(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "read result:", err)
		os.Exit(1)
	}
	var result model.Result
	if err := json.Unmarshal(data, &result); err != nil {
		fmt.Fprintln(os.Stderr, "parse result:", err)
		os.Exit(1)
	}
	launchTUI(result)
}

func runReal(requested model.Profile, ownsNetwork bool) {
	reg, err := registry.Load()
	if err != nil {
		fmt.Fprintln(os.Stderr, "load registry:", err)
		os.Exit(3)
	}

	// Determine KnownNetwork before resolving confirmation steps, since
	// G5 depends on it: read the current WiFi association once, up
	// front, zero-packet (spec §4.7).
	adapter := platform.New()
	wifiInfo, _ := adapter.WiFiInfo()
	netInfo := model.NewNetworkInfo(wifiInfo.SSID, wifiInfo.BSSID)

	list, err := whitelist.Load()
	if err != nil {
		fmt.Fprintln(os.Stderr, "load whitelist:", err)
		os.Exit(3)
	}
	netInfo.KnownNetwork = wifiInfo.Available && list.Contains(netInfo.BSSIDHash)
	netInfo.Band = wifiInfo.Band
	netInfo.Channel = wifiInfo.Channel
	netInfo.Security = wifiInfo.Security
	netInfo.PMF = wifiInfo.PMF

	steps, err := guard.Resolve(guard.ProfileRequest{Requested: requested, OwnsNetwork: ownsNetwork, KnownNetwork: netInfo.KnownNetwork})
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(4)
	}

	effective := requested
	if !runConfirm(requested, netInfo.KnownNetwork, steps) {
		fmt.Fprintln(os.Stderr, "dibatalkan: konfirmasi profil tidak diselesaikan")
		os.Exit(4)
	}

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

	// handledIDs are the checks that actually became a runnable Checker
	// below — NOT simply everything reg.Filter allowed. defs also
	// contains IDs buildCheckers couldn't map to a factory
	// (unimplemented); those must still surface as Skipped entries (with
	// their own Control.Reason) instead of silently vanishing from
	// Result.Checks / Verdict.BlindSpots, which would violate P4 (spec
	// §2, "a Verdict that doesn't list what wasn't checked is a bug").
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

	// G4: watch for a BSSID change during the run. On change, downgrade
	// the reported profile to passive and cancel the run — in-flight
	// checkers observe ctx's cancellation via runner.go's per-checker
	// context.WithTimeout wrapping (spec G4). downgraded is written from
	// the watcher goroutine and read from this goroutine after the loop
	// below, so it must be an atomic.Bool, not a plain bool — a plain
	// bool here is a real data race (go test -race catches it): nothing
	// synchronizes the write in the watcher goroutine with the read
	// after the loop, since the loop only observes checks.Run's channel
	// closing, not ctx.Done() directly. Reading ctx.Err() instead would
	// NOT be equivalent — the outer 30s context.WithTimeout above can
	// also make ctx.Err() non-nil on a plain timeout that has nothing to
	// do with a BSSID change, which must NOT downgrade the profile.
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
	// Stop the BSSID watcher goroutine now, not just via the deferred
	// cancel(). runReal ends in os.Exit (launchTUI runs an interactive
	// TUI session afterward), and os.Exit never runs deferred functions
	// — so without this explicit call the watcher would keep polling
	// platform.WiFiInfo() (nmcli fork on Linux) every 2s for the rest of
	// the process's life with no one left observing it. cancel is a
	// context.CancelFunc, safe to call more than once, so the deferred
	// call above stays as a harmless no-op second call.
	cancel()

	if downgraded.Load() {
		effective = model.ProfilePassive
	}

	findings, verdict := interpret.Apply(results)

	result := model.Result{
		SchemaVersion: model.SchemaVersionV1,
		ToolVersion:   "0.4.0-m4",
		RunID:         fmt.Sprintf("run-%d", time.Now().UnixNano()),
		StartedAt:     start,
		DurationMS:    time.Since(start).Milliseconds(),
		Profile:       effective,
		Network:       netInfo,
		Checks:        results,
		Findings:      findings,
		Verdict:       verdict,
	}
	launchTUI(result)
	os.Exit(exitCodeFor(result))
}

// exitCodeFor computes the process exit code from the final result
// (spec §9.2). Findings are already severity-classified by
// interpret.Apply, so this just finds the worst one present.
func exitCodeFor(result model.Result) int {
	hasCritical := false
	hasWarning := false
	for _, f := range result.Findings {
		switch f.Severity {
		case model.SeverityCritical:
			hasCritical = true
		case model.SeverityWarning:
			hasWarning = true
		}
	}
	switch {
	case hasCritical:
		return 2
	case hasWarning:
		return 1
	default:
		return 0
	}
}

func launchTUI(result model.Result) {
	if _, err := tea.NewProgram(tui.New(result)).Run(); err != nil {
		fmt.Fprintln(os.Stderr, "tui error:", err)
		os.Exit(3)
	}
}

// buildCheckers maps each registry definition to its concrete Checker,
// skipping (and reporting separately) any ID with no implementation
// yet. This mapping lives here, not in internal/checks, because
// internal/checks/local and internal/checks/wifi both import
// internal/checks (for the Checker/CheckContext types) — importing
// them back from internal/checks would be a cycle.
func buildCheckers(defs []registry.CheckDefinition) (built []checks.Checker, unimplemented []string) {
	factory := map[string]func(registry.CheckDefinition) checks.Checker{
		"local.interface":       func(d registry.CheckDefinition) checks.Checker { return local.NewInterfaceCheck(d) },
		"local.gateway":         func(d registry.CheckDefinition) checks.Checker { return local.NewGatewayCheck(d) },
		"local.dns_servers":     func(d registry.CheckDefinition) checks.Checker { return local.NewDNSServersCheck(d) },
		"local.routing":         func(d registry.CheckDefinition) checks.Checker { return local.NewRoutingCheck(d) },
		"local.mtu":             func(d registry.CheckDefinition) checks.Checker { return local.NewMTUCheck(d) },
		"local.proxy_system":    func(d registry.CheckDefinition) checks.Checker { return local.NewProxySystemCheck(d) },
		"local.trust_store":     func(d registry.CheckDefinition) checks.Checker { return local.NewTrustStoreCheck(d) },
		"wifi.security":         func(d registry.CheckDefinition) checks.Checker { return wifi.NewSecurityCheck(d) },
		"wifi.pmf":              func(d registry.CheckDefinition) checks.Checker { return wifi.NewPMFCheck(d) },
		"wifi.signal":           func(d registry.CheckDefinition) checks.Checker { return wifi.NewSignalCheck(d) },
		"wifi.channel":          func(d registry.CheckDefinition) checks.Checker { return wifi.NewChannelCheck(d) },
		"wifi.bssid_vendor":     func(d registry.CheckDefinition) checks.Checker { return wifi.NewBSSIDVendorCheck(d) },
		"wifi.link_speed":       func(d registry.CheckDefinition) checks.Checker { return wifi.NewLinkSpeedCheck(d) },
		"dns.resolve_basic":     func(d registry.CheckDefinition) checks.Checker { return dns.NewResolveBasicCheck(d) },
		"tls.cert_issuer":       func(d registry.CheckDefinition) checks.Checker { return tls.NewCertIssuerCheck(d) },
		"net.captive_portal":    func(d registry.CheckDefinition) checks.Checker { return netchecks.NewCaptivePortalCheck(d) },
		"net.latency_gateway":   func(d registry.CheckDefinition) checks.Checker { return netchecks.NewLatencyGatewayCheck(d) },
		"net.latency_internet":  func(d registry.CheckDefinition) checks.Checker { return netchecks.NewLatencyInternetCheck(d) },
		"dns.compare_doh":       func(d registry.CheckDefinition) checks.Checker { return dns.NewCompareDoHCheck(d) },
		"dns.transparent_proxy": func(d registry.CheckDefinition) checks.Checker { return dns.NewTransparentProxyCheck(d) },
		"net.bufferbloat":       func(d registry.CheckDefinition) checks.Checker { return netchecks.NewBufferbloatCheck(d) },
		"net.ipv6":              func(d registry.CheckDefinition) checks.Checker { return netchecks.NewIPv6Check(d) },
	}
	for _, def := range defs {
		ctor, ok := factory[def.ID]
		if !ok {
			unimplemented = append(unimplemented, def.ID)
			continue
		}
		built = append(built, ctor(def))
	}
	return built, unimplemented
}
