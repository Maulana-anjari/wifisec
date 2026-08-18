package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	pflag "github.com/spf13/pflag"

	"github.com/Maulana-anjari/wifisec/internal/checks"
	"github.com/Maulana-anjari/wifisec/internal/checks/local"
	"github.com/Maulana-anjari/wifisec/internal/checks/wifi"
	"github.com/Maulana-anjari/wifisec/internal/guard"
	"github.com/Maulana-anjari/wifisec/internal/interpret"
	"github.com/Maulana-anjari/wifisec/internal/model"
	"github.com/Maulana-anjari/wifisec/internal/platform"
	"github.com/Maulana-anjari/wifisec/internal/registry"
	"github.com/Maulana-anjari/wifisec/internal/tui"
)

// main has three modes:
//   wifisec <result.json>              loads a saved/fixture Result and renders it (M1, kept for manual TUI review)
//   wifisec known-networks add         adds the current network to the whitelist (M3, spec §9.1/G7)
//   wifisec [--profile P] [--i-own-this-network]  runs real checks at the requested profile (M2/M3)
func main() {
	if len(os.Args) >= 2 && !strings.HasPrefix(os.Args[1], "-") {
		switch os.Args[1] {
		case "known-networks":
			if len(os.Args) >= 3 && os.Args[2] == "add" {
				runKnownNetworksAdd()
				return
			}
			fmt.Fprintln(os.Stderr, "usage: wifisec known-networks add")
			os.Exit(3)
		default:
			runFromFile(os.Args[1])
			return
		}
	}

	profileFlag := pflag.String("profile", "passive", "profile to run: passive, minimal, standard, full")
	ownsNetwork := pflag.Bool("i-own-this-network", false, "confirm non-interactively that you own/administer this network (required above standard)")
	pflag.Parse()

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
		os.Exit(1)
	}

	defs := reg.Filter(model.ProfilePassive)
	builtCheckers, unimplemented := buildCheckers(defs)
	for _, id := range unimplemented {
		fmt.Fprintf(os.Stderr, "warning: %s has no implementation yet, skipping\n", id)
	}
	if len(unimplemented) > 0 {
		// All 13 passive checks have real implementations as of this
		// milestone, so this should never trigger in practice — if it
		// does, it's a registry/factory-map drift bug the user needs to
		// know about immediately, not a soft warning they can miss.
		fmt.Fprintln(os.Stderr, "error: one or more passive-profile checks have no implementation; refusing to produce an incomplete verdict")
		os.Exit(1)
	}

	// Every check the passive profile does NOT allow must still show up
	// as an explicit skipped result (spec P4: a Verdict that doesn't
	// list what wasn't checked is a bug) — reg.Filter above only
	// returns what's runnable, so walk the full registry for the rest.
	passiveIDs := make(map[string]bool, len(defs))
	for _, d := range defs {
		passiveIDs[d.ID] = true
	}
	var skipped []model.Check
	for _, def := range reg.Checks {
		if passiveIDs[def.ID] {
			continue
		}
		skipped = append(skipped, model.Check{
			ID:              def.ID,
			Layer:           def.Layer,
			Title:           def.Title,
			ProfileRequired: def.ProfileRequired,
			Status:          model.StatusSkipped,
			Confidence:      model.ConfidenceLow,
			Control:         model.Control{Performed: false, Reason: "profile_does_not_allow"},
			PacketsSent:     0,
		})
	}

	cc := checks.CheckContext{
		Platform: platform.New(),
		Counter:  guard.NewPacketCounter(model.ProfilePassive.EstimatedPackets()),
		Timeout:  10 * time.Second,
	}

	// Outer budget for the whole run (all checkers combined); cc.Timeout
	// above governs each individual check via runner.go's per-checker
	// context.WithTimeout, so a single slow check can't consume the
	// entire 30s budget by itself.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	start := time.Now()
	results := append([]model.Check{}, skipped...)
	for c := range checks.Run(ctx, builtCheckers, cc) {
		results = append(results, c)
	}

	findings, verdict := interpret.Apply(results)

	result := model.Result{
		SchemaVersion: model.SchemaVersionV1,
		ToolVersion:   "0.2.0-m2",
		RunID:         fmt.Sprintf("run-%d", time.Now().UnixNano()),
		StartedAt:     start,
		DurationMS:    time.Since(start).Milliseconds(),
		Profile:       model.ProfilePassive,
		Checks:        results,
		Findings:      findings,
		Verdict:       verdict,
	}
	launchTUI(result)
}

func launchTUI(result model.Result) {
	if _, err := tea.NewProgram(tui.New(result)).Run(); err != nil {
		fmt.Fprintln(os.Stderr, "tui error:", err)
		os.Exit(1)
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
