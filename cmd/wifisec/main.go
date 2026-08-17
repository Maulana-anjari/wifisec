package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	tea "github.com/charmbracelet/bubbletea"

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

// main has two modes:
//   wifisec <result.json>   loads a saved/fixture Result and renders it (M1 stub, kept for manual TUI review)
//   wifisec                 runs the real passive-profile checks on this machine and renders the result (M2)
// Flag parsing, profile selection, and higher profiles land in M3/M4
// (spec §9.1, §11).
func main() {
	if len(os.Args) >= 2 {
		runFromFile(os.Args[1])
		return
	}
	runReal()
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

func runReal() {
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

	cc := checks.CheckContext{
		Platform: platform.New(),
		Counter:  guard.NewPacketCounter(model.ProfilePassive.EstimatedPackets()),
		Timeout:  10 * time.Second,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	start := time.Now()
	var results []model.Check
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
