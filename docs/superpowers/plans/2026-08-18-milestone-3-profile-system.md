# Milestone 3: Profile System — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement every G1–G7 profile-enforcement rule, the interactive raise-profile confirmation flow, the known-networks whitelist, BSSID-change auto-downgrade, and exit codes — the guard rail spec calls "the most critical component" and requires built before any active (packet-sending) check exists.

**Architecture:** `internal/whitelist` (new — known_networks.yaml load/save/match, spec G7) → `internal/guard` (extended — `Resolve` for the static/step-list side of G1/G2/G3/G5/G6, `Watch` for the live BSSID-change monitor of G4) → `cmd/wifisec` (extended — pflag-based CLI flags, a small standalone confirmation bubbletea program that reuses `internal/tui.ProfileDialog` for rendering, and exit-code computation from the final `model.Result`). `internal/tui`'s existing `Model`/`Screen` architecture is **not modified** — the confirmation flow runs to completion *before* `tui.New(result)` is ever called, exactly as it does today, preserving the "tui only imports model" dependency rule without a redesign.

**Tech Stack:** Go 1.24 (unchanged), existing deps (bubbletea, lipgloss, yaml.v3) plus `github.com/spf13/pflag` — spec §3.3 names pflag explicitly for flag parsing, and this is the milestone that introduces real CLI flags (`--profile`, `--i-own-this-network`), so this is where it's added.

**Spec:** `SPEC-wifisec.md` (repo root) — this plan implements §5 (profile system and guard rail, in full), §9.1 (the two flags this milestone needs), §9.2 (exit codes), and the M3 exit criteria in §11 (T2, T3, T4).

## Global Constraints

- Go module `go 1.24.0` floor — do not lower it.
- New dependency this milestone: `github.com/spf13/pflag` — already pre-approved by spec §3.3 for exactly this purpose. No other new dependency without explicit approval.
- `internal/model` still imports nothing internal — this milestone does not touch it, except reusing the existing `model.NewNetworkInfo` (added in M1, unused until now) to finally populate `Result.Network` (an M2-deferred gap this milestone closes as a side effect of G7's whitelist matching).
- `internal/tui` still only imports `internal/model` — **not modified this milestone**. Do not add a `guard` or `whitelist` import to it, and do not add a pre-run screen to `tui.Model`. The confirmation dialog is a **separate, small bubbletea program** living in `cmd/wifisec`, which already imports `internal/tui` (for `tui.ProfileDialog`, exported since M1) and can freely also import `internal/guard`.
- `internal/checks` (parent) still never imports `internal/tui`.
- Absolute prohibitions from spec §0.1 remain binding, most relevant here: **never** implement a way to persist/restore the last-used profile across sessions (G1, spec §5.3), and **never** add a flag that bypasses full-profile confirmation besides `--i-own-this-network` (spec §5.3).
- `--redact`, `--json`, `--report`, `--no-color`, `--timeout`, `list-checks`, `control-server` are explicitly **out of scope this milestone** — M3's own exit criteria (spec §11) is "seluruh aturan G1–G7, dialog konfirmasi, whitelist, exit code," none of which need those flags/subcommands. They land when M4/M5 actually need them.
- Design decisions already made (do not re-litigate; ask the user only if you find these are actually wrong, not merely debatable):
  - **G1** ("profil default `passive`, state sesi sebelumnya tidak dibaca") is satisfied by construction: `--profile`'s pflag default is `"passive"`, and no code path anywhere reads a previously-persisted profile. No dedicated runtime check exists for this — it's a structural guarantee, verified by a test asserting the flag's default and by the absence of any profile-persistence code (this plan never writes one).
  - **G2/G3/G5** (typed confirmation, dialog content, second confirmation for `full`+unknown-network) are driven by a small standalone `tea.Program` in `cmd/wifisec/confirm.go`, walking an ordered list of confirmation steps that `guard.Resolve` computes. It reuses `tui.ProfileDialog.View()`/`.Confirmed()` unmodified for step 1 (G2/G3); step 2 (G5, only when target is `full` and the network isn't known) prepends one warning line ahead of a second `tui.ProfileDialog` instance rather than adding a new field to `ProfileDialog` itself — keeps `internal/tui` untouched.
  - **G4**'s BSSID watcher polls `platform.Adapter.WiFiInfo()` every **2 seconds** (spec doesn't specify an interval; frequent enough to catch a real roaming/AP-switch event without meaningfully adding to the process's own resource use, since `WiFiInfo()` is itself zero-packet per spec §4.7).
  - **G7**'s `known_networks.yaml` schema (spec references the file's existence and content — "berisi hash BSSID" — without defining exact YAML structure): a top-level `networks:` list of `{bssid_hash, label}` entries, `label` optional. Uses the exact same `"sha256:<hex>"` hash format `model.NewNetworkInfo` already produces (spec §4.5) — no new hash function.
  - `XDG_CONFIG_HOME` fallback: when unset, falls back to `$HOME/.config` per the XDG Base Directory spec's own documented default — spec text only says "`$XDG_CONFIG_HOME/wifisec/known_networks.yaml`" without addressing the unset case, but the standard's own fallback is unambiguous and not a project-specific judgment call.
  - Invalid `--profile` values and G6 violations both exit with code 4 (spec §9.2's "profil tidak mengizinkan operasi yang diminta" is the closest fit for both — spec defines no separate "bad flag value" code).

---

### Task 1: `internal/whitelist` — known-networks whitelist (spec G7)

**Files:**
- Create: `internal/whitelist/whitelist.go`
- Test: `internal/whitelist/whitelist_test.go`

**Interfaces:**
- Consumes: nothing internal (stdlib `os`/`path/filepath` + `gopkg.in/yaml.v3`).
- Produces: `type Entry struct{BSSIDHash, Label string}`, `type List struct{Networks []Entry}`, `func Path() (string, error)`, `func Load() (*List, error)`, `func (*List) Contains(bssidHash string) bool`, `func (*List) Add(bssidHash, label string)`, `func (*List) Save() error`.

- [ ] **Step 1: Write the failing tests**

Create `internal/whitelist/whitelist_test.go`:

```go
package whitelist

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPathUsesXDGConfigHome(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "/tmp/wifisec-xdg-test")
	got, err := Path()
	if err != nil {
		t.Fatalf("Path() error: %v", err)
	}
	want := "/tmp/wifisec-xdg-test/wifisec/known_networks.yaml"
	if got != want {
		t.Errorf("Path() = %q, want %q", got, want)
	}
}

func TestPathFallsBackToHomeConfigWhenXDGUnset(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "")
	home := t.TempDir()
	t.Setenv("HOME", home)
	got, err := Path()
	if err != nil {
		t.Fatalf("Path() error: %v", err)
	}
	want := filepath.Join(home, ".config", "wifisec", "known_networks.yaml")
	if got != want {
		t.Errorf("Path() = %q, want %q", got, want)
	}
}

func TestLoadMissingFileReturnsEmptyList(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	l, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if len(l.Networks) != 0 {
		t.Errorf("expected empty list for missing file, got %d entries", len(l.Networks))
	}
}

func TestAddThenContains(t *testing.T) {
	l := &List{}
	if l.Contains("sha256:abc") {
		t.Fatal("empty list should not contain anything")
	}
	l.Add("sha256:abc", "home")
	if !l.Contains("sha256:abc") {
		t.Error("expected list to contain the added hash")
	}
}

func TestAddIsIdempotent(t *testing.T) {
	l := &List{}
	l.Add("sha256:abc", "home")
	l.Add("sha256:abc", "home again")
	if len(l.Networks) != 1 {
		t.Errorf("expected 1 entry after adding the same hash twice, got %d", len(l.Networks))
	}
}

func TestSaveThenLoadRoundTrips(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	l := &List{}
	l.Add("sha256:home-network", "rumah")
	if err := l.Save(); err != nil {
		t.Fatalf("Save() error: %v", err)
	}

	path, _ := Path()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected file at %s: %v", path, err)
	}

	loaded, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if !loaded.Contains("sha256:home-network") {
		t.Error("round-tripped list should contain the saved hash")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/whitelist/... -v`
Expected: FAIL — package doesn't exist yet.

- [ ] **Step 3: Write the implementation**

Create `internal/whitelist/whitelist.go`:

```go
// Package whitelist implements the known-networks whitelist (spec
// §5.2 G7): the only mechanism by which a network is ever considered
// "known," gating spec G5's second full-profile confirmation.
package whitelist

import (
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Entry is one whitelisted network (spec G7: "berisi hash BSSID").
// Label is an optional human-readable note, never used for matching.
type Entry struct {
	BSSIDHash string `yaml:"bssid_hash"`
	Label     string `yaml:"label,omitempty"`
}

type List struct {
	Networks []Entry `yaml:"networks"`
}

// Path returns $XDG_CONFIG_HOME/wifisec/known_networks.yaml (spec
// G7), falling back to $HOME/.config per the XDG Base Directory
// spec's own documented default when XDG_CONFIG_HOME is unset.
func Path() (string, error) {
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, "wifisec", "known_networks.yaml"), nil
}

// Load reads the whitelist file. A missing file is not an error — it
// means an empty whitelist, consistent with spec P1/G1: no prior
// state is ever assumed present.
func Load() (*List, error) {
	path, err := Path()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &List{}, nil
	}
	if err != nil {
		return nil, err
	}
	var l List
	if err := yaml.Unmarshal(data, &l); err != nil {
		return nil, err
	}
	return &l, nil
}

// Contains reports whether bssidHash (spec §4.5 "sha256:<hex>"
// format) is in the whitelist.
func (l *List) Contains(bssidHash string) bool {
	for _, e := range l.Networks {
		if e.BSSIDHash == bssidHash {
			return true
		}
	}
	return false
}

// Add appends bssidHash to the whitelist if not already present. It
// does not write to disk — call Save separately.
func (l *List) Add(bssidHash, label string) {
	if l.Contains(bssidHash) {
		return
	}
	l.Networks = append(l.Networks, Entry{BSSIDHash: bssidHash, Label: label})
}

// Save writes the whitelist to Path(), creating parent directories as
// needed. File permissions are restrictive (0600) since this file
// indirectly identifies networks the user has used, even though it
// stores only hashes, not plaintext SSIDs/BSSIDs.
func (l *List) Save() error {
	path, err := Path()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := yaml.Marshal(l)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/whitelist/... -v`
Expected: PASS (6 tests)

- [ ] **Step 5: Commit**

```bash
git add internal/whitelist/
git commit -m "feat(whitelist): add known-networks whitelist load/save/match (spec G7)"
```

---

### Task 2: `internal/guard` — `Resolve` (G1/G2/G3/G5/G6 step-list and static rejection)

**Files:**
- Create: `internal/guard/enforce.go`
- Test: `internal/guard/enforce_test.go`

**Interfaces:**
- Consumes: `model.Profile` (M1).
- Produces: `type ConfirmStep int` (`ConfirmRaise`, `ConfirmFullUnknown`), `type ProfileRequest struct{Requested model.Profile; OwnsNetwork bool; KnownNetwork bool}`, `var ErrRequiresOwnership error`, `func Resolve(req ProfileRequest) ([]ConfirmStep, error)`.

- [ ] **Step 1: Write the failing tests**

Create `internal/guard/enforce_test.go`:

```go
package guard

import (
	"errors"
	"testing"

	"github.com/Maulana-anjari/wifisec/internal/model"
)

func TestResolvePassiveNeedsNoConfirmation(t *testing.T) {
	steps, err := Resolve(ProfileRequest{Requested: model.ProfilePassive})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(steps) != 0 {
		t.Errorf("expected no confirmation steps for passive, got %v", steps)
	}
}

func TestResolveMinimalNeedsOneConfirmation(t *testing.T) {
	steps, err := Resolve(ProfileRequest{Requested: model.ProfileMinimal})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(steps) != 1 || steps[0] != ConfirmRaise {
		t.Errorf("expected [ConfirmRaise], got %v", steps)
	}
}

func TestResolveFullOnKnownNetworkNeedsOneConfirmation(t *testing.T) {
	steps, err := Resolve(ProfileRequest{Requested: model.ProfileFull, OwnsNetwork: true, KnownNetwork: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(steps) != 1 || steps[0] != ConfirmRaise {
		t.Errorf("expected [ConfirmRaise] for full on a known network, got %v", steps)
	}
}

func TestResolveFullOnUnknownNetworkNeedsTwoConfirmations(t *testing.T) {
	steps, err := Resolve(ProfileRequest{Requested: model.ProfileFull, OwnsNetwork: true, KnownNetwork: false})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(steps) != 2 || steps[0] != ConfirmRaise || steps[1] != ConfirmFullUnknown {
		t.Errorf("expected [ConfirmRaise, ConfirmFullUnknown] for full on an unknown network, got %v", steps)
	}
}

func TestResolveFullWithoutOwnershipFlagIsRejected(t *testing.T) {
	_, err := Resolve(ProfileRequest{Requested: model.ProfileFull, OwnsNetwork: false})
	if !errors.Is(err, ErrRequiresOwnership) {
		t.Errorf("expected ErrRequiresOwnership, got %v", err)
	}
}

func TestResolveStandardWithoutOwnershipFlagIsAllowed(t *testing.T) {
	// G6 only gates profiles ABOVE standard — standard itself needs no
	// --i-own-this-network flag, only its own G2 typed confirmation.
	steps, err := Resolve(ProfileRequest{Requested: model.ProfileStandard, OwnsNetwork: false})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(steps) != 1 || steps[0] != ConfirmRaise {
		t.Errorf("expected [ConfirmRaise], got %v", steps)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/guard/... -run TestResolve -v`
Expected: FAIL — `Resolve` doesn't exist yet.

- [ ] **Step 3: Write the implementation**

Create `internal/guard/enforce.go`:

```go
package guard

import (
	"errors"

	"github.com/Maulana-anjari/wifisec/internal/model"
)

// ErrRequiresOwnership is returned by Resolve when the requested
// profile is above standard and OwnsNetwork is false (spec G6: "Untuk
// profil di atas standard, --profile memerlukan --i-own-this-network
// sebagai konfirmasi non-interaktif").
var ErrRequiresOwnership = errors.New("guard: profile above standard requires --i-own-this-network")

// ConfirmStep is one interactive confirmation the caller (cmd/wifisec)
// must walk the user through before running checks at a raised
// profile.
type ConfirmStep int

const (
	// ConfirmRaise is the typed-profile-name confirmation required for
	// any profile above passive (spec G2/G3).
	ConfirmRaise ConfirmStep = iota
	// ConfirmFullUnknown is the second confirmation required only for
	// profile full on a network not in the whitelist (spec G5).
	ConfirmFullUnknown
)

// ProfileRequest describes what the caller is asking for and the
// context Resolve needs to compute the required confirmation steps.
type ProfileRequest struct {
	Requested    model.Profile
	OwnsNetwork  bool // --i-own-this-network flag (spec G6)
	KnownNetwork bool // whitelist.Contains result (spec G5, G7)
}

// Resolve computes the ordered confirmation steps required before
// req.Requested may run (spec §5.2 G1–G3, G5, G6). It never blocks —
// interactive confirmation is the caller's job (cmd/wifisec). Resolve
// only rejects combinations that must never be allowed regardless of
// any confirmation (G6); everything else it expresses as a step list.
//
// Passive requires no confirmation at all (spec G1: it's the default,
// and raising TO passive is a no-op, not a raise).
func Resolve(req ProfileRequest) ([]ConfirmStep, error) {
	if req.Requested.Level() > model.ProfileStandard.Level() && !req.OwnsNetwork {
		return nil, ErrRequiresOwnership
	}
	if req.Requested == model.ProfilePassive {
		return nil, nil
	}
	steps := []ConfirmStep{ConfirmRaise}
	if req.Requested == model.ProfileFull && !req.KnownNetwork {
		steps = append(steps, ConfirmFullUnknown)
	}
	return steps, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/guard/... -v`
Expected: PASS (all guard package tests, including the pre-existing `PacketCounter` tests from M2)

- [ ] **Step 5: Commit**

```bash
git add internal/guard/enforce.go internal/guard/enforce_test.go
git commit -m "feat(guard): add Resolve computing G1/G2/G3/G5/G6 confirmation steps"
```

---

### Task 3: `internal/guard` — BSSID-change watcher (spec G4) + T4

**Files:**
- Create: `internal/guard/bssid_watch.go`
- Test: `internal/guard/bssid_watch_test.go`

**Interfaces:**
- Consumes: `platform.Adapter` (M2).
- Produces: `func Watch(ctx context.Context, adapter platform.Adapter, initialBSSID string, interval time.Duration, onChange func(newBSSID string)) `.

- [ ] **Step 1: Write the failing tests**

Create `internal/guard/bssid_watch_test.go`:

```go
package guard

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/Maulana-anjari/wifisec/internal/platform"
)

// fakeWiFiAdapter returns a scripted sequence of BSSIDs, one per
// WiFiInfo() call, repeating the last entry once the script is
// exhausted.
type fakeWiFiAdapter struct {
	mu      sync.Mutex
	bssids  []string
	callIdx int
}

func (f *fakeWiFiAdapter) WiFiInfo() (platform.WiFiInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	idx := f.callIdx
	if idx >= len(f.bssids) {
		idx = len(f.bssids) - 1
	}
	f.callIdx++
	return platform.WiFiInfo{Available: true, BSSID: f.bssids[idx]}, nil
}
func (f *fakeWiFiAdapter) NetConfig() (platform.NetConfig, error)     { return platform.NetConfig{}, nil }
func (f *fakeWiFiAdapter) ProxyConfig() (platform.ProxyConfig, error) { return platform.ProxyConfig{}, nil }
func (f *fakeWiFiAdapter) TrustStoreCAs() ([]platform.CACert, error)  { return nil, nil }
func (f *fakeWiFiAdapter) RoutingTable() ([]platform.Route, error)    { return nil, nil }

func TestWatchFiresOnChangeWhenBSSIDDiffers(t *testing.T) {
	adapter := &fakeWiFiAdapter{bssids: []string{"AA:AA:AA:AA:AA:AA", "BB:BB:BB:BB:BB:BB"}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	changed := make(chan string, 1)
	go Watch(ctx, adapter, "AA:AA:AA:AA:AA:AA", 5*time.Millisecond, func(newBSSID string) {
		changed <- newBSSID
	})

	select {
	case got := <-changed:
		if got != "BB:BB:BB:BB:BB:BB" {
			t.Errorf("onChange got %q, want BB:BB:BB:BB:BB:BB", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("onChange was never called")
	}
}

func TestWatchNeverFiresWhenBSSIDStable(t *testing.T) {
	adapter := &fakeWiFiAdapter{bssids: []string{"AA:AA:AA:AA:AA:AA"}}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	fired := false
	Watch(ctx, adapter, "AA:AA:AA:AA:AA:AA", 5*time.Millisecond, func(string) {
		fired = true
	})
	if fired {
		t.Error("onChange fired despite a stable BSSID")
	}
}

func TestWatchStopsWhenContextCancelled(t *testing.T) {
	adapter := &fakeWiFiAdapter{bssids: []string{"AA:AA:AA:AA:AA:AA"}}
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		Watch(ctx, adapter, "AA:AA:AA:AA:AA:AA", 5*time.Millisecond, func(string) {})
		close(done)
	}()

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Watch did not return after context cancellation")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/guard/... -run TestWatch -v`
Expected: FAIL — `Watch` doesn't exist yet.

- [ ] **Step 3: Write the implementation**

Create `internal/guard/bssid_watch.go`:

```go
package guard

import (
	"context"
	"time"

	"github.com/Maulana-anjari/wifisec/internal/platform"
)

// Watch polls adapter.WiFiInfo() every interval and calls onChange
// exactly once, with the newly observed BSSID, the first time it
// differs from initialBSSID (spec G4: "perubahan BSSID saat runtime
// menurunkan profil ke passive seketika dan membatalkan check yang
// sedang berjalan"). Watch itself does not downgrade any profile or
// cancel anything — that's the caller's onChange callback (typically
// calling the run's context.CancelFunc and updating the reported
// profile). Watch returns when ctx is done or after firing onChange
// once, whichever comes first.
//
// An empty or unavailable BSSID reading (platform.WiFiInfo.Available
// == false) is not treated as a change — a check run doesn't need to
// treat "WiFi briefly unreadable" the same as "associated to a
// different AP."
func Watch(ctx context.Context, adapter platform.Adapter, initialBSSID string, interval time.Duration, onChange func(newBSSID string)) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			info, err := adapter.WiFiInfo()
			if err != nil || !info.Available {
				continue
			}
			if info.BSSID != "" && info.BSSID != initialBSSID {
				onChange(info.BSSID)
				return
			}
		}
	}
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/guard/... -v`
Expected: PASS (all guard package tests)

- [ ] **Step 5: Commit**

```bash
git add internal/guard/bssid_watch.go internal/guard/bssid_watch_test.go
git commit -m "feat(guard): add BSSID-change watcher (spec G4, T4)"
```

---

### Task 4: T3 completion — packet-limit rejection surfaces as `StatusError`

**Files:**
- Create: `internal/checks/counter_integration_test.go`

**Interfaces:**
- Consumes: `checks.Checker`, `checks.CheckContext`, `checks.NewErrorCheck`, `checks.Run` (M2); `guard.PacketCounter` (M2).

Spec T3 has two halves: "Assert `counter.Add` mengembalikan error saat limit terlampaui" (already covered by M2's `internal/guard/counter_test.go`) **and** "check yang bersangkutan berstatus `StatusError`" — nothing in the codebase exercises that second half yet, because none of the 13 real checks (all zero-packet) ever call `Counter.Add`. This task closes that gap with a synthetic checker, without waiting for Milestone 4's real packet-sending checks.

- [ ] **Step 1: Write the test**

Create `internal/checks/counter_integration_test.go`:

```go
package checks_test

import (
	"context"
	"testing"
	"time"

	"github.com/Maulana-anjari/wifisec/internal/checks"
	"github.com/Maulana-anjari/wifisec/internal/guard"
	"github.com/Maulana-anjari/wifisec/internal/model"
	"github.com/Maulana-anjari/wifisec/internal/registry"
)

// packetHungryChecker simulates a check that tries to send more
// packets than the active profile's counter allows — exactly the
// scenario spec T3 requires, without needing a real Milestone 4 check.
type packetHungryChecker struct {
	def registry.CheckDefinition
	n   int
}

func (c packetHungryChecker) Definition() registry.CheckDefinition { return c.def }

func (c packetHungryChecker) Run(ctx context.Context, cc checks.CheckContext) model.Check {
	start := time.Now()
	if err := cc.Counter.Add(c.def.ID, c.n); err != nil {
		return checks.NewErrorCheck(c.def, err, start)
	}
	return model.Check{ID: c.def.ID, Status: model.StatusNormal, Confidence: model.ConfidenceHigh}
}

func TestT3PacketLimitRejectionSurfacesAsStatusError(t *testing.T) {
	def := registry.CheckDefinition{ID: "test.packet_hungry", Layer: model.LayerLocal, Title: "Packet-hungry test check"}
	checker := packetHungryChecker{def: def, n: 5}

	// Passive profile: limit is 0, so any Add must fail.
	counter := guard.NewPacketCounter(model.ProfilePassive.EstimatedPackets())
	cc := checks.CheckContext{Counter: counter}

	var got model.Check
	for c := range checks.Run(context.Background(), []checks.Checker{checker}, cc) {
		got = c
	}

	if got.Status != model.StatusError {
		t.Errorf("Status = %s, want error (spec T3: rejected Add must surface as StatusError)", got.Status)
	}
	if got.Error == "" {
		t.Error("expected a non-empty Error message explaining the rejection")
	}
	if counter.Total() != 0 {
		t.Errorf("counter.Total() = %d, want 0 (rejected Add must not partially apply)", counter.Total())
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/checks/... -run TestT3 -v`
Expected: FAIL initially only if something is actually broken — this test exercises entirely existing M2 machinery (`checks.Run`, `checks.NewErrorCheck`, `guard.PacketCounter`), so it's plausible it passes immediately. If it passes on the first run, that's fine — this task's job is to make T3's second half exist and pass, not necessarily to watch it go red first (no new production code is being added). Note this in your report either way.

- [ ] **Step 3: Run test to verify it passes**

Run: `go test ./internal/checks/... -run TestT3 -v`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add internal/checks/counter_integration_test.go
git commit -m "test(checks): add T3 — rejected packet-limit Add surfaces as StatusError"
```

---

### Task 5: `cmd/wifisec` — pflag-based CLI flags and `known-networks add`

**Files:**
- Modify: `cmd/wifisec/main.go`
- Create: `cmd/wifisec/knownnetworks.go`

**Interfaces:**
- Consumes: `whitelist.List` (Task 1); `model.Profile`, `model.NewNetworkInfo` (M1); `platform.Adapter` (M2).
- Produces: `func parseProfile(s string) (model.Profile, error)` (in `main.go`), `func runKnownNetworksAdd()` (in `knownnetworks.go`).

This task only adds flag parsing and the `known-networks add` subcommand — it does **not** yet wire the confirmation flow or the BSSID watcher into `runReal()` (that's Task 7, after Task 6 builds the confirmation program those flags feed into).

- [ ] **Step 1: Add pflag to go.mod**

Run: `go get github.com/spf13/pflag@latest`

- [ ] **Step 2: Write `cmd/wifisec/knownnetworks.go`**

```go
package main

import (
	"fmt"
	"os"

	"github.com/Maulana-anjari/wifisec/internal/model"
	"github.com/Maulana-anjari/wifisec/internal/platform"
	"github.com/Maulana-anjari/wifisec/internal/whitelist"
)

// runKnownNetworksAdd implements `wifisec known-networks add` (spec
// §9.1): hash the currently-associated network's BSSID and add it to
// the whitelist, so future runs see KnownNetwork == true for it
// (gating spec G5's second full-profile confirmation).
func runKnownNetworksAdd() {
	info, err := platform.New().WiFiInfo()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: read WiFi info:", err)
		os.Exit(3)
	}
	if !info.Available || info.BSSID == "" {
		fmt.Fprintln(os.Stderr, "error: no connected WiFi network to add")
		os.Exit(3)
	}

	net := model.NewNetworkInfo(info.SSID, info.BSSID)
	list, err := whitelist.Load()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: load whitelist:", err)
		os.Exit(3)
	}
	list.Add(net.BSSIDHash, info.SSID)
	if err := list.Save(); err != nil {
		fmt.Fprintln(os.Stderr, "error: save whitelist:", err)
		os.Exit(3)
	}
	fmt.Printf("Ditambahkan ke whitelist: %s\n", info.SSID)
}
```

- [ ] **Step 3: Add flag parsing and subcommand dispatch to `main.go`**

Modify `cmd/wifisec/main.go`. Read the current file first, then apply these changes:

Add to the import block:
```go
	pflag "github.com/spf13/pflag"
```

Replace `main()` with:

```go
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
```

Add `"strings"` to the import block (used by the `strings.HasPrefix` dispatch above).

Change `runReal`'s signature from `func runReal() {` to `func runReal(requested model.Profile, ownsNetwork bool) {` — leave its body exactly as-is for this task (it still ignores both new parameters and always runs at `model.ProfilePassive`; wiring them is Task 7). Add a one-line `_ = requested; _ = ownsNetwork` **only if** the compiler complains about unused parameters — Go does not error on unused function parameters (only unused locals), so this should not be necessary; if you find yourself tempted to add it, that's a sign the signature or a lint tool is confused, not a real requirement — check first before adding.

- [ ] **Step 4: Verify it builds and the existing behavior is unchanged**

Run:
```bash
go build ./...
go vet ./...
go test ./...
go run ./cmd/wifisec testdata/fixtures/clean_home.json   # M1 fixture-file mode: must still work
```
Expected: all pass; `--profile`/`--i-own-this-network` parse but don't yet change behavior (`runReal` still hardcodes passive internally, per Step 3's note) — that wiring is Task 7. Also manually confirm `go run ./cmd/wifisec --profile bogus` exits 4 with a clear error message, and `go run ./cmd/wifisec known-networks add` either succeeds (if this machine has an active WiFi connection) or exits 3 with a clear message (if not) — either outcome is fine, report which one happened.

- [ ] **Step 5: Commit**

```bash
git add cmd/wifisec/main.go cmd/wifisec/knownnetworks.go go.mod go.sum
git commit -m "feat(cmd): add pflag CLI flags and known-networks add subcommand"
```

---

### Task 6: `cmd/wifisec` — interactive confirmation program (spec G2/G3/G5)

**Files:**
- Create: `cmd/wifisec/confirm.go`
- Test: `cmd/wifisec/confirm_test.go`

**Interfaces:**
- Consumes: `guard.ConfirmStep`, `guard.ConfirmRaise`, `guard.ConfirmFullUnknown` (Task 2); `tui.ProfileDialog` (M1, exported, unmodified); `model.Profile` (M1).
- Produces: `type confirmModel struct{...}`, `func newConfirmModel(target model.Profile, knownNetwork bool, steps []guard.ConfirmStep) confirmModel`, satisfying `tea.Model` (`Init`, `Update`, `View`), plus `func (m confirmModel) Result() (confirmed bool)`.

This is a small, standalone bubbletea program — **not** part of `internal/tui.Model**. It's constructed, run via its own `tea.NewProgram(...).Run()`, and discarded before `tui.New(result)` is ever called (Task 7 wires the call site).

- [ ] **Step 1: Write the failing tests**

Create `cmd/wifisec/confirm_test.go`:

```go
package main

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/Maulana-anjari/wifisec/internal/guard"
	"github.com/Maulana-anjari/wifisec/internal/model"
)

func TestConfirmModelTypingBuildsUpTyped(t *testing.T) {
	m := newConfirmModel(model.ProfileMinimal, true, []guard.ConfirmStep{guard.ConfirmRaise})
	for _, r := range "minimal" {
		updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
		m = updated.(confirmModel)
	}
	if m.dialog.Typed != "minimal" {
		t.Errorf("Typed = %q, want %q", m.dialog.Typed, "minimal")
	}
}

func TestConfirmModelBackspaceRemovesLastRune(t *testing.T) {
	m := newConfirmModel(model.ProfileMinimal, true, []guard.ConfirmStep{guard.ConfirmRaise})
	m.dialog.Typed = "minima"
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyBackspace})
	m = updated.(confirmModel)
	if m.dialog.Typed != "minim" {
		t.Errorf("Typed after backspace = %q, want %q", m.dialog.Typed, "minim")
	}
}

func TestConfirmModelEnterWithWrongTextDoesNotAdvance(t *testing.T) {
	m := newConfirmModel(model.ProfileMinimal, true, []guard.ConfirmStep{guard.ConfirmRaise})
	m.dialog.Typed = "wrong"
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(confirmModel)
	if m.done || m.aborted {
		t.Error("wrong text must not confirm or abort")
	}
	if m.stepIdx != 0 {
		t.Errorf("stepIdx = %d, want 0 (must not advance on wrong text)", m.stepIdx)
	}
}

func TestConfirmModelEnterWithRightTextAdvancesThenCompletes(t *testing.T) {
	m := newConfirmModel(model.ProfileMinimal, true, []guard.ConfirmStep{guard.ConfirmRaise})
	m.dialog.Typed = "minimal"
	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(confirmModel)
	if !m.done {
		t.Error("expected done=true after the only step is confirmed")
	}
	if cmd == nil {
		t.Error("expected a tea.Quit command once done")
	}
}

func TestConfirmModelTwoStepsRequiresBothConfirmations(t *testing.T) {
	m := newConfirmModel(model.ProfileFull, false, []guard.ConfirmStep{guard.ConfirmRaise, guard.ConfirmFullUnknown})
	m.dialog.Typed = "full"
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(confirmModel)
	if m.done {
		t.Fatal("must not be done after only the first of two steps")
	}
	if m.stepIdx != 1 {
		t.Fatalf("stepIdx = %d, want 1 after first step confirmed", m.stepIdx)
	}
	if m.dialog.Typed != "" {
		t.Errorf("Typed should reset between steps, got %q", m.dialog.Typed)
	}

	m.dialog.Typed = "full"
	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(confirmModel)
	if !m.done || cmd == nil {
		t.Error("expected done=true and tea.Quit after the second step is confirmed")
	}
}

func TestConfirmModelEscAborts(t *testing.T) {
	m := newConfirmModel(model.ProfileMinimal, true, []guard.ConfirmStep{guard.ConfirmRaise})
	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m = updated.(confirmModel)
	if !m.aborted || cmd == nil {
		t.Error("expected aborted=true and tea.Quit on Esc")
	}
}

func TestConfirmModelResultReflectsDoneNotAborted(t *testing.T) {
	m := newConfirmModel(model.ProfilePassive, true, nil)
	if m.Result() {
		t.Error("Result() should be false before done")
	}
	m.done = true
	if !m.Result() {
		t.Error("Result() should be true once done and not aborted")
	}
	m.aborted = true
	if m.Result() {
		t.Error("Result() should be false if aborted, even if done was set")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./cmd/wifisec/... -run TestConfirm -v`
Expected: FAIL — `confirmModel` doesn't exist yet.

- [ ] **Step 3: Write the implementation**

Create `cmd/wifisec/confirm.go`:

```go
package main

import (
	"fmt"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/Maulana-anjari/wifisec/internal/guard"
	"github.com/Maulana-anjari/wifisec/internal/model"
	"github.com/Maulana-anjari/wifisec/internal/tui"
)

// confirmModel is a small, standalone bubbletea program that walks
// the user through the confirmation steps guard.Resolve computed
// (spec G2/G3/G5). It is deliberately NOT part of internal/tui.Model —
// it runs to completion before tui.New(result) is ever called, so
// internal/tui never needs to import guard.
type confirmModel struct {
	target  model.Profile
	steps   []guard.ConfirmStep
	stepIdx int
	dialog  tui.ProfileDialog
	done    bool
	aborted bool
}

func newConfirmModel(target model.Profile, knownNetwork bool, steps []guard.ConfirmStep) confirmModel {
	return confirmModel{
		target: target,
		steps:  steps,
		dialog: tui.ProfileDialog{Target: target, KnownNetwork: knownNetwork},
	}
}

func (m confirmModel) Init() tea.Cmd { return nil }

func (m confirmModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	keyMsg, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}
	switch keyMsg.Type {
	case tea.KeyEsc, tea.KeyCtrlC:
		m.aborted = true
		return m, tea.Quit
	case tea.KeyEnter:
		if m.dialog.Confirmed() {
			m.stepIdx++
			if m.stepIdx >= len(m.steps) {
				m.done = true
				return m, tea.Quit
			}
			m.dialog.Typed = ""
		}
		return m, nil
	case tea.KeyBackspace:
		if len(m.dialog.Typed) > 0 {
			m.dialog.Typed = m.dialog.Typed[:len(m.dialog.Typed)-1]
		}
		return m, nil
	case tea.KeyRunes:
		m.dialog.Typed += string(keyMsg.Runes)
		return m, nil
	}
	return m, nil
}

func (m confirmModel) View() string {
	if len(m.steps) == 0 {
		return ""
	}
	var warning string
	if m.steps[m.stepIdx] == guard.ConfirmFullUnknown {
		warning = "Jaringan ini tidak ada di whitelist Anda — konfirmasi kedua diperlukan.\n\n"
	}
	return warning + m.dialog.View() + "\n(Enter untuk konfirmasi, Esc untuk batal)\n"
}

// Result reports whether every confirmation step was completed
// without the user aborting.
func (m confirmModel) Result() bool {
	return m.done && !m.aborted
}

// runConfirm runs the confirmation program to completion and reports
// whether the user completed every step. It never returns an error —
// an unreadable terminal or a bubbletea failure is treated the same
// as an abort, since proceeding without confirmation is never safe.
func runConfirm(target model.Profile, knownNetwork bool, steps []guard.ConfirmStep) bool {
	if len(steps) == 0 {
		return true
	}
	p := tea.NewProgram(newConfirmModel(target, knownNetwork, steps))
	final, err := p.Run()
	if err != nil {
		fmt.Println("confirmation aborted:", err)
		return false
	}
	return final.(confirmModel).Result()
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./cmd/wifisec/... -v`
Expected: PASS (7 new tests)

- [ ] **Step 5: Commit**

```bash
git add cmd/wifisec/confirm.go cmd/wifisec/confirm_test.go
git commit -m "feat(cmd): add standalone confirmation program for G2/G3/G5"
```

---

### Task 7: Wire profile resolution, confirmation, whitelist, and the BSSID watcher into `runReal`

**Files:**
- Modify: `cmd/wifisec/main.go`

**Interfaces:**
- Consumes: everything from Tasks 1–6, plus `checks.Run`, `interpret.Apply` (M2).

- [ ] **Step 1: Rewrite `runReal` to use the requested profile end-to-end**

Read the current `runReal` in `cmd/wifisec/main.go` first, then replace it with:

```go
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
	if len(steps) > 0 {
		if !runConfirm(requested, netInfo.KnownNetwork, steps) {
			fmt.Fprintln(os.Stderr, "dibatalkan: konfirmasi profil tidak diselesaikan")
			os.Exit(4)
		}
	}

	defs := reg.Filter(effective)
	builtCheckers, unimplemented := buildCheckers(defs)
	for _, id := range unimplemented {
		fmt.Fprintf(os.Stderr, "warning: %s has no implementation yet, skipping\n", id)
	}

	passiveOnlyIDs := make(map[string]bool, len(defs))
	for _, d := range defs {
		passiveOnlyIDs[d.ID] = true
	}
	var skipped []model.Check
	for _, def := range reg.Checks {
		if passiveOnlyIDs[def.ID] {
			continue
		}
		skipped = append(skipped, model.Check{
			ID: def.ID, Layer: def.Layer, Title: def.Title, ProfileRequired: def.ProfileRequired,
			Status: model.StatusSkipped, Confidence: model.ConfidenceLow,
			Control: model.Control{Performed: false, Reason: "profile_does_not_allow"},
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
	if wifiInfo.Available {
		go guard.Watch(ctx, adapter, wifiInfo.BSSID, 2*time.Second, func(string) {
			downgraded.Store(true)
			cancel()
		})
	}

	start := time.Now()
	results := append([]model.Check{}, skipped...)
	for c := range checks.Run(ctx, builtCheckers, cc) {
		results = append(results, c)
	}

	if downgraded.Load() {
		effective = model.ProfilePassive
	}

	findings, verdict := interpret.Apply(results)

	result := model.Result{
		SchemaVersion: model.SchemaVersionV1,
		ToolVersion:   "0.3.0-m3",
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
```

Add `"github.com/Maulana-anjari/wifisec/internal/whitelist"` and `"sync/atomic"` to the import block. Leave `netInfo.OUI` unset (empty string) in this task — a real OUI-from-BSSID extraction already exists in `internal/checks/wifi/bssid_vendor.go`'s `ouiFromBSSID` but it's unexported and check-package-local, and nothing currently reads `Result.Network.OUI`; wiring it is out of scope for this milestone.

- [ ] **Step 2: Write `exitCodeFor`**

Add to `cmd/wifisec/main.go`:

```go
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
```

- [ ] **Step 3: Verify it builds and runs correctly**

Run:
```bash
go build ./...
go vet ./...
go test ./...
```
Expected: all pass.

Manually run (pty workaround if `/dev/tty` is unavailable in this sandbox, same as Milestone 2's Task 8/9 needed):
```bash
go run ./cmd/wifisec                              # passive, default: no confirmation dialog should appear
go run ./cmd/wifisec --profile minimal            # should show the ConfirmRaise dialog; typing "minimal" + Enter should proceed
go run ./cmd/wifisec --profile minimal            # then press Esc instead: should abort with exit code 4, no TUI shown
```
Report exactly what happened for each, including the exit code (`echo $?` after each run).

- [ ] **Step 4: Commit**

```bash
git add cmd/wifisec/main.go
git commit -m "feat(cmd): wire profile resolution, confirmation, whitelist, and BSSID watch into runReal"
```

---

### Task 8: T4 — auto-downgrade integration test + final milestone verification

**Files:**
- Create: `internal/guard/downgrade_integration_test.go`

**Interfaces:**
- Consumes: `guard.Watch` (Task 3); `checks.Run`, `checks.Checker`, `checks.CheckContext` (M2).

Task 3's `bssid_watch_test.go` already unit-tests `Watch` in isolation. This task adds the integration-level assertion spec T4 actually asks for: "assert profil turun ke passive **dan context dibatalkan**" — i.e., that a real, in-flight `checks.Run` call actually observes the cancellation, not just that `Watch`'s callback fires.

- [ ] **Step 1: Write the test**

Create `internal/guard/downgrade_integration_test.go`:

```go
package guard_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Maulana-anjari/wifisec/internal/checks"
	"github.com/Maulana-anjari/wifisec/internal/guard"
	"github.com/Maulana-anjari/wifisec/internal/model"
	"github.com/Maulana-anjari/wifisec/internal/platform"
	"github.com/Maulana-anjari/wifisec/internal/registry"
)

// bssidFlippingAdapter reports one BSSID for the first call, then a
// different one forever after — simulating an AP change mid-run.
type bssidFlippingAdapter struct{ calls int }

func (a *bssidFlippingAdapter) WiFiInfo() (platform.WiFiInfo, error) {
	a.calls++
	bssid := "AA:AA:AA:AA:AA:AA"
	if a.calls > 1 {
		bssid = "CC:CC:CC:CC:CC:CC"
	}
	return platform.WiFiInfo{Available: true, BSSID: bssid}, nil
}
func (a *bssidFlippingAdapter) NetConfig() (platform.NetConfig, error)     { return platform.NetConfig{}, nil }
func (a *bssidFlippingAdapter) ProxyConfig() (platform.ProxyConfig, error) { return platform.ProxyConfig{}, nil }
func (a *bssidFlippingAdapter) TrustStoreCAs() ([]platform.CACert, error)  { return nil, nil }
func (a *bssidFlippingAdapter) RoutingTable() ([]platform.Route, error)    { return nil, nil }

// slowChecker blocks until ctx is cancelled or a generous timeout
// elapses, so the test can observe cancellation actually propagating.
type slowChecker struct{ def registry.CheckDefinition }

func (c slowChecker) Definition() registry.CheckDefinition { return c.def }
func (c slowChecker) Run(ctx context.Context, cc checks.CheckContext) model.Check {
	select {
	case <-ctx.Done():
		return model.Check{ID: c.def.ID, Status: model.StatusError, Error: "cancelled: " + ctx.Err().Error()}
	case <-time.After(5 * time.Second):
		return model.Check{ID: c.def.ID, Status: model.StatusNormal}
	}
}

func TestT4AutoDowngradeOnBSSIDChangeCancelsRunningChecks(t *testing.T) {
	adapter := &bssidFlippingAdapter{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// downgraded is read from this goroutine after the loop below and
	// written from the Watch goroutine's callback — an atomic.Bool
	// avoids the same data race the production code in cmd/wifisec's
	// runReal must also avoid (see that task's note): a plain bool here
	// would have no synchronized happens-before edge with the read.
	var downgraded atomic.Bool
	go guard.Watch(ctx, adapter, "AA:AA:AA:AA:AA:AA", 5*time.Millisecond, func(string) {
		downgraded.Store(true)
		cancel()
	})

	def := registry.CheckDefinition{ID: "test.slow", Layer: model.LayerLocal, Title: "slow"}
	var got model.Check
	for c := range checks.Run(ctx, []checks.Checker{slowChecker{def: def}}, checks.CheckContext{}) {
		got = c
	}

	if !downgraded.Load() {
		t.Error("expected the watcher to report a BSSID change")
	}
	if got.Status != model.StatusError {
		t.Errorf("Status = %s, want error (the running check must observe ctx cancellation, spec T4/G4)", got.Status)
	}
}
```

- [ ] **Step 2: Run test to verify it passes**

Run: `go test ./internal/guard/... -run TestT4 -v`
Expected: PASS

- [ ] **Step 3: Full milestone verification**

Run:
```bash
go build ./...
go vet ./...
go test ./... -v
```
Expected: all pass, no warnings. Confirm against spec §11 M3 exit criteria:
- [ ] T2 passes (`internal/registry/registry_test.go`'s pre-existing `TestFilterRespectsProfileLevel` — already covered since Milestone 1, no new work needed; just confirm it's still green)
- [ ] T3 passes (Task 4, this milestone)
- [ ] T4 passes (this task)
- [ ] Every G1–G7 rule has corresponding code: G1 (flag default + no persistence, Task 5), G2/G3 (confirm dialog, Task 6), G4 (BSSID watch, Task 3), G5 (second confirmation step, Task 2/6), G6 (ownership-flag rejection, Task 2), G7 (whitelist, Task 1)
- [ ] Exit codes (§9.2) computed and returned (Task 7)

- [ ] **Step 4: Commit**

```bash
git add internal/guard/downgrade_integration_test.go
git commit -m "test(guard): add T4 — BSSID change auto-downgrades and cancels running checks"
```
