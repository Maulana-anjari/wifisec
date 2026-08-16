# Milestone 1: Foundation — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the data model (spec §4), the declarative check registry loader (spec §6), all six JSON test fixtures, and a fully navigable bubbletea TUI that renders those fixtures — with zero network code anywhere in this milestone.

**Architecture:** Three independent packages (`model`, `registry`, `tui`) plus a thin `cmd/wifisec` entrypoint that loads a JSON `Result` file and launches the TUI. `model` has no internal dependencies; `registry` depends only on `model`; `tui` depends only on `model`. This mirrors the dependency rule in spec §3.1 and lets each package be tested in isolation, entirely offline.

**Tech Stack:** Go 1.22+, `github.com/charmbracelet/bubbletea`, `github.com/charmbracelet/lipgloss`, `gopkg.in/yaml.v3`. (`miekg/dns` and `spf13/pflag` are not needed until checks and CLI flags exist in later milestones — do not add them yet.)

**Spec:** `SPEC-wifisec.md` (repo root) — this plan implements §4 (types), §6 (registry data), §8.2 (fixtures), §9.3 (TUI screens), and the M1 exit criteria in §11.

## Global Constraints

- Go module path: `github.com/Maulana-anjari/wifisec` (matches the GitHub remote).
- Go 1.22+ (spec header table).
- Allowed dependencies for this milestone: `github.com/charmbracelet/bubbletea`, `github.com/charmbracelet/lipgloss`, `gopkg.in/yaml.v3`. No other third-party module may be added without explicit approval (spec §3.3, §0 rule 5).
- Type names and JSON field names in `internal/model` must match spec §4 **exactly** — do not add, rename, or remove fields (spec §0 rule 1).
- `internal/model` must not import any other internal package. `internal/tui` must only import `internal/model`. `internal/checks` (not built in this milestone) must never import `internal/tui` (spec §3.1).
- No network code of any kind in this milestone — no `net.Dial`, no DNS, no HTTP calls, anywhere (spec §11 M1: "Tidak ada kode jaringan sama sekali").
- Code style: short functions, no speculative abstraction, errors handled at the call site, avoid generics unless they remove real duplication, avoid reflection entirely (spec §0 rule 3).
- M1 is done when all six fixtures render and can be navigated, and tests T5, T6, T7, T9 pass (spec §11).

---

### Task 1: Module setup + `model.Profile`

**Files:**
- Create: `go.mod`
- Create: `internal/model/profile.go`
- Test: `internal/model/profile_test.go`

**Interfaces:**
- Produces: `type Profile string`, consts `ProfilePassive`, `ProfileMinimal`, `ProfileStandard`, `ProfileFull`; methods `(Profile) Level() int`, `(Profile) EstimatedPackets() int`, `(Profile) Allows(required Profile) bool`.

- [ ] **Step 1: Initialize the Go module**

Run:
```bash
cd /home/maul/Kerjaan/personal-project/wifisec
go mod init github.com/Maulana-anjari/wifisec
go get github.com/charmbracelet/bubbletea@latest
go get github.com/charmbracelet/lipgloss@latest
go get gopkg.in/yaml.v3@latest
```
Expected: `go.mod` and `go.sum` created, listing the three dependencies.

- [ ] **Step 2: Write the failing test**

Create `internal/model/profile_test.go`:

```go
package model

import "testing"

func TestProfileLevel(t *testing.T) {
	cases := []struct {
		p    Profile
		want int
	}{
		{ProfilePassive, 0},
		{ProfileMinimal, 1},
		{ProfileStandard, 2},
		{ProfileFull, 3},
	}
	for _, c := range cases {
		if got := c.p.Level(); got != c.want {
			t.Errorf("%s.Level() = %d, want %d", c.p, got, c.want)
		}
	}
}

func TestProfileAllows(t *testing.T) {
	if !ProfileStandard.Allows(ProfileMinimal) {
		t.Error("standard should allow minimal-required checks")
	}
	if ProfileMinimal.Allows(ProfileStandard) {
		t.Error("minimal should not allow standard-required checks")
	}
	if !ProfilePassive.Allows(ProfilePassive) {
		t.Error("a profile should allow its own level")
	}
}

func TestProfileEstimatedPacketsMonotonic(t *testing.T) {
	profiles := []Profile{ProfilePassive, ProfileMinimal, ProfileStandard, ProfileFull}
	for i := 1; i < len(profiles); i++ {
		if profiles[i].EstimatedPackets() < profiles[i-1].EstimatedPackets() {
			t.Errorf("%s.EstimatedPackets() < %s.EstimatedPackets(), estimates must not decrease as profile rises", profiles[i], profiles[i-1])
		}
	}
	if ProfilePassive.EstimatedPackets() != 0 {
		t.Errorf("passive.EstimatedPackets() = %d, want 0 (spec P1: passive sends nothing)", ProfilePassive.EstimatedPackets())
	}
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./internal/model/... -run TestProfile -v`
Expected: FAIL — package `model` / `Profile` type does not exist yet.

- [ ] **Step 4: Write the implementation**

Create `internal/model/profile.go`:

```go
package model

// Profile controls how intrusive checks are allowed to be (spec §4.1).
type Profile string

const (
	ProfilePassive  Profile = "passive"
	ProfileMinimal  Profile = "minimal"
	ProfileStandard Profile = "standard"
	ProfileFull     Profile = "full"
)

var profileLevel = map[Profile]int{
	ProfilePassive:  0,
	ProfileMinimal:  1,
	ProfileStandard: 2,
	ProfileFull:     3,
}

// estimatedPackets is a rough, static per-profile guidance value shown
// in the raise-profile confirmation dialog (spec §5.2 G3). It sums the
// approximate packet counts from spec §6.2-§6.4; it is not a hard
// limit — guard.PacketCounter enforces the real limit at runtime.
var estimatedPackets = map[Profile]int{
	ProfilePassive:  0,
	ProfileMinimal:  2,
	ProfileStandard: 50,
	ProfileFull:     150,
}

// Level returns the numeric ordering for profile comparison:
// passive=0, minimal=1, standard=2, full=3.
func (p Profile) Level() int {
	return profileLevel[p]
}

// EstimatedPackets returns the approximate packet count to display in
// the confirmation dialog (spec §4.1).
func (p Profile) EstimatedPackets() int {
	return estimatedPackets[p]
}

// Allows reports whether this profile permits a check that requires
// the given profile (spec §4.1, §5.2 G-rules).
func (p Profile) Allows(required Profile) bool {
	return p.Level() >= required.Level()
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `go test ./internal/model/... -run TestProfile -v`
Expected: PASS (3 tests)

- [ ] **Step 6: Commit**

```bash
git add go.mod go.sum internal/model/profile.go internal/model/profile_test.go
git commit -m "feat(model): add Profile type with level, packet estimate, and allows"
```

---

### Task 2: `model.Check` + `ValidateCheck` (T6)

**Files:**
- Create: `internal/model/check.go`
- Test: `internal/model/check_test.go`

**Interfaces:**
- Consumes: `model.Profile` (Task 1).
- Produces: `type CheckStatus string` (`StatusNormal`, `StatusAnomalous`, `StatusInconclusive`, `StatusSkipped`, `StatusError`); `type Confidence string` (`ConfidenceHigh`, `ConfidenceMedium`, `ConfidenceLow`); `type Layer string` (`LayerLocal`, `LayerWiFi`, `LayerDNS`, `LayerL4`, `LayerTLS`, `LayerHTTP`, `LayerPerf`); `type Control struct{...}`; `type Check struct{...}`; `func ValidateCheck(c Check, selfEvident bool) error`.

- [ ] **Step 1: Write the failing tests**

Create `internal/model/check_test.go`:

```go
package model

import "testing"

func TestValidateCheckRejectsSkippedWithPackets(t *testing.T) {
	c := Check{ID: "x", Status: StatusSkipped, PacketsSent: 1}
	if err := ValidateCheck(c, false); err == nil {
		t.Error("expected error for skipped check with packets_sent > 0")
	}
}

func TestValidateCheckRejectsHighConfidenceAnomalousWithoutControl(t *testing.T) {
	c := Check{
		ID:         "x",
		Status:     StatusAnomalous,
		Confidence: ConfidenceHigh,
		Control:    Control{Performed: false},
	}
	if err := ValidateCheck(c, false); err == nil {
		t.Error("expected error for non-self-evident anomalous+high-confidence check without a control")
	}
	if err := ValidateCheck(c, true); err != nil {
		t.Errorf("self-evident check should be allowed: %v", err)
	}
}

func TestValidateCheckRejectsJudgmentalObservedKeys(t *testing.T) {
	for _, key := range []string{"blocked", "is_dangerous", "UNSAFE_score"} {
		c := Check{
			ID:       "x",
			Status:   StatusNormal,
			Observed: map[string]any{key: true},
		}
		if err := ValidateCheck(c, false); err == nil {
			t.Errorf("expected error for judgmental observed key %q", key)
		}
	}
}

func TestValidateCheckAcceptsValidCheck(t *testing.T) {
	c := Check{
		ID:         "x",
		Status:     StatusAnomalous,
		Confidence: ConfidenceMedium,
		Control:    Control{Performed: false},
		Observed:   map[string]any{"issuer": "Let's Encrypt R3"},
	}
	if err := ValidateCheck(c, false); err != nil {
		t.Errorf("expected valid check to pass, got: %v", err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/model/... -run TestValidateCheck -v`
Expected: FAIL — `Check`, `ValidateCheck`, etc. do not exist yet.

- [ ] **Step 3: Write the implementation**

Create `internal/model/check.go`:

```go
package model

import (
	"fmt"
	"strings"
)

type CheckStatus string

const (
	StatusNormal       CheckStatus = "normal"
	StatusAnomalous    CheckStatus = "anomalous"
	StatusInconclusive CheckStatus = "inconclusive"
	StatusSkipped      CheckStatus = "skipped"
	StatusError        CheckStatus = "error"
)

type Confidence string

const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
)

type Layer string

const (
	LayerLocal Layer = "local"
	LayerWiFi  Layer = "wifi"
	LayerDNS   Layer = "dns"
	LayerL4    Layer = "l4"
	LayerTLS   Layer = "tls"
	LayerHTTP  Layer = "http"
	LayerPerf  Layer = "perf"
)

type Control struct {
	Performed bool   `json:"performed"`
	Reason    string `json:"reason,omitempty"`
	Result    string `json:"result,omitempty"`
}

type Check struct {
	ID              string         `json:"id"`
	Layer           Layer          `json:"layer"`
	Title           string         `json:"title"`
	ProfileRequired Profile        `json:"profile_required"`
	Status          CheckStatus    `json:"status"`
	Confidence      Confidence     `json:"confidence"`
	Target          string         `json:"target,omitempty"`
	Observed        map[string]any `json:"observed,omitempty"`
	Expected        map[string]any `json:"expected,omitempty"`
	Control         Control        `json:"control"`
	PacketsSent     int            `json:"packets_sent"`
	DurationMS      int64          `json:"duration_ms"`
	Error           string         `json:"error,omitempty"`
}

// judgmentalKeywords are assessment terms forbidden in Check.Observed
// (spec §4.2, P2: observation must stay separate from judgment).
var judgmentalKeywords = []string{"blocked", "dangerous", "unsafe"}

// ValidateCheck enforces the structural invariants from spec §4.2.
// selfEvident is the check's registry-level CheckDefinition.SelfEvident
// flag (spec §4.6, §6.1) — Check itself carries no such field, so
// callers with registry access (checks.Runner in a later milestone)
// must pass it in.
func ValidateCheck(c Check, selfEvident bool) error {
	if c.Status == StatusSkipped && c.PacketsSent > 0 {
		return fmt.Errorf("check %s: status skipped requires packets_sent == 0, got %d", c.ID, c.PacketsSent)
	}
	if c.Status == StatusAnomalous && !c.Control.Performed && c.Confidence == ConfidenceHigh && !selfEvident {
		return fmt.Errorf("check %s: anomalous status without a performed control requires confidence below high unless self_evident", c.ID)
	}
	for key := range c.Observed {
		lower := strings.ToLower(key)
		for _, kw := range judgmentalKeywords {
			if strings.Contains(lower, kw) {
				return fmt.Errorf("check %s: observed key %q contains judgment term %q (see P2)", c.ID, key, kw)
			}
		}
	}
	return nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/model/... -run TestValidateCheck -v`
Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
git add internal/model/check.go internal/model/check_test.go
git commit -m "feat(model): add Check types and ValidateCheck (T6)"
```

---

### Task 3: `model.Finding` + `ValidateFinding`

**Files:**
- Create: `internal/model/finding.go`
- Test: `internal/model/finding_test.go`

**Interfaces:**
- Consumes: `model.Confidence` (Task 2).
- Produces: `type Severity string` (`SeverityCritical`, `SeverityWarning`, `SeverityInfo`); `type Finding struct{...}`; `func ValidateFinding(f Finding, validCheckIDs map[string]bool) error`.

- [ ] **Step 1: Write the failing tests**

Create `internal/model/finding_test.go`:

```go
package model

import "testing"

func TestValidateFindingRequiresBasedOn(t *testing.T) {
	f := Finding{ID: "x", BasedOn: nil}
	if err := ValidateFinding(f, map[string]bool{"check.a": true}); err == nil {
		t.Error("expected error for finding with empty based_on")
	}
}

func TestValidateFindingRequiresKnownCheckIDs(t *testing.T) {
	f := Finding{ID: "x", BasedOn: []string{"check.unknown"}}
	if err := ValidateFinding(f, map[string]bool{"check.a": true}); err == nil {
		t.Error("expected error for finding based_on an ID not present in results")
	}
}

func TestValidateFindingAcceptsValid(t *testing.T) {
	f := Finding{ID: "x", BasedOn: []string{"check.a"}}
	if err := ValidateFinding(f, map[string]bool{"check.a": true}); err != nil {
		t.Errorf("expected valid finding to pass, got: %v", err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/model/... -run TestValidateFinding -v`
Expected: FAIL — `Finding`/`ValidateFinding` do not exist yet.

- [ ] **Step 3: Write the implementation**

Create `internal/model/finding.go`:

```go
package model

import "fmt"

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityWarning  Severity = "warning"
	SeverityInfo     Severity = "info"
)

type Finding struct {
	ID                 string     `json:"id"`
	Severity           Severity   `json:"severity"`
	Confidence         Confidence `json:"confidence"`
	Title              string     `json:"title"`
	Explanation        string     `json:"explanation"`
	Impact             []string   `json:"impact,omitempty"`
	BasedOn            []string   `json:"based_on"`
	Recommendation     string     `json:"recommendation"`
	FalsePositiveHints []string   `json:"false_positive_hints,omitempty"`
}

// ValidateFinding enforces spec §4.3: a Finding must cite at least one
// check ID that actually exists among the run's results.
func ValidateFinding(f Finding, validCheckIDs map[string]bool) error {
	if len(f.BasedOn) == 0 {
		return fmt.Errorf("finding %s: based_on must not be empty", f.ID)
	}
	for _, id := range f.BasedOn {
		if !validCheckIDs[id] {
			return fmt.Errorf("finding %s: based_on references unknown check id %q", f.ID, id)
		}
	}
	return nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/model/... -run TestValidateFinding -v`
Expected: PASS (3 tests)

- [ ] **Step 5: Commit**

```bash
git add internal/model/finding.go internal/model/finding_test.go
git commit -m "feat(model): add Finding type and ValidateFinding"
```

---

### Task 4: `model.Verdict` + `ValidateVerdict` (T7)

**Files:**
- Create: `internal/model/verdict.go`
- Test: `internal/model/verdict_test.go`

**Interfaces:**
- Consumes: `model.Check`, `model.StatusSkipped` (Task 2).
- Produces: `type Safety string` (`SafetyOK`, `SafetyCaution`, `SafetyAvoid`, `SafetyUnknown`); `type Verdict struct{...}`; `func ValidateVerdict(checks []Check, v Verdict) error`.

- [ ] **Step 1: Write the failing tests**

Create `internal/model/verdict_test.go`:

```go
package model

import "testing"

func TestValidateVerdictRejectsSkippedWithoutBlindSpots(t *testing.T) {
	checks := []Check{{ID: "a", Status: StatusSkipped}}
	v := Verdict{Safety: SafetyUnknown, BlindSpots: nil}
	if err := ValidateVerdict(checks, v); err == nil {
		t.Error("expected error: skipped check present but blind_spots is empty (P4)")
	}
}

func TestValidateVerdictAcceptsSkippedWithBlindSpots(t *testing.T) {
	checks := []Check{{ID: "a", Status: StatusSkipped}}
	v := Verdict{Safety: SafetyUnknown, BlindSpots: []string{"DNS not checked"}}
	if err := ValidateVerdict(checks, v); err != nil {
		t.Errorf("expected valid verdict to pass, got: %v", err)
	}
}

func TestValidateVerdictAcceptsNoSkippedNoBlindSpots(t *testing.T) {
	checks := []Check{{ID: "a", Status: StatusNormal}}
	v := Verdict{Safety: SafetyOK, BlindSpots: nil}
	if err := ValidateVerdict(checks, v); err != nil {
		t.Errorf("expected valid verdict to pass, got: %v", err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/model/... -run TestValidateVerdict -v`
Expected: FAIL — `Verdict`/`ValidateVerdict` do not exist yet.

- [ ] **Step 3: Write the implementation**

Create `internal/model/verdict.go`:

```go
package model

import "fmt"

type Safety string

const (
	SafetyOK      Safety = "ok"
	SafetyCaution Safety = "caution"
	SafetyAvoid   Safety = "avoid"
	SafetyUnknown Safety = "unknown"
)

type Verdict struct {
	Safety      Safety            `json:"safety"`
	Score       int               `json:"score"`
	Headline    string            `json:"headline"`
	TopFindings []string          `json:"top_findings"`
	BlindSpots  []string          `json:"blind_spots"`
	UseCases    map[string]string `json:"use_cases"`
}

// ValidateVerdict enforces spec §4.4 / P4: any skipped check must be
// reflected in the verdict's BlindSpots.
func ValidateVerdict(checks []Check, v Verdict) error {
	for _, c := range checks {
		if c.Status == StatusSkipped {
			if len(v.BlindSpots) == 0 {
				return fmt.Errorf("verdict: checks include a skipped status but blind_spots is empty (see P4)")
			}
			return nil
		}
	}
	return nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/model/... -run TestValidateVerdict -v`
Expected: PASS (3 tests)

- [ ] **Step 5: Commit**

```bash
git add internal/model/verdict.go internal/model/verdict_test.go
git commit -m "feat(model): add Verdict type and ValidateVerdict (T7)"
```

---

### Task 5: `model.Result` + `NetworkInfo` (T9)

**Files:**
- Create: `internal/model/result.go`
- Test: `internal/model/result_test.go`

**Interfaces:**
- Consumes: `model.Profile`, `model.Check`, `model.Finding`, `model.Verdict` (Tasks 1-4).
- Produces: `type NetworkInfo struct{...}`; `func NewNetworkInfo(ssid, bssid string) NetworkInfo`; `func (NetworkInfo) SSIDPlain() string`; `func (NetworkInfo) BSSIDPlain() string`; `type Result struct{...}`; `const SchemaVersionV1 = "1.0"`.

- [ ] **Step 1: Write the failing tests**

Create `internal/model/result_test.go`:

```go
package model

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestNetworkInfoHashesPlaintextAndHidesIt(t *testing.T) {
	n := NewNetworkInfo("MyHomeWiFi", "AA:BB:CC:DD:EE:FF")
	if !strings.HasPrefix(n.SSIDHash, "sha256:") {
		t.Errorf("SSIDHash = %q, want sha256: prefix", n.SSIDHash)
	}
	if !strings.HasPrefix(n.BSSIDHash, "sha256:") {
		t.Errorf("BSSIDHash = %q, want sha256: prefix", n.BSSIDHash)
	}
	if n.SSIDPlain() != "MyHomeWiFi" {
		t.Errorf("SSIDPlain() = %q, want MyHomeWiFi", n.SSIDPlain())
	}

	data, err := json.Marshal(n)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "MyHomeWiFi") || strings.Contains(string(data), "AA:BB:CC:DD:EE:FF") {
		t.Errorf("marshaled NetworkInfo leaked plaintext: %s", data)
	}
}

func TestResultRoundTripsThroughJSON(t *testing.T) {
	original := Result{
		SchemaVersion: SchemaVersionV1,
		ToolVersion:   "0.1.0-m1",
		RunID:         "run-test-0001",
		StartedAt:     time.Date(2026, 8, 16, 9, 0, 0, 0, time.UTC),
		DurationMS:    850,
		Profile:       ProfileStandard,
		Network: NetworkInfo{
			SSIDHash:     "sha256:aaaa",
			BSSIDHash:    "sha256:bbbb",
			KnownNetwork: true,
		},
		Checks: []Check{
			{ID: "wifi.security", Layer: LayerWiFi, Status: StatusNormal, Confidence: ConfidenceHigh},
		},
		Findings: []Finding{
			{ID: "weak_encryption", Severity: SeverityCritical, BasedOn: []string{"wifi.security"}},
		},
		Verdict: Verdict{Safety: SafetyOK, Score: 100},
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	var roundTripped Result
	if err := json.Unmarshal(data, &roundTripped); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(original, roundTripped) {
		t.Errorf("round trip mismatch:\noriginal:  %+v\nroundtrip: %+v", original, roundTripped)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/model/... -run "TestNetworkInfo|TestResult" -v`
Expected: FAIL — `NetworkInfo`/`Result` do not exist yet.

- [ ] **Step 3: Write the implementation**

Create `internal/model/result.go`:

```go
package model

import (
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// SchemaVersionV1 is the schema_version value for spec v1.0 (spec §4.5).
const SchemaVersionV1 = "1.0"

type NetworkInfo struct {
	SSIDHash     string `json:"ssid_hash"`
	BSSIDHash    string `json:"bssid_hash"`
	OUI          string `json:"oui,omitempty"`
	Band         string `json:"band,omitempty"`
	Channel      int    `json:"channel,omitempty"`
	Security     string `json:"security,omitempty"`
	PMF          string `json:"pmf,omitempty"`
	KnownNetwork bool   `json:"known_network"`

	ssidPlain  string
	bssidPlain string
}

// NewNetworkInfo hashes the plaintext SSID/BSSID with SHA-256 (spec
// §4.5) and keeps the plaintext only in unexported fields, so it is
// available for TUI display and whitelist matching but never marshaled
// to JSON.
func NewNetworkInfo(ssid, bssid string) NetworkInfo {
	return NetworkInfo{
		SSIDHash:   hashNetworkID(ssid),
		BSSIDHash:  hashNetworkID(bssid),
		ssidPlain:  ssid,
		bssidPlain: bssid,
	}
}

func hashNetworkID(v string) string {
	sum := sha256.Sum256([]byte(v))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func (n NetworkInfo) SSIDPlain() string  { return n.ssidPlain }
func (n NetworkInfo) BSSIDPlain() string { return n.bssidPlain }

type Result struct {
	SchemaVersion string      `json:"schema_version"`
	ToolVersion   string      `json:"tool_version"`
	RunID         string      `json:"run_id"`
	StartedAt     time.Time   `json:"started_at"`
	DurationMS    int64       `json:"duration_ms"`
	Profile       Profile     `json:"profile"`
	Network       NetworkInfo `json:"network"`
	Checks        []Check     `json:"checks"`
	Findings      []Finding   `json:"findings"`
	Verdict       Verdict     `json:"verdict"`
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/model/... -v`
Expected: PASS (all model package tests, including Tasks 1-4)

- [ ] **Step 5: Commit**

```bash
git add internal/model/result.go internal/model/result_test.go
git commit -m "feat(model): add Result/NetworkInfo with SSID/BSSID redaction (T9)"
```

---

### Task 6: `registry` package — loader + `checks.yaml`

**Files:**
- Create: `internal/registry/registry.go`
- Create: `internal/registry/checks.yaml`
- Test: `internal/registry/registry_test.go`

**Interfaces:**
- Consumes: `model.Layer`, `model.Profile` (Task 1, 2).
- Produces: `type CheckDefinition struct{...}`; `type Registry struct{ Checks []CheckDefinition }`; `func Load(path string) (*Registry, error)`; `func (*Registry) Filter(profile model.Profile) []CheckDefinition`; `func (*Registry) ByID(id string) (CheckDefinition, bool)`.

- [ ] **Step 1: Write the failing tests**

Create `internal/registry/registry_test.go`:

```go
package registry

import (
	"testing"

	"github.com/Maulana-anjari/wifisec/internal/model"
)

func TestLoadParsesChecksYAML(t *testing.T) {
	r, err := Load("checks.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Checks) == 0 {
		t.Fatal("expected at least one check definition")
	}
	def, ok := r.ByID("local.trust_store")
	if !ok {
		t.Fatal("expected local.trust_store to be defined")
	}
	if !def.SelfEvident {
		t.Error("local.trust_store must be self_evident: true (spec §6.1)")
	}
	if def.ProfileRequired != model.ProfilePassive {
		t.Errorf("local.trust_store profile_required = %s, want passive", def.ProfileRequired)
	}
}

func TestFilterRespectsProfileLevel(t *testing.T) {
	r, err := Load("checks.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, def := range r.Filter(model.ProfileMinimal) {
		if def.ProfileRequired.Level() > model.ProfileMinimal.Level() {
			t.Errorf("Filter(minimal) returned %s which requires %s", def.ID, def.ProfileRequired)
		}
	}
	passiveOnly := r.Filter(model.ProfilePassive)
	full := r.Filter(model.ProfileFull)
	if len(passiveOnly) >= len(full) {
		t.Errorf("Filter(full) should return more checks than Filter(passive): got %d vs %d", len(full), len(passiveOnly))
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/registry/... -v`
Expected: FAIL — package doesn't exist yet.

- [ ] **Step 3: Write `checks.yaml`**

Create `internal/registry/checks.yaml` (all 29 checks from spec §6.1-§6.4):

```yaml
checks:
  # Profil passive — 0 paket (spec §6.1)
  - id: local.interface
    layer: local
    title: "Konfigurasi interface"
    description: "IP, netmask, MTU, nama interface"
    profile_required: passive
    requires_control_server: false
    requires_privilege: false
    self_evident: false
    estimated_packets: 0
  - id: local.gateway
    layer: local
    title: "Gateway default"
    description: "IP gateway, apakah privat"
    profile_required: passive
    requires_control_server: false
    requires_privilege: false
    self_evident: false
    estimated_packets: 0
  - id: local.dns_servers
    layer: local
    title: "Server DNS dari DHCP"
    description: "Daftar resolver, klasifikasi internal/publik"
    profile_required: passive
    requires_control_server: false
    requires_privilege: false
    self_evident: false
    estimated_packets: 0
  - id: local.routing
    layer: local
    title: "Tabel routing"
    description: "Rute default, rute mencurigakan"
    profile_required: passive
    requires_control_server: false
    requires_privilege: false
    self_evident: false
    estimated_packets: 0
  - id: local.mtu
    layer: local
    title: "MTU interface"
    description: "Nilai MTU, apakah non-standar"
    profile_required: passive
    requires_control_server: false
    requires_privilege: false
    self_evident: false
    estimated_packets: 0
  - id: local.proxy_system
    layer: local
    title: "Proxy sistem"
    description: "HTTP/HTTPS proxy, PAC URL"
    profile_required: passive
    requires_control_server: false
    requires_privilege: false
    self_evident: false
    estimated_packets: 0
  - id: local.trust_store
    layer: local
    title: "CA di trust store"
    description: "CA non-publik yang terpasang"
    profile_required: passive
    requires_control_server: false
    requires_privilege: false
    self_evident: true
    estimated_packets: 0
  - id: wifi.security
    layer: wifi
    title: "Tipe enkripsi"
    description: "WPA2/WPA3/WEP/open"
    profile_required: passive
    requires_control_server: false
    requires_privilege: false
    self_evident: false
    estimated_packets: 0
  - id: wifi.pmf
    layer: wifi
    title: "Protected Management Frames"
    description: "enabled/disabled/required"
    profile_required: passive
    requires_control_server: false
    requires_privilege: false
    self_evident: false
    estimated_packets: 0
  - id: wifi.signal
    layer: wifi
    title: "Kekuatan sinyal"
    description: "RSSI, estimasi kualitas"
    profile_required: passive
    requires_control_server: false
    requires_privilege: false
    self_evident: false
    estimated_packets: 0
  - id: wifi.channel
    layer: wifi
    title: "Channel dan band"
    description: "Channel, band, lebar"
    profile_required: passive
    requires_control_server: false
    requires_privilege: false
    self_evident: false
    estimated_packets: 0
  - id: wifi.bssid_vendor
    layer: wifi
    title: "Vendor perangkat AP"
    description: "OUI, nama vendor"
    profile_required: passive
    requires_control_server: false
    requires_privilege: false
    self_evident: false
    estimated_packets: 0

  # Profil minimal — ~2 paket (spec §6.2)
  - id: dns.resolve_basic
    layer: dns
    title: "Resolusi DNS dasar"
    description: "Hasil resolve satu domain kontrol"
    profile_required: minimal
    requires_control_server: false
    requires_privilege: false
    self_evident: false
    estimated_packets: 1
  - id: tls.cert_issuer
    layer: tls
    title: "Penerbit sertifikat"
    description: "Issuer, fingerprint, panjang rantai"
    profile_required: minimal
    requires_control_server: false
    requires_privilege: false
    self_evident: false
    estimated_packets: 1

  # Profil standard (spec §6.3)
  - id: net.captive_portal
    layer: http
    title: "Deteksi captive portal"
    description: "Status portal login"
    profile_required: standard
    requires_control_server: false
    requires_privilege: false
    self_evident: false
    estimated_packets: 2
  - id: net.latency_gateway
    layer: perf
    title: "Latency ke gateway"
    description: "RTT ke gateway lokal"
    profile_required: standard
    requires_control_server: false
    requires_privilege: false
    self_evident: false
    estimated_packets: 10
  - id: net.latency_internet
    layer: perf
    title: "Latency ke internet"
    description: "RTT ke host internet"
    profile_required: standard
    requires_control_server: false
    requires_privilege: false
    self_evident: false
    estimated_packets: 10
  - id: net.jitter
    layer: perf
    title: "Jitter"
    description: "Variasi latency, dihitung dari net.latency_internet"
    profile_required: standard
    requires_control_server: false
    requires_privilege: false
    self_evident: false
    estimated_packets: 0
  - id: net.packet_loss
    layer: perf
    title: "Packet loss"
    description: "Persentase paket hilang, dihitung dari net.latency_internet"
    profile_required: standard
    requires_control_server: false
    requires_privilege: false
    self_evident: false
    estimated_packets: 0
  - id: dns.compare_doh
    layer: dns
    title: "Perbandingan DNS jaringan vs DoH"
    description: "Selisih hasil resolve lokal vs DoH"
    profile_required: standard
    requires_control_server: false
    requires_privilege: false
    self_evident: false
    estimated_packets: 4
  - id: dns.transparent_proxy
    layer: dns
    title: "Deteksi intersepsi port 53"
    description: "Apakah query ke resolver lain tetap dijawab"
    profile_required: standard
    requires_control_server: false
    requires_privilege: false
    self_evident: false
    estimated_packets: 2
  - id: net.bufferbloat
    layer: perf
    title: "Latency saat dibebani"
    description: "RTT di bawah beban vs idle"
    profile_required: standard
    requires_control_server: false
    requires_privilege: false
    self_evident: false
    estimated_packets: 20
  - id: net.ipv6
    layer: l4
    title: "Ketersediaan IPv6"
    description: "Konektivitas IPv6 keluar"
    profile_required: standard
    requires_control_server: false
    requires_privilege: false
    self_evident: false
    estimated_packets: 2

  # Profil full (spec §6.4)
  - id: l4.port_reachability
    layer: l4
    title: "Ketercapaian port umum"
    description: "Status open/filtered untuk port umum; jeda >=200ms, maks 20 port, sekuensial"
    profile_required: full
    requires_control_server: true
    requires_privilege: false
    self_evident: false
    estimated_packets: 20
  - id: tls.sni_inspection
    layer: tls
    title: "Deteksi inspeksi SNI"
    description: "Apakah SNI diperiksa/diblokir di jalur"
    profile_required: full
    requires_control_server: true
    requires_privilege: false
    self_evident: false
    estimated_packets: 4
  - id: tls.ech_support
    layer: tls
    title: "Dukungan ECH"
    description: "Apakah Encrypted Client Hello berhasil"
    profile_required: full
    requires_control_server: true
    requires_privilege: false
    self_evident: false
    estimated_packets: 4
  - id: http.header_injection
    layer: http
    title: "Header yang disisipkan proxy"
    description: "Header request/response yang ditambahkan di jalur"
    profile_required: full
    requires_control_server: false
    requires_privilege: false
    self_evident: false
    estimated_packets: 2
  - id: net.path_mtu
    layer: l4
    title: "Path MTU discovery"
    description: "MTU efektif sepanjang jalur"
    profile_required: full
    requires_control_server: true
    requires_privilege: false
    self_evident: false
    estimated_packets: 10
  - id: net.throttling
    layer: perf
    title: "Throttling selektif"
    description: "Perbandingan throughput antar jenis trafik"
    profile_required: full
    requires_control_server: true
    requires_privilege: false
    self_evident: false
    estimated_packets: 20
  - id: net.quic
    layer: l4
    title: "Ketersediaan QUIC/HTTP3"
    description: "Konektivitas UDP/443 QUIC"
    profile_required: full
    requires_control_server: false
    requires_privilege: false
    self_evident: false
    estimated_packets: 2
  - id: wifi.channel_congestion
    layer: wifi
    title: "Kongesti channel"
    description: "Level kongesti channel WiFi saat ini"
    profile_required: full
    requires_control_server: false
    requires_privilege: false
    self_evident: false
    estimated_packets: 0
```

- [ ] **Step 4: Write the loader**

Create `internal/registry/registry.go`:

```go
package registry

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/Maulana-anjari/wifisec/internal/model"
)

// CheckDefinition is the static, declarative metadata for one check
// (spec §4.6). Runtime results are model.Check, not this type.
type CheckDefinition struct {
	ID                    string        `yaml:"id"`
	Layer                 model.Layer   `yaml:"layer"`
	Title                 string        `yaml:"title"`
	Description           string        `yaml:"description"`
	ProfileRequired       model.Profile `yaml:"profile_required"`
	RequiresControlServer bool          `yaml:"requires_control_server"`
	RequiresPrivilege     bool          `yaml:"requires_privilege"`
	SelfEvident           bool          `yaml:"self_evident"`
	EstimatedPackets      int           `yaml:"estimated_packets"`
}

type Registry struct {
	Checks []CheckDefinition
}

type yamlFile struct {
	Checks []CheckDefinition `yaml:"checks"`
}

// Load reads and parses a checks.yaml registry file (spec §6).
func Load(path string) (*Registry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("registry: read %s: %w", path, err)
	}
	var f yamlFile
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("registry: parse %s: %w", path, err)
	}
	return &Registry{Checks: f.Checks}, nil
}

// Filter returns only the definitions runnable at the given profile
// (spec §3.2, §5.2): those whose ProfileRequired.Level() <= profile.Level().
func (r *Registry) Filter(profile model.Profile) []CheckDefinition {
	var out []CheckDefinition
	for _, c := range r.Checks {
		if c.ProfileRequired.Level() <= profile.Level() {
			out = append(out, c)
		}
	}
	return out
}

// ByID looks up a single definition by its check ID.
func (r *Registry) ByID(id string) (CheckDefinition, bool) {
	for _, c := range r.Checks {
		if c.ID == id {
			return c, true
		}
	}
	return CheckDefinition{}, false
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `go test ./internal/registry/... -v`
Expected: PASS (2 tests)

- [ ] **Step 6: Commit**

```bash
git add internal/registry/registry.go internal/registry/checks.yaml internal/registry/registry_test.go
git commit -m "feat(registry): add checks.yaml (spec §6) and profile-filtering loader"
```

---

### Task 7: `tui/style.go` — glyphs, styles, breakpoint

**Files:**
- Create: `internal/tui/style.go`
- Test: `internal/tui/style_test.go`

**Interfaces:**
- Consumes: `model.Profile`, `model.CheckStatus`, `model.Severity` (Tasks 1, 2, 3).
- Produces: `const breakpointColumns = 70`; `func ProfileGlyph(model.Profile) string`; `func StatusGlyph(model.CheckStatus) string`; `func SeverityStyle(model.Severity) lipgloss.Style`; `func isNarrow(width int) bool`.

- [ ] **Step 1: Write the failing tests**

Create `internal/tui/style_test.go`:

```go
package tui

import (
	"testing"

	"github.com/Maulana-anjari/wifisec/internal/model"
)

func TestProfileGlyphIsDistinctPerProfile(t *testing.T) {
	seen := map[string]model.Profile{}
	for _, p := range []model.Profile{model.ProfilePassive, model.ProfileMinimal, model.ProfileStandard, model.ProfileFull} {
		g := ProfileGlyph(p)
		if prev, ok := seen[g]; ok {
			t.Errorf("glyph %q used for both %s and %s", g, prev, p)
		}
		seen[g] = p
	}
}

func TestStatusGlyphIsDistinctPerStatus(t *testing.T) {
	seen := map[string]model.CheckStatus{}
	statuses := []model.CheckStatus{
		model.StatusNormal, model.StatusAnomalous, model.StatusInconclusive,
		model.StatusSkipped, model.StatusError,
	}
	for _, s := range statuses {
		g := StatusGlyph(s)
		if prev, ok := seen[g]; ok {
			t.Errorf("glyph %q used for both %s and %s", g, prev, s)
		}
		seen[g] = s
	}
}

func TestIsNarrowBreakpoint(t *testing.T) {
	if isNarrow(70) {
		t.Error("70 columns should not be narrow (breakpoint is exclusive below 70)")
	}
	if !isNarrow(69) {
		t.Error("69 columns should be narrow")
	}
	if isNarrow(0) {
		t.Error("width 0 (unknown) should not be treated as narrow")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/tui/... -v`
Expected: FAIL — package doesn't exist yet.

- [ ] **Step 3: Write the implementation**

Create `internal/tui/style.go`:

```go
package tui

import (
	"github.com/charmbracelet/lipgloss"

	"github.com/Maulana-anjari/wifisec/internal/model"
)

const breakpointColumns = 70

var (
	styleCritical = lipgloss.NewStyle().Foreground(lipgloss.Color("9"))
	styleWarning  = lipgloss.NewStyle().Foreground(lipgloss.Color("11"))
	styleInfo     = lipgloss.NewStyle().Foreground(lipgloss.Color("12"))
)

// ProfileGlyph returns the header glyph for a profile (spec §9.3).
func ProfileGlyph(p model.Profile) string {
	switch p {
	case model.ProfilePassive:
		return "●"
	case model.ProfileMinimal:
		return "◐"
	case model.ProfileStandard:
		return "◑"
	case model.ProfileFull:
		return "◆"
	default:
		return "?"
	}
}

// StatusGlyph returns the check-status glyph. Color only reinforces
// this; it is never the sole differentiator (spec §9.3).
func StatusGlyph(s model.CheckStatus) string {
	switch s {
	case model.StatusNormal:
		return "✓"
	case model.StatusAnomalous:
		return "!"
	case model.StatusInconclusive:
		return "?"
	case model.StatusSkipped:
		return "–"
	case model.StatusError:
		return "×"
	default:
		return " "
	}
}

// SeverityStyle returns the lipgloss style for a finding severity.
func SeverityStyle(s model.Severity) lipgloss.Style {
	switch s {
	case model.SeverityCritical:
		return styleCritical
	case model.SeverityWarning:
		return styleWarning
	default:
		return styleInfo
	}
}

// isNarrow reports whether the terminal is below the single breakpoint
// (spec §9.3): side-by-side columns collapse to stacked below 70 cols.
// Width 0 means "unknown" (no WindowSizeMsg received yet) and is not
// treated as narrow.
func isNarrow(width int) bool {
	return width > 0 && width < breakpointColumns
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/tui/... -v`
Expected: PASS (3 tests)

- [ ] **Step 5: Commit**

```bash
git add internal/tui/style.go internal/tui/style_test.go
git commit -m "feat(tui): add profile/status glyphs, severity styles, breakpoint helper"
```

---

### Task 8: `tui` verdict screen

**Files:**
- Create: `internal/tui/screen_verdict.go`
- Test: `internal/tui/screen_verdict_test.go`

**Interfaces:**
- Consumes: `model.Result`, `isNarrow` (Task 7).
- Produces: `func renderVerdictScreen(r model.Result, width int) string`.

- [ ] **Step 1: Write the failing test**

Create `internal/tui/screen_verdict_test.go`:

```go
package tui

import (
	"strings"
	"testing"

	"github.com/Maulana-anjari/wifisec/internal/model"
)

func TestRenderVerdictScreenShowsHeadlineAndScore(t *testing.T) {
	r := model.Result{
		Verdict: model.Verdict{
			Safety:      model.SafetyOK,
			Score:       100,
			Headline:    "Jaringan ini aman.",
			TopFindings: []string{"finding.a"},
			BlindSpots:  []string{},
			UseCases:    map[string]string{"browsing_umum": "ok"},
		},
	}
	out := renderVerdictScreen(r, 100)
	if !strings.Contains(out, "Jaringan ini aman.") {
		t.Errorf("expected headline in output, got:\n%s", out)
	}
	if !strings.Contains(out, "100") {
		t.Errorf("expected score in output, got:\n%s", out)
	}
	if !strings.Contains(out, "finding.a") {
		t.Errorf("expected top finding in output, got:\n%s", out)
	}
}

func TestRenderVerdictScreenGivesBlindSpotsEqualWeight(t *testing.T) {
	r := model.Result{
		Verdict: model.Verdict{
			TopFindings: []string{"a", "b"},
			BlindSpots:  []string{"x"},
		},
	}
	out := renderVerdictScreen(r, 100)
	if !strings.Contains(out, "Temuan utama") || !strings.Contains(out, "Tidak diperiksa") {
		t.Errorf("expected both section headers present, got:\n%s", out)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/tui/... -run TestRenderVerdictScreen -v`
Expected: FAIL — `renderVerdictScreen` doesn't exist yet.

- [ ] **Step 3: Write the implementation**

Create `internal/tui/screen_verdict.go`:

```go
package tui

import (
	"fmt"
	"strings"

	"github.com/Maulana-anjari/wifisec/internal/model"
)

// useCaseOrder is the fixed display order for spec §7.3 use cases.
var useCaseOrder = []string{"browsing_umum", "login_akun_pribadi", "kerja_sensitif", "internet_banking"}

func renderVerdictScreen(r model.Result, width int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s  (score %d)\n", strings.ToUpper(string(r.Verdict.Safety)), r.Verdict.Score)
	b.WriteString(r.Verdict.Headline)
	b.WriteString("\n\n")

	left := renderList("Temuan utama", r.Verdict.TopFindings)
	right := renderList("Tidak diperiksa", r.Verdict.BlindSpots)

	if isNarrow(width) {
		b.WriteString(left)
		b.WriteString("\n")
		b.WriteString(right)
	} else {
		b.WriteString(joinColumns(left, right, width))
	}

	if len(r.Verdict.UseCases) > 0 {
		b.WriteString("\nUse case:\n")
		for _, key := range useCaseOrder {
			if v, ok := r.Verdict.UseCases[key]; ok {
				fmt.Fprintf(&b, "  %-20s %s\n", key, v)
			}
		}
	}
	return b.String()
}

func renderList(title string, items []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s (%d)\n", title, len(items))
	if len(items) == 0 {
		b.WriteString("  (tidak ada)\n")
	}
	for _, item := range items {
		fmt.Fprintf(&b, "  - %s\n", item)
	}
	return b.String()
}

// joinColumns lays two rendered blocks side by side at equal width, so
// "top findings" and "blind spots" carry the same visual weight
// (spec §9.3).
func joinColumns(left, right string, width int) string {
	colWidth := width/2 - 1
	if colWidth < 1 {
		colWidth = 1
	}
	leftLines := strings.Split(strings.TrimRight(left, "\n"), "\n")
	rightLines := strings.Split(strings.TrimRight(right, "\n"), "\n")
	n := len(leftLines)
	if len(rightLines) > n {
		n = len(rightLines)
	}
	var b strings.Builder
	for i := 0; i < n; i++ {
		var l, r string
		if i < len(leftLines) {
			l = leftLines[i]
		}
		if i < len(rightLines) {
			r = rightLines[i]
		}
		fmt.Fprintf(&b, "%-*s %s\n", colWidth, l, r)
	}
	return b.String()
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/tui/... -run TestRenderVerdictScreen -v`
Expected: PASS (2 tests)

- [ ] **Step 5: Commit**

```bash
git add internal/tui/screen_verdict.go internal/tui/screen_verdict_test.go
git commit -m "feat(tui): add verdict screen renderer"
```

---

### Task 9: `tui` findings screen

**Files:**
- Create: `internal/tui/screen_findings.go`
- Test: `internal/tui/screen_findings_test.go`

**Interfaces:**
- Consumes: `model.Result`, `SeverityStyle` (Task 7).
- Produces: `func renderFindingsScreen(r model.Result, selected, width int) string`.

- [ ] **Step 1: Write the failing test**

Create `internal/tui/screen_findings_test.go`:

```go
package tui

import (
	"strings"
	"testing"

	"github.com/Maulana-anjari/wifisec/internal/model"
)

func TestRenderFindingsScreenListsAllFindings(t *testing.T) {
	r := model.Result{
		Findings: []model.Finding{
			{ID: "a", Title: "Finding A", Severity: model.SeverityCritical},
			{ID: "b", Title: "Finding B", Severity: model.SeverityInfo, FalsePositiveHints: []string{"could be a false positive"}},
		},
	}
	out := renderFindingsScreen(r, 0, 100)
	if !strings.Contains(out, "Finding A") || !strings.Contains(out, "Finding B") {
		t.Errorf("expected both findings in output, got:\n%s", out)
	}
	if !strings.Contains(out, "could be a false positive") {
		t.Errorf("expected false_positive_hints shown directly (spec §9.3), got:\n%s", out)
	}
}

func TestRenderFindingsScreenHandlesEmpty(t *testing.T) {
	out := renderFindingsScreen(model.Result{}, 0, 100)
	if !strings.Contains(out, "0") {
		t.Errorf("expected empty-count indicator, got:\n%s", out)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/tui/... -run TestRenderFindingsScreen -v`
Expected: FAIL — `renderFindingsScreen` doesn't exist yet.

- [ ] **Step 3: Write the implementation**

Create `internal/tui/screen_findings.go`:

```go
package tui

import (
	"fmt"
	"strings"

	"github.com/Maulana-anjari/wifisec/internal/model"
)

func renderFindingsScreen(r model.Result, selected, width int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Findings (%d)\n", len(r.Findings))
	if len(r.Findings) == 0 {
		b.WriteString("  (tidak ada temuan)\n")
		return b.String()
	}
	for i, f := range r.Findings {
		cursor := "  "
		if i == selected {
			cursor = "> "
		}
		style := SeverityStyle(f.Severity)
		fmt.Fprintf(&b, "%s%s %s\n", cursor, glyphForSeverity(f.Severity), style.Render(f.Title))
		for _, hint := range f.FalsePositiveHints {
			fmt.Fprintf(&b, "      hint: %s\n", hint)
		}
	}
	return b.String()
}

func glyphForSeverity(s model.Severity) string {
	switch s {
	case model.SeverityCritical:
		return "▲"
	case model.SeverityWarning:
		return "!"
	default:
		return "·"
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/tui/... -run TestRenderFindingsScreen -v`
Expected: PASS (2 tests)

- [ ] **Step 5: Commit**

```bash
git add internal/tui/screen_findings.go internal/tui/screen_findings_test.go
git commit -m "feat(tui): add findings screen renderer"
```

---

### Task 10: `tui` detail screen

**Files:**
- Create: `internal/tui/screen_detail.go`
- Test: `internal/tui/screen_detail_test.go`

**Interfaces:**
- Consumes: `model.Result`, `StatusGlyph` (Task 7).
- Produces: `func renderDetailScreen(r model.Result, selected, width int) string`.

- [ ] **Step 1: Write the failing test**

Create `internal/tui/screen_detail_test.go`:

```go
package tui

import (
	"strings"
	"testing"

	"github.com/Maulana-anjari/wifisec/internal/model"
)

func TestRenderDetailScreenShowsSelectedCheck(t *testing.T) {
	r := model.Result{
		Checks: []model.Check{
			{ID: "a", Title: "Check A", Status: model.StatusNormal},
			{ID: "b", Title: "Check B", Status: model.StatusError, Error: "boom"},
		},
	}
	out := renderDetailScreen(r, 1, 100)
	if !strings.Contains(out, "Check B") {
		t.Errorf("expected selected check title, got:\n%s", out)
	}
	if !strings.Contains(out, "boom") {
		t.Errorf("expected error message shown, got:\n%s", out)
	}
	if strings.Contains(out, "Check A") {
		t.Errorf("did not expect unselected check title, got:\n%s", out)
	}
}

func TestRenderDetailScreenHandlesEmpty(t *testing.T) {
	out := renderDetailScreen(model.Result{}, 0, 100)
	if !strings.Contains(out, "0") {
		t.Errorf("expected empty-count indicator, got:\n%s", out)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/tui/... -run TestRenderDetailScreen -v`
Expected: FAIL — `renderDetailScreen` doesn't exist yet.

- [ ] **Step 3: Write the implementation**

Create `internal/tui/screen_detail.go`:

```go
package tui

import (
	"fmt"
	"strings"

	"github.com/Maulana-anjari/wifisec/internal/model"
)

func renderDetailScreen(r model.Result, selected, width int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Checks (%d)\n", len(r.Checks))
	if len(r.Checks) == 0 {
		b.WriteString("  (tidak ada check)\n")
		return b.String()
	}
	c := r.Checks[selected]
	fmt.Fprintf(&b, "%s %s  [%s]\n", StatusGlyph(c.Status), c.Title, c.ID)
	fmt.Fprintf(&b, "  layer: %s   status: %s   confidence: %s\n", c.Layer, c.Status, c.Confidence)
	if c.Target != "" {
		fmt.Fprintf(&b, "  target: %s\n", c.Target)
	}
	fmt.Fprintf(&b, "  control performed: %v", c.Control.Performed)
	if c.Control.Reason != "" {
		fmt.Fprintf(&b, "   reason: %s", c.Control.Reason)
	}
	b.WriteString("\n")
	if c.Error != "" {
		fmt.Fprintf(&b, "  error: %s\n", c.Error)
	}
	fmt.Fprintf(&b, "  packets sent: %d   duration: %dms\n", c.PacketsSent, c.DurationMS)
	return b.String()
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/tui/... -run TestRenderDetailScreen -v`
Expected: PASS (2 tests)

- [ ] **Step 5: Commit**

```bash
git add internal/tui/screen_detail.go internal/tui/screen_detail_test.go
git commit -m "feat(tui): add check detail screen renderer"
```

---

### Task 11: `tui` live screen

**Files:**
- Create: `internal/tui/screen_live.go`
- Test: `internal/tui/screen_live_test.go`

**Interfaces:**
- Consumes: `model.Result`, `StatusGlyph` (Task 7).
- Produces: `func renderLiveScreen(r model.Result, width int) string`.

- [ ] **Step 1: Write the failing test**

Create `internal/tui/screen_live_test.go`:

```go
package tui

import (
	"strings"
	"testing"

	"github.com/Maulana-anjari/wifisec/internal/model"
)

func TestRenderLiveScreenListsAllChecksWithGlyphs(t *testing.T) {
	r := model.Result{
		Checks: []model.Check{
			{ID: "a", Title: "Check A", Status: model.StatusNormal},
			{ID: "b", Title: "Check B", Status: model.StatusSkipped},
		},
	}
	out := renderLiveScreen(r, 100)
	if !strings.Contains(out, "Check A") || !strings.Contains(out, "Check B") {
		t.Errorf("expected both checks listed, got:\n%s", out)
	}
	if !strings.Contains(out, StatusGlyph(model.StatusSkipped)) {
		t.Errorf("expected skipped glyph present, got:\n%s", out)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/tui/... -run TestRenderLiveScreen -v`
Expected: FAIL — `renderLiveScreen` doesn't exist yet.

- [ ] **Step 3: Write the implementation**

Create `internal/tui/screen_live.go`:

```go
package tui

import (
	"fmt"
	"strings"

	"github.com/Maulana-anjari/wifisec/internal/model"
)

func renderLiveScreen(r model.Result, width int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Live (%d checks)\n", len(r.Checks))
	for _, c := range r.Checks {
		fmt.Fprintf(&b, "  %s %s\n", StatusGlyph(c.Status), c.Title)
	}
	return b.String()
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/tui/... -run TestRenderLiveScreen -v`
Expected: PASS (1 test)

- [ ] **Step 5: Commit**

```bash
git add internal/tui/screen_live.go internal/tui/screen_live_test.go
git commit -m "feat(tui): add live monitor screen renderer"
```

---

### Task 12: `tui` profile confirmation dialog

**Files:**
- Create: `internal/tui/dialog_profile.go`
- Test: `internal/tui/dialog_profile_test.go`

**Interfaces:**
- Consumes: `model.Profile` (Task 1).
- Produces: `type ProfileDialog struct{ Target model.Profile; KnownNetwork bool; Typed string }`; `func (ProfileDialog) View() string`; `func (ProfileDialog) Confirmed() bool`.

- [ ] **Step 1: Write the failing test**

Create `internal/tui/dialog_profile_test.go`:

```go
package tui

import (
	"strings"
	"testing"

	"github.com/Maulana-anjari/wifisec/internal/model"
)

func TestProfileDialogShowsEstimateAndWarnsOnFull(t *testing.T) {
	d := ProfileDialog{Target: model.ProfileFull, KnownNetwork: false}
	out := d.View()
	if !strings.Contains(out, "PERINGATAN") {
		t.Errorf("expected a warning for profile full, got:\n%s", out)
	}
	if !strings.Contains(out, "full") {
		t.Errorf("expected target profile named in dialog, got:\n%s", out)
	}
}

func TestProfileDialogConfirmedRequiresExactMatch(t *testing.T) {
	d := ProfileDialog{Target: model.ProfileMinimal, Typed: "minima"}
	if d.Confirmed() {
		t.Error("partial match should not confirm (spec G2: exact match required)")
	}
	d.Typed = "minimal"
	if !d.Confirmed() {
		t.Error("exact match should confirm")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/tui/... -run TestProfileDialog -v`
Expected: FAIL — `ProfileDialog` doesn't exist yet.

- [ ] **Step 3: Write the implementation**

Create `internal/tui/dialog_profile.go`:

```go
package tui

import (
	"fmt"
	"strings"

	"github.com/Maulana-anjari/wifisec/internal/model"
)

// ProfileDialog renders the profile-raise confirmation dialog (spec
// §5.2 G2/G3). It only renders; the caller collects the typed
// confirmation text via the TUI's key handling.
type ProfileDialog struct {
	Target       model.Profile
	KnownNetwork bool
	Typed        string
}

func (d ProfileDialog) View() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Naikkan profil ke %s?\n", d.Target)
	fmt.Fprintf(&b, "  estimasi paket: ~%d\n", d.Target.EstimatedPackets())
	fmt.Fprintf(&b, "  known network: %v\n", d.KnownNetwork)
	if d.Target == model.ProfileFull {
		b.WriteString("  PERINGATAN: profil full paling intrusif, hanya untuk jaringan milik sendiri.\n")
	}
	fmt.Fprintf(&b, "  ketik %q untuk konfirmasi: %s\n", string(d.Target), d.Typed)
	return b.String()
}

// Confirmed reports whether the typed text exactly matches the target
// profile name (spec G2: full name, exact match required).
func (d ProfileDialog) Confirmed() bool {
	return d.Typed == string(d.Target)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/tui/... -run TestProfileDialog -v`
Expected: PASS (2 tests)

- [ ] **Step 5: Commit**

```bash
git add internal/tui/dialog_profile.go internal/tui/dialog_profile_test.go
git commit -m "feat(tui): add profile-raise confirmation dialog renderer"
```

---

### Task 13: `tui.Model` — app wiring and navigation

**Files:**
- Create: `internal/tui/app.go`
- Test: `internal/tui/app_test.go`

**Interfaces:**
- Consumes: `model.Result`; `renderVerdictScreen`, `renderFindingsScreen`, `renderDetailScreen`, `renderLiveScreen` (Tasks 8-11); `ProfileGlyph` (Task 7).
- Produces: `type Screen int` (`ScreenVerdict`, `ScreenFindings`, `ScreenDetail`, `ScreenLive`); `type Model struct{...}` implementing `tea.Model`; `func New(result model.Result) Model`.

- [ ] **Step 1: Write the failing test**

Create `internal/tui/app_test.go`:

```go
package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/Maulana-anjari/wifisec/internal/model"
)

func TestTabCyclesThroughAllFourScreens(t *testing.T) {
	m := New(model.Result{})
	if m.screen != ScreenVerdict {
		t.Fatalf("expected initial screen to be ScreenVerdict, got %v", m.screen)
	}
	wantOrder := []Screen{ScreenFindings, ScreenDetail, ScreenLive, ScreenVerdict}
	for _, want := range wantOrder {
		next, _ := m.Update(tea.KeyMsg{Type: tea.KeyTab})
		m = next.(Model)
		if m.screen != want {
			t.Fatalf("after tab, screen = %v, want %v", m.screen, want)
		}
	}
}

func TestQuitKeySetsQuittingAndReturnsQuitCmd(t *testing.T) {
	m := New(model.Result{})
	next, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("q")})
	m = next.(Model)
	if !m.quitting {
		t.Error("expected quitting to be true after 'q'")
	}
	if cmd == nil {
		t.Error("expected a non-nil tea.Cmd (tea.Quit) after 'q'")
	}
}

func TestViewRendersHeaderWithProfileGlyphAndPacketCount(t *testing.T) {
	r := model.Result{
		Profile: model.ProfileStandard,
		Checks:  []model.Check{{PacketsSent: 3}, {PacketsSent: 2}},
	}
	m := New(r)
	next, _ := m.Update(tea.WindowSizeMsg{Width: 100, Height: 40})
	m = next.(Model)
	out := m.View()
	if !strings.Contains(out, ProfileGlyph(model.ProfileStandard)) {
		t.Errorf("expected profile glyph in header, got:\n%s", out)
	}
	if !strings.Contains(out, "5") {
		t.Errorf("expected total packet count (5) in header, got:\n%s", out)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/tui/... -run "TestTabCycles|TestQuitKey|TestViewRenders" -v`
Expected: FAIL — `Model`/`New`/`Screen` do not exist yet.

- [ ] **Step 3: Write the implementation**

Create `internal/tui/app.go`:

```go
package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/Maulana-anjari/wifisec/internal/model"
)

type Screen int

const (
	ScreenVerdict Screen = iota
	ScreenFindings
	ScreenDetail
	ScreenLive
	screenCount
)

// Model is the top-level bubbletea model. It only imports internal/model
// (spec §3.1: tui only imports model).
type Model struct {
	result       model.Result
	screen       Screen
	width        int
	findingIndex int
	checkIndex   int
	quitting     bool
}

// New builds a Model that renders the given result, starting on the
// verdict screen (spec §9.3).
func New(result model.Result) Model {
	return Model{result: result, screen: ScreenVerdict}
}

func (m Model) Init() tea.Cmd { return nil }

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		return m, nil
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			m.quitting = true
			return m, tea.Quit
		case "tab", "right":
			m.screen = (m.screen + 1) % screenCount
			return m, nil
		case "shift+tab", "left":
			m.screen = (m.screen + screenCount - 1) % screenCount
			return m, nil
		case "down", "j":
			m.moveSelection(1)
			return m, nil
		case "up", "k":
			m.moveSelection(-1)
			return m, nil
		case "enter":
			if m.screen == ScreenFindings {
				m.screen = ScreenDetail
			}
			return m, nil
		}
	}
	return m, nil
}

func (m Model) View() string {
	if m.quitting {
		return ""
	}
	var b strings.Builder
	b.WriteString(m.renderHeader())
	b.WriteString("\n")
	switch m.screen {
	case ScreenVerdict:
		b.WriteString(renderVerdictScreen(m.result, m.width))
	case ScreenFindings:
		b.WriteString(renderFindingsScreen(m.result, m.findingIndex, m.width))
	case ScreenDetail:
		b.WriteString(renderDetailScreen(m.result, m.checkIndex, m.width))
	case ScreenLive:
		b.WriteString(renderLiveScreen(m.result, m.width))
	}
	return b.String()
}

func (m Model) renderHeader() string {
	glyph := ProfileGlyph(m.result.Profile)
	return fmt.Sprintf("wifisec  %s %s  paket:%d  %s",
		glyph, m.result.Profile, totalPackets(m.result.Checks), m.result.StartedAt.Format("15:04:05"))
}

func totalPackets(checks []model.Check) int {
	total := 0
	for _, c := range checks {
		total += c.PacketsSent
	}
	return total
}

func (m *Model) moveSelection(delta int) {
	switch m.screen {
	case ScreenFindings:
		n := len(m.result.Findings)
		if n == 0 {
			return
		}
		m.findingIndex = clampIndex(m.findingIndex+delta, n)
	case ScreenDetail:
		n := len(m.result.Checks)
		if n == 0 {
			return
		}
		m.checkIndex = clampIndex(m.checkIndex+delta, n)
	}
}

func clampIndex(i, n int) int {
	if i < 0 {
		return 0
	}
	if i >= n {
		return n - 1
	}
	return i
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/tui/... -v`
Expected: PASS (all tui package tests, including Tasks 7-12)

- [ ] **Step 5: Commit**

```bash
git add internal/tui/app.go internal/tui/app_test.go
git commit -m "feat(tui): wire screens into a navigable bubbletea Model"
```

---

### Task 14: Fixtures + golden-file renderer test (T5)

**Files:**
- Create: `testdata/fixtures/clean_home.json`
- Create: `testdata/fixtures/corporate_mitm.json`
- Create: `testdata/fixtures/captive_portal.json`
- Create: `testdata/fixtures/open_wifi.json`
- Create: `testdata/fixtures/passive_only.json`
- Create: `testdata/fixtures/all_failed.json`
- Create: `internal/tui/golden_test.go`

**Interfaces:**
- Consumes: `model.Result` (JSON schema, Task 5); `tui.New`, `tui.Screen` constants (Task 13).
- Produces: `testdata/golden/<fixture>.<screen>.golden` files (generated by running the test with `-update`).

- [ ] **Step 1: Create the six fixtures**

Create `testdata/fixtures/clean_home.json`:

```json
{
  "schema_version": "1.0",
  "tool_version": "0.1.0-m1",
  "run_id": "run-clean-home-0001",
  "started_at": "2026-08-16T09:00:00Z",
  "duration_ms": 850,
  "profile": "standard",
  "network": {
    "ssid_hash": "sha256:aaaa111100000000000000000000000000000000000000000000000000",
    "bssid_hash": "sha256:bbbb222200000000000000000000000000000000000000000000000000",
    "oui": "AC:DE:48",
    "band": "5GHz",
    "channel": 44,
    "security": "WPA3",
    "pmf": "required",
    "known_network": true
  },
  "checks": [
    {
      "id": "wifi.security",
      "layer": "wifi",
      "title": "Tipe enkripsi",
      "profile_required": "passive",
      "status": "normal",
      "confidence": "high",
      "observed": {"security": "WPA3"},
      "control": {"performed": false},
      "packets_sent": 0,
      "duration_ms": 5
    },
    {
      "id": "wifi.pmf",
      "layer": "wifi",
      "title": "Protected Management Frames",
      "profile_required": "passive",
      "status": "normal",
      "confidence": "high",
      "observed": {"pmf": "required"},
      "control": {"performed": false},
      "packets_sent": 0,
      "duration_ms": 4
    },
    {
      "id": "local.trust_store",
      "layer": "local",
      "title": "CA di trust store",
      "profile_required": "passive",
      "status": "normal",
      "confidence": "high",
      "observed": {"non_public_ca_found": false},
      "control": {"performed": false},
      "packets_sent": 0,
      "duration_ms": 12
    },
    {
      "id": "tls.cert_issuer",
      "layer": "tls",
      "title": "Penerbit sertifikat",
      "profile_required": "minimal",
      "status": "normal",
      "confidence": "high",
      "target": "example.com",
      "observed": {"issuer": "Let's Encrypt R3"},
      "expected": {"source": "baseline_bundled"},
      "control": {"performed": false},
      "packets_sent": 1,
      "duration_ms": 120
    },
    {
      "id": "dns.compare_doh",
      "layer": "dns",
      "title": "Perbandingan DNS jaringan vs DoH",
      "profile_required": "standard",
      "status": "normal",
      "confidence": "medium",
      "observed": {"match": true},
      "control": {"performed": true, "result": "match"},
      "packets_sent": 4,
      "duration_ms": 210
    },
    {
      "id": "net.captive_portal",
      "layer": "http",
      "title": "Deteksi captive portal",
      "profile_required": "standard",
      "status": "normal",
      "confidence": "high",
      "observed": {"portal_detected": false},
      "control": {"performed": false},
      "packets_sent": 2,
      "duration_ms": 90
    }
  ],
  "findings": [],
  "verdict": {
    "safety": "ok",
    "score": 100,
    "headline": "Jaringan ini tampak aman untuk penggunaan umum.",
    "top_findings": [],
    "blind_spots": [],
    "use_cases": {
      "browsing_umum": "ok",
      "login_akun_pribadi": "ok",
      "kerja_sensitif": "caution",
      "internet_banking": "caution"
    }
  }
}
```

Create `testdata/fixtures/corporate_mitm.json`:

```json
{
  "schema_version": "1.0",
  "tool_version": "0.1.0-m1",
  "run_id": "run-corporate-mitm-0001",
  "started_at": "2026-08-16T09:10:00Z",
  "duration_ms": 900,
  "profile": "standard",
  "network": {
    "ssid_hash": "sha256:cccc333300000000000000000000000000000000000000000000000000",
    "bssid_hash": "sha256:dddd444400000000000000000000000000000000000000000000000000",
    "oui": "00:1A:2B",
    "band": "5GHz",
    "channel": 36,
    "security": "WPA2",
    "pmf": "disabled",
    "known_network": false
  },
  "checks": [
    {
      "id": "local.trust_store",
      "layer": "local",
      "title": "CA di trust store",
      "profile_required": "passive",
      "status": "anomalous",
      "confidence": "high",
      "observed": {"non_public_ca_found": true, "subject": "Acme Corp Proxy CA", "issuer": "Acme Corp Root CA"},
      "control": {"performed": false},
      "packets_sent": 0,
      "duration_ms": 15
    },
    {
      "id": "tls.cert_issuer",
      "layer": "tls",
      "title": "Penerbit sertifikat",
      "profile_required": "minimal",
      "status": "anomalous",
      "confidence": "medium",
      "target": "example.com",
      "observed": {"issuer": "Acme Corp Proxy CA", "fingerprint": "sha256:9f9f0000", "chain_length": 2},
      "expected": {"source": "baseline_bundled", "issuer": "Let's Encrypt R3"},
      "control": {"performed": false},
      "packets_sent": 1,
      "duration_ms": 110
    },
    {
      "id": "wifi.security",
      "layer": "wifi",
      "title": "Tipe enkripsi",
      "profile_required": "passive",
      "status": "normal",
      "confidence": "high",
      "observed": {"security": "WPA2"},
      "control": {"performed": false},
      "packets_sent": 0,
      "duration_ms": 5
    }
  ],
  "findings": [
    {
      "id": "tls_interception",
      "severity": "critical",
      "confidence": "high",
      "title": "Trafik HTTPS kemungkinan besar dibaca oleh operator jaringan",
      "explanation": "Sertifikat diterbitkan oleh CA yang tidak dikenal publik dan CA tersebut terpasang di trust store perangkat ini.",
      "impact": ["password", "email", "chat", "internal_docs"],
      "based_on": ["tls.cert_issuer", "local.trust_store"],
      "recommendation": "Hindari login ke akun pribadi. Gunakan koneksi seluler untuk hal sensitif.",
      "false_positive_hints": ["Umum dan sah pada perangkat milik perusahaan dengan MDM."]
    }
  ],
  "verdict": {
    "safety": "avoid",
    "score": 60,
    "headline": "Trafik HTTPS di jaringan ini kemungkinan besar dapat dibaca oleh operator.",
    "top_findings": ["tls_interception"],
    "blind_spots": [],
    "use_cases": {
      "browsing_umum": "caution",
      "login_akun_pribadi": "avoid",
      "kerja_sensitif": "avoid",
      "internet_banking": "avoid"
    }
  }
}
```

Create `testdata/fixtures/captive_portal.json`:

```json
{
  "schema_version": "1.0",
  "tool_version": "0.1.0-m1",
  "run_id": "run-captive-portal-0001",
  "started_at": "2026-08-16T09:20:00Z",
  "duration_ms": 400,
  "profile": "standard",
  "network": {
    "ssid_hash": "sha256:eeee555500000000000000000000000000000000000000000000000000",
    "bssid_hash": "sha256:ffff666600000000000000000000000000000000000000000000000000",
    "band": "2.4GHz",
    "channel": 6,
    "security": "open",
    "pmf": "disabled",
    "known_network": false
  },
  "checks": [
    {
      "id": "net.captive_portal",
      "layer": "http",
      "title": "Deteksi captive portal",
      "profile_required": "standard",
      "status": "anomalous",
      "confidence": "high",
      "observed": {"portal_detected": true},
      "control": {"performed": false},
      "packets_sent": 2,
      "duration_ms": 80
    },
    {
      "id": "dns.compare_doh",
      "layer": "dns",
      "title": "Perbandingan DNS jaringan vs DoH",
      "profile_required": "standard",
      "status": "inconclusive",
      "confidence": "low",
      "control": {"performed": false, "reason": "captive_portal_detected"},
      "packets_sent": 0,
      "duration_ms": 20
    },
    {
      "id": "net.latency_gateway",
      "layer": "perf",
      "title": "Latency ke gateway",
      "profile_required": "standard",
      "status": "inconclusive",
      "confidence": "low",
      "control": {"performed": false, "reason": "captive_portal_detected"},
      "packets_sent": 0,
      "duration_ms": 5
    }
  ],
  "findings": [
    {
      "id": "captive_portal",
      "severity": "info",
      "confidence": "high",
      "title": "Jaringan memerlukan login portal",
      "explanation": "Portal captive terdeteksi dan belum login; pemeriksaan lain ditunda.",
      "based_on": ["net.captive_portal"],
      "recommendation": "Login ke portal lalu jalankan pemeriksaan ulang."
    }
  ],
  "verdict": {
    "safety": "unknown",
    "score": 95,
    "headline": "Login ke portal jaringan diperlukan sebelum pemeriksaan lain dapat dilakukan.",
    "top_findings": ["captive_portal"],
    "blind_spots": ["Kualitas DNS dan latency belum diperiksa karena portal captive."],
    "use_cases": {
      "browsing_umum": "caution",
      "login_akun_pribadi": "caution",
      "kerja_sensitif": "caution",
      "internet_banking": "caution"
    }
  }
}
```

Create `testdata/fixtures/open_wifi.json`:

```json
{
  "schema_version": "1.0",
  "tool_version": "0.1.0-m1",
  "run_id": "run-open-wifi-0001",
  "started_at": "2026-08-16T09:30:00Z",
  "duration_ms": 300,
  "profile": "minimal",
  "network": {
    "ssid_hash": "sha256:1111aaaa00000000000000000000000000000000000000000000000000",
    "bssid_hash": "sha256:2222bbbb00000000000000000000000000000000000000000000000000",
    "band": "2.4GHz",
    "channel": 1,
    "security": "open",
    "pmf": "disabled",
    "known_network": false
  },
  "checks": [
    {
      "id": "wifi.security",
      "layer": "wifi",
      "title": "Tipe enkripsi",
      "profile_required": "passive",
      "status": "anomalous",
      "confidence": "medium",
      "observed": {"security": "open"},
      "control": {"performed": false},
      "packets_sent": 0,
      "duration_ms": 4
    },
    {
      "id": "wifi.pmf",
      "layer": "wifi",
      "title": "Protected Management Frames",
      "profile_required": "passive",
      "status": "anomalous",
      "confidence": "medium",
      "observed": {"pmf": "disabled"},
      "control": {"performed": false},
      "packets_sent": 0,
      "duration_ms": 3
    },
    {
      "id": "tls.cert_issuer",
      "layer": "tls",
      "title": "Penerbit sertifikat",
      "profile_required": "minimal",
      "status": "normal",
      "confidence": "high",
      "target": "example.com",
      "observed": {"issuer": "Let's Encrypt R3"},
      "expected": {"source": "baseline_bundled"},
      "control": {"performed": false},
      "packets_sent": 1,
      "duration_ms": 100
    }
  ],
  "findings": [
    {
      "id": "weak_encryption",
      "severity": "critical",
      "confidence": "high",
      "title": "Jaringan tidak terenkripsi",
      "explanation": "Jaringan WiFi ini terbuka (open); trafik lapisan link dapat disadap siapa pun dalam jangkauan.",
      "based_on": ["wifi.security"],
      "recommendation": "Gunakan VPN atau hindari trafik sensitif di jaringan ini."
    },
    {
      "id": "no_pmf",
      "severity": "warning",
      "confidence": "medium",
      "title": "Protected Management Frames tidak aktif",
      "explanation": "Frame manajemen WiFi tidak dilindungi, membuka peluang deauth palsu.",
      "based_on": ["wifi.pmf"],
      "recommendation": "Waspadai koneksi terputus mendadak; itu bisa jadi serangan deauth."
    }
  ],
  "verdict": {
    "safety": "avoid",
    "score": 45,
    "headline": "Jaringan terbuka tanpa enkripsi; trafik non-HTTPS dapat disadap.",
    "top_findings": ["weak_encryption", "no_pmf"],
    "blind_spots": [],
    "use_cases": {
      "browsing_umum": "caution",
      "login_akun_pribadi": "avoid",
      "kerja_sensitif": "avoid",
      "internet_banking": "avoid"
    }
  }
}
```

Create `testdata/fixtures/passive_only.json`:

```json
{
  "schema_version": "1.0",
  "tool_version": "0.1.0-m1",
  "run_id": "run-passive-only-0001",
  "started_at": "2026-08-16T09:40:00Z",
  "duration_ms": 120,
  "profile": "passive",
  "network": {
    "ssid_hash": "sha256:3333cccc00000000000000000000000000000000000000000000000000",
    "bssid_hash": "sha256:4444dddd00000000000000000000000000000000000000000000000000",
    "band": "5GHz",
    "channel": 149,
    "security": "WPA2",
    "pmf": "optional",
    "known_network": false
  },
  "checks": [
    {
      "id": "wifi.security",
      "layer": "wifi",
      "title": "Tipe enkripsi",
      "profile_required": "passive",
      "status": "normal",
      "confidence": "high",
      "observed": {"security": "WPA2"},
      "control": {"performed": false},
      "packets_sent": 0,
      "duration_ms": 4
    },
    {
      "id": "local.trust_store",
      "layer": "local",
      "title": "CA di trust store",
      "profile_required": "passive",
      "status": "normal",
      "confidence": "high",
      "observed": {"non_public_ca_found": false},
      "control": {"performed": false},
      "packets_sent": 0,
      "duration_ms": 10
    },
    {
      "id": "dns.resolve_basic",
      "layer": "dns",
      "title": "Resolusi DNS dasar",
      "profile_required": "minimal",
      "status": "skipped",
      "confidence": "low",
      "control": {"performed": false, "reason": "profile_does_not_allow"},
      "packets_sent": 0,
      "duration_ms": 0
    },
    {
      "id": "tls.cert_issuer",
      "layer": "tls",
      "title": "Penerbit sertifikat",
      "profile_required": "minimal",
      "status": "skipped",
      "confidence": "low",
      "control": {"performed": false, "reason": "profile_does_not_allow"},
      "packets_sent": 0,
      "duration_ms": 0
    },
    {
      "id": "net.captive_portal",
      "layer": "http",
      "title": "Deteksi captive portal",
      "profile_required": "standard",
      "status": "skipped",
      "confidence": "low",
      "control": {"performed": false, "reason": "profile_does_not_allow"},
      "packets_sent": 0,
      "duration_ms": 0
    }
  ],
  "findings": [],
  "verdict": {
    "safety": "unknown",
    "score": 100,
    "headline": "Hanya pemeriksaan pasif yang dijalankan; keyakinan verdict rendah.",
    "top_findings": [],
    "blind_spots": [
      "Keamanan HTTPS (TLS) tidak diperiksa - profil passive tidak mengirim paket.",
      "DNS tidak diperiksa - profil passive tidak mengirim paket.",
      "Captive portal dan kualitas jaringan tidak diperiksa - memerlukan profil standard."
    ],
    "use_cases": {
      "browsing_umum": "caution",
      "login_akun_pribadi": "caution",
      "kerja_sensitif": "caution",
      "internet_banking": "caution"
    }
  }
}
```

Create `testdata/fixtures/all_failed.json`:

```json
{
  "schema_version": "1.0",
  "tool_version": "0.1.0-m1",
  "run_id": "run-all-failed-0001",
  "started_at": "2026-08-16T09:50:00Z",
  "duration_ms": 60,
  "profile": "minimal",
  "network": {
    "ssid_hash": "sha256:5555eeee00000000000000000000000000000000000000000000000000",
    "bssid_hash": "sha256:6666ffff00000000000000000000000000000000000000000000000000",
    "known_network": false
  },
  "checks": [
    {
      "id": "local.interface",
      "layer": "local",
      "title": "Konfigurasi interface",
      "profile_required": "passive",
      "status": "error",
      "confidence": "low",
      "control": {"performed": false},
      "packets_sent": 0,
      "duration_ms": 5,
      "error": "gagal membaca interface: permission denied"
    },
    {
      "id": "wifi.security",
      "layer": "wifi",
      "title": "Tipe enkripsi",
      "profile_required": "passive",
      "status": "error",
      "confidence": "low",
      "control": {"performed": false},
      "packets_sent": 0,
      "duration_ms": 3,
      "error": "wifi adapter tidak terdeteksi"
    },
    {
      "id": "dns.resolve_basic",
      "layer": "dns",
      "title": "Resolusi DNS dasar",
      "profile_required": "minimal",
      "status": "error",
      "confidence": "low",
      "control": {"performed": false},
      "packets_sent": 0,
      "duration_ms": 30,
      "error": "timeout menghubungi resolver"
    }
  ],
  "findings": [],
  "verdict": {
    "safety": "unknown",
    "score": 0,
    "headline": "Seluruh pemeriksaan gagal dijalankan; tidak ada kesimpulan yang dapat diberikan.",
    "top_findings": [],
    "blind_spots": [
      "Seluruh check gagal - tidak ada satu pun aspek jaringan yang berhasil diperiksa."
    ],
    "use_cases": {
      "browsing_umum": "caution",
      "login_akun_pribadi": "caution",
      "kerja_sensitif": "caution",
      "internet_banking": "caution"
    }
  }
}
```

- [ ] **Step 2: Write the golden-file test harness**

Create `internal/tui/golden_test.go`:

```go
package tui

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/Maulana-anjari/wifisec/internal/model"
)

var update = flag.Bool("update", false, "regenerate golden files")

// TestRenderFixturesGolden is T5 (spec §8.1): every fixture is
// rendered on every screen and compared against a checked-in golden
// file. No network access happens anywhere in this test.
func TestRenderFixturesGolden(t *testing.T) {
	fixtures, err := filepath.Glob(filepath.Join("..", "..", "testdata", "fixtures", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(fixtures) == 0 {
		t.Fatal("no fixtures found under testdata/fixtures")
	}

	screens := []struct {
		name   string
		screen Screen
	}{
		{"verdict", ScreenVerdict},
		{"findings", ScreenFindings},
		{"detail", ScreenDetail},
		{"live", ScreenLive},
	}

	for _, path := range fixtures {
		path := path
		name := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))

		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var result model.Result
		if err := json.Unmarshal(data, &result); err != nil {
			t.Fatalf("%s: %v", path, err)
		}

		for _, sc := range screens {
			sc := sc
			t.Run(name+"/"+sc.name, func(t *testing.T) {
				m := New(result)
				next, _ := m.Update(tea.WindowSizeMsg{Width: 100, Height: 40})
				m = next.(Model)
				m = gotoScreen(m, sc.screen)
				got := m.View()

				goldenPath := filepath.Join("..", "..", "testdata", "golden", name+"."+sc.name+".golden")
				if *update {
					if err := os.MkdirAll(filepath.Dir(goldenPath), 0o755); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(goldenPath, []byte(got), 0o644); err != nil {
						t.Fatal(err)
					}
				}

				want, err := os.ReadFile(goldenPath)
				if err != nil {
					t.Fatalf("missing golden file %s (run with -update to create it): %v", goldenPath, err)
				}
				if got != string(want) {
					t.Errorf("golden mismatch for %s/%s\n--- got ---\n%s\n--- want ---\n%s", name, sc.name, got, want)
				}
			})
		}
	}
}

func gotoScreen(m Model, target Screen) Model {
	for i := 0; i < int(target); i++ {
		next, _ := m.Update(tea.KeyMsg{Type: tea.KeyTab})
		m = next.(Model)
	}
	return m
}
```

- [ ] **Step 3: Generate the golden files**

Run:
```bash
go test ./internal/tui/... -run TestRenderFixturesGolden -update -v
```
Expected: PASS, and `testdata/golden/` is populated with 24 files (6 fixtures × 4 screens). Open a few and eyeball them for sanity — e.g. `testdata/golden/corporate_mitm.verdict.golden` should show `AVOID` and the `tls_interception` finding.

- [ ] **Step 4: Run the test again without `-update` to confirm it's stable**

Run: `go test ./internal/tui/... -run TestRenderFixturesGolden -v`
Expected: PASS (24 subtests) — proves the renderer is a pure function of its input (T5).

- [ ] **Step 5: Commit**

```bash
git add testdata/fixtures testdata/golden internal/tui/golden_test.go
git commit -m "test(tui): add T5 golden-file fixture renderer coverage"
```

---

### Task 15: `cmd/wifisec` entrypoint

**Files:**
- Create: `cmd/wifisec/main.go`

**Interfaces:**
- Consumes: `model.Result` (Task 5), `tui.New` (Task 13).

- [ ] **Step 1: Write the entrypoint**

Create `cmd/wifisec/main.go`:

```go
package main

import (
	"encoding/json"
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/Maulana-anjari/wifisec/internal/model"
	"github.com/Maulana-anjari/wifisec/internal/tui"
)

// main is an M1 stub: it renders a pre-built model.Result JSON file so
// the TUI can be exercised manually end to end. Flag parsing, profile
// selection, and running real checks land in later milestones
// (spec §9.1, §11 M2-M4).
func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: wifisec <result.json>")
		os.Exit(1)
	}
	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "read result:", err)
		os.Exit(1)
	}
	var result model.Result
	if err := json.Unmarshal(data, &result); err != nil {
		fmt.Fprintln(os.Stderr, "parse result:", err)
		os.Exit(1)
	}
	if _, err := tea.NewProgram(tui.New(result)).Run(); err != nil {
		fmt.Fprintln(os.Stderr, "tui error:", err)
		os.Exit(1)
	}
}
```

- [ ] **Step 2: Verify it builds and runs manually**

Run:
```bash
go build ./...
go run ./cmd/wifisec testdata/fixtures/clean_home.json
```
Expected: build succeeds; the TUI launches showing the `clean_home` verdict screen. Manually confirm: `tab` cycles through all four screens, `q` quits. This is the manual half of "M1 selesai bila: seluruh fixture dapat dirender dan dinavigasi" (spec §11) — the automated half is Task 14's golden test.

- [ ] **Step 3: Commit**

```bash
git add cmd/wifisec/main.go
git commit -m "feat(cmd): add M1 stub entrypoint that renders a Result JSON file"
```

---

### Task 16: Final verification

**Files:** none (verification only)

- [ ] **Step 1: Build everything**

Run: `go build ./...`
Expected: no errors.

- [ ] **Step 2: Vet everything**

Run: `go vet ./...`
Expected: no warnings.

- [ ] **Step 3: Run the full test suite**

Run: `go test ./... -v`
Expected: PASS across `internal/model`, `internal/registry`, `internal/tui` — covering T5 (golden fixtures), T6 (`ValidateCheck`), T7 (`ValidateVerdict`), and T9 (`Result` round trip).

- [ ] **Step 4: Confirm M1 exit criteria against spec §11**

Checklist:
- [ ] Types from spec §4 exist in `internal/model`, field names/JSON tags unchanged.
- [ ] Registry loader exists and `Filter` respects `ProfileRequired.Level()`.
- [ ] All six fixtures from spec §8.2 exist under `testdata/fixtures/`.
- [ ] All four TUI screens render from every fixture (verified by `go test ./internal/tui/...`) and are manually navigable (verified by `go run ./cmd/wifisec <fixture>`).
- [ ] No file under `internal/` or `cmd/` imports `net`, `net/http`, `net/dns`, or opens a socket.
- [ ] T5, T6, T7, T9 pass.

- [ ] **Step 5: Commit (if any cleanup was needed)**

```bash
git status
# if clean, nothing to commit — M1 is complete
```
