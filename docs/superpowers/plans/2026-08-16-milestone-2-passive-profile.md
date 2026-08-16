# Milestone 2: Passive Profile — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `wifisec` produce a real verdict on a real network: a Linux platform adapter, all 13 spec §6.1 passive (zero-packet) checks, the packet counter guard rail, and enough of the interpret engine to turn real check results into a real `model.Verdict`.

**Architecture:** `internal/platform` (OS adapter, Linux only this milestone) → `internal/guard` (packet counter) → `internal/checks` (Checker interface + concurrent streaming runner) with two leaf subpackages `internal/checks/local` and `internal/checks/wifi` implementing the 13 checks → `internal/interpret` (rules.yaml-driven findings + §7.3 verdict scoring) → wired into `cmd/wifisec` as a new no-argument invocation path that runs for real and launches the TUI with a live `model.Result`.

**Tech Stack:** Go 1.24 (as landed in M1's `go.mod`), same three approved deps (bubbletea, lipgloss, yaml.v3) — this milestone adds no new third-party dependency; `ip -j` (iproute2, JSON output) and `nmcli` (NetworkManager) are shelled out to, both already present on the target Linux dev machine.

**Spec:** `SPEC-wifisec.md` (repo root) — this plan implements §4.6 (Checker/CheckContext), §4.7 (platform.Adapter), §5.1 (PacketCounter), §6.1 (13 passive checks), a scoped slice of §7 (interpret) sufficient for real findings/verdict, and the M2 exit criteria in §11.

## Global Constraints

- Go module path `github.com/Maulana-anjari/wifisec`, module currently pins `go 1.24.0` (M1 fix wave; do not lower it).
- No new third-party dependency without explicit approval — everything in this plan uses stdlib plus the three deps already in `go.mod`.
- `internal/model` still imports nothing internal — this milestone does not touch it.
- `internal/checks` (parent package) imports `internal/model`, `internal/registry`, `internal/platform`, `internal/guard` — never `internal/tui`. `internal/checks/local` and `internal/checks/wifi` import `internal/checks` (for the `Checker`/`CheckContext` types) plus the same set — never each other, never `internal/tui`.
- **Zero network packets in this milestone.** All 13 §6.1 checks are `estimated_packets: 0` in the registry. Shelling out to local system commands (`ip`, `nmcli`) is not a network packet — but `nmcli`'s WiFi-scan subcommand can trigger a live 802.11 scan unless told not to. **Every `nmcli ... device wifi list` invocation in this plan MUST include `--rescan no`.** This is the single most safety-critical detail in this milestone — T1 (passive profile sends zero packets) is spec's own most-important test (§8.1: "Ini test terpenting di seluruh proyek").
- Code style: short functions, no speculative abstraction, errors handled at the call site, avoid generics unless they remove real duplication, avoid reflection entirely.
- Design decisions already made (do not re-litigate; ask the user only if you find these are actually wrong, not merely debatable):
  - Public-CA classification list is bundled into the binary via `go:embed`, sourced from this dev machine's `/etc/ssl/certs/*.pem` (Debian/Ubuntu's `ca-certificates` package — a real Mozilla-curated bundle, not a fabricated list).
  - macOS is out of scope this milestone; `internal/platform/stub.go` (build tag `!linux && !darwin`) already covers it gracefully via `Available: false`.
  - `internal/interpret` in this milestone covers only rules reachable from §6.1 checks: `weak_encryption`, `no_pmf`, `foreign_ca_present`, `dns_internal_resolver`. The remaining §7.2 rules need checks from later milestones and are out of scope here.
  - `platform.CACert` and `platform.Route` have no literal spec definition (spec §4.7 references both types without defining their fields) — this plan defines minimal, obviously-needed fields based on how each type is used elsewhere in the spec (fixture examples, finding descriptions).
  - WiFi signal strength: `nmcli` only exposes a 0–100 quality percentage, not raw dBm. This plan converts via NetworkManager's own documented reverse formula (`dBm = quality/2 - 100`) and reports it as an approximation, not raw radio dBm.
  - WiFi PMF status: `nmcli` does not expose it in the fields this plan reads, and `wpa_cli` requires elevated permissions not available to an unprivileged user. `WiFiInfo.PMF` is reported as `""` (unknown) rather than guessed; the `wifi.pmf` check treats an empty PMF as `StatusInconclusive`, not a false "disabled".
  - The check-ID → concrete-`Checker` factory mapping lives in `cmd/wifisec` (the only current consumer), not as a new internal package — avoids both an import cycle (`internal/checks` cannot import its own `local`/`wifi` subpackages) and a premature abstraction.

---

### Task 1: `internal/platform` types, `Adapter` interface, stub adapter

**Files:**
- Create: `internal/platform/platform.go`
- Create: `internal/platform/stub.go`
- Test: `internal/platform/platform_test.go`

**Interfaces:**
- Produces: `type WiFiInfo struct{...}`, `type NetConfig struct{...}`, `type ProxyConfig struct{...}`, `type CACert struct{...}`, `type Route struct{...}`, `type Adapter interface{...}`.

- [ ] **Step 1: Write the failing test**

Create `internal/platform/platform_test.go`:

```go
package platform

import "testing"

func TestNewReturnsNonNilAdapter(t *testing.T) {
	a := New()
	if a == nil {
		t.Fatal("New() returned nil")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/platform/... -v`
Expected: FAIL — package doesn't exist yet.

- [ ] **Step 3: Write the types and interface**

Create `internal/platform/platform.go`:

```go
// Package platform provides zero-network-packet OS introspection (spec
// §4.7): current WiFi association, IP configuration, system proxy,
// installed trust-store CAs, and the routing table. Every method must
// return Available/Reason-style partial data rather than an error when
// information is merely unavailable — only a genuinely broken adapter
// call returns a non-nil error.
package platform

type WiFiInfo struct {
	SSID      string
	BSSID     string
	RSSI      int
	Channel   int
	Band      string
	Security  string
	PMF       string
	LinkSpeed int
	Available bool
	Reason    string // set when Available == false
}

type NetConfig struct {
	Interface  string
	IP         string
	Gateway    string
	Netmask    string
	MTU        int
	DNSServers []string
}

type ProxyConfig struct {
	Enabled    bool
	HTTPProxy  string
	HTTPSProxy string
	PACUrl     string
}

// CACert is one certificate found in the OS trust store (spec §4.7,
// consumed by the local.trust_store check). Not part of the spec's
// literal struct list — spec §4.7 references the type without defining
// its fields; these are the minimal fields local.trust_store needs to
// report a finding (spec fixture example: "subject"/"issuer" keys).
type CACert struct {
	Subject     string
	Issuer      string
	Fingerprint string // "sha256:<hex>", same format as model.NetworkInfo's hashes
}

// Route is one routing-table entry (spec §4.7, consumed by
// local.routing). Same note as CACert: fields chosen for what
// local.routing needs to report ("rute default, rute mencurigakan").
type Route struct {
	Destination string
	Gateway     string
	Interface   string
	Metric      int
	Default     bool
}

// Adapter is the OS-specific implementation selected by New() via
// build tags (spec §4.7). Every method must be zero-network-packet.
type Adapter interface {
	WiFiInfo() (WiFiInfo, error)
	NetConfig() (NetConfig, error)
	ProxyConfig() (ProxyConfig, error)
	TrustStoreCAs() ([]CACert, error)
	RoutingTable() ([]Route, error)
}
```

- [ ] **Step 4: Write the stub adapter for unsupported platforms**

Create `internal/platform/stub.go`:

```go
//go:build !linux && !darwin

package platform

// stubAdapter backs platforms with no real adapter yet (spec §4.7:
// "Jika utilitas tidak tersedia... kembalikan WiFiInfo{Available:
// false, ...} — jangan kembalikan error yang menggagalkan seluruh
// run"). darwin.go (a later milestone) will narrow this build tag's
// effective platforms automatically once it exists.
type stubAdapter struct{}

func New() Adapter { return stubAdapter{} }

func (stubAdapter) WiFiInfo() (WiFiInfo, error) {
	return WiFiInfo{Available: false, Reason: "platform not supported"}, nil
}

func (stubAdapter) NetConfig() (NetConfig, error) {
	return NetConfig{}, nil
}

func (stubAdapter) ProxyConfig() (ProxyConfig, error) {
	return ProxyConfig{}, nil
}

func (stubAdapter) TrustStoreCAs() ([]CACert, error) {
	return nil, nil
}

func (stubAdapter) RoutingTable() ([]Route, error) {
	return nil, nil
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `go test ./internal/platform/... -v`
Expected: PASS (this repo builds on Linux, so `New()` here actually resolves to Task 2's `linux.go` once it exists — for this task alone, if `linux.go` doesn't exist yet, `stub.go`'s tag `!linux && !darwin` means it will NOT compile standalone on this Linux machine. To verify Task 1 in isolation, temporarily note in your test run that `go build ./internal/platform/...` will fail to link `New()` on Linux until Task 2 lands — this is expected and resolves itself once Task 2 is committed. Do not work around it by weakening the build tag.)

- [ ] **Step 6: Commit**

```bash
git add internal/platform/platform.go internal/platform/stub.go internal/platform/platform_test.go
git commit -m "feat(platform): add Adapter interface, types, and stub fallback"
```

---

### Task 2: `internal/platform/linux.go` — real Linux adapter

**Files:**
- Create: `internal/platform/linux.go`
- Test: `internal/platform/linux_test.go`

**Interfaces:**
- Consumes: `platform.WiFiInfo`, `platform.NetConfig`, `platform.ProxyConfig`, `platform.CACert`, `platform.Route`, `platform.Adapter` (Task 1).
- Produces: `New() Adapter` (Linux build), satisfying `Adapter` for `linuxAdapter`.

This is the biggest task in the milestone — it's one file because Go requires every `Adapter` method present before it type-checks, so splitting it across tasks would leave an uncompilable intermediate state.

- [ ] **Step 1: Write the failing tests**

Create `internal/platform/linux_test.go`:

```go
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/platform/... -run TestLinux -v`
Expected: FAIL — `linuxAdapter`/`New()` (Linux build) don't exist yet.

- [ ] **Step 3: Write the implementation**

Create `internal/platform/linux.go`:

```go
//go:build linux

package platform

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

type linuxAdapter struct{}

func New() Adapter { return linuxAdapter{} }

// --- NetConfig ---

type ipRouteEntry struct {
	Dst     string `json:"dst"`
	Gateway string `json:"gateway"`
	Dev     string `json:"dev"`
	Metric  int    `json:"metric"`
}

type ipAddrEntry struct {
	IfName   string `json:"ifname"`
	MTU      int    `json:"mtu"`
	AddrInfo []struct {
		Family    string `json:"family"`
		Local     string `json:"local"`
		PrefixLen int    `json:"prefixlen"`
	} `json:"addr_info"`
}

func (linuxAdapter) NetConfig() (NetConfig, error) {
	routeOut, err := exec.Command("ip", "-j", "route", "show", "default").Output()
	if err != nil {
		return NetConfig{}, fmt.Errorf("platform: ip route show default: %w", err)
	}
	var routes []ipRouteEntry
	if err := json.Unmarshal(routeOut, &routes); err != nil {
		return NetConfig{}, fmt.Errorf("platform: parse ip route output: %w", err)
	}

	cfg := NetConfig{DNSServers: parseResolvConf("/etc/resolv.conf")}
	if len(routes) == 0 {
		return cfg, nil // no default route is valid, informative data (not an error)
	}
	cfg.Interface = routes[0].Dev
	cfg.Gateway = routes[0].Gateway

	addrOut, err := exec.Command("ip", "-j", "addr", "show", "dev", cfg.Interface).Output()
	if err != nil {
		return cfg, nil // interface details unavailable; the route info we have still stands
	}
	var addrs []ipAddrEntry
	if err := json.Unmarshal(addrOut, &addrs); err != nil || len(addrs) == 0 {
		return cfg, nil
	}
	cfg.MTU = addrs[0].MTU
	for _, a := range addrs[0].AddrInfo {
		if a.Family == "inet" {
			cfg.IP = a.Local
			cfg.Netmask = cidrToNetmask(a.PrefixLen)
			break
		}
	}
	return cfg, nil
}

func cidrToNetmask(prefixLen int) string {
	if prefixLen < 0 || prefixLen > 32 {
		return ""
	}
	mask := uint32(0xffffffff) << (32 - prefixLen)
	return fmt.Sprintf("%d.%d.%d.%d",
		byte(mask>>24), byte(mask>>16), byte(mask>>8), byte(mask))
}

func parseResolvConf(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var servers []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "nameserver ") {
			continue
		}
		servers = append(servers, strings.TrimSpace(strings.TrimPrefix(line, "nameserver ")))
	}
	return servers
}

// --- RoutingTable ---

func (linuxAdapter) RoutingTable() ([]Route, error) {
	out, err := exec.Command("ip", "-j", "route", "show").Output()
	if err != nil {
		return nil, fmt.Errorf("platform: ip route show: %w", err)
	}
	var entries []ipRouteEntry
	if err := json.Unmarshal(out, &entries); err != nil {
		return nil, fmt.Errorf("platform: parse ip route output: %w", err)
	}
	routes := make([]Route, 0, len(entries))
	for _, e := range entries {
		routes = append(routes, Route{
			Destination: e.Dst,
			Gateway:     e.Gateway,
			Interface:   e.Dev,
			Metric:      e.Metric,
			Default:     e.Dst == "default",
		})
	}
	return routes, nil
}

// --- ProxyConfig ---

func (linuxAdapter) ProxyConfig() (ProxyConfig, error) {
	httpProxy := firstNonEmptyEnv("http_proxy", "HTTP_PROXY")
	httpsProxy := firstNonEmptyEnv("https_proxy", "HTTPS_PROXY")
	return ProxyConfig{
		Enabled:    httpProxy != "" || httpsProxy != "",
		HTTPProxy:  httpProxy,
		HTTPSProxy: httpsProxy,
		// PACUrl: no portable env-var convention on Linux; desktop-
		// environment-specific detection (gsettings, kioslaverc) is
		// out of scope for this milestone.
	}, nil
}

func firstNonEmptyEnv(names ...string) string {
	for _, n := range names {
		if v := os.Getenv(n); v != "" {
			return v
		}
	}
	return ""
}

// --- TrustStoreCAs ---

func (linuxAdapter) TrustStoreCAs() ([]CACert, error) {
	entries, err := os.ReadDir("/etc/ssl/certs")
	if err != nil {
		return nil, nil // no trust store at the expected path is informative, not fatal
	}
	var certs []CACert
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".pem") {
			continue
		}
		data, err := os.ReadFile("/etc/ssl/certs/" + entry.Name())
		if err != nil {
			continue
		}
		block, _ := pem.Decode(data)
		if block == nil {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		sum := sha256.Sum256(cert.Raw)
		certs = append(certs, CACert{
			Subject:     cert.Subject.String(),
			Issuer:      cert.Issuer.String(),
			Fingerprint: "sha256:" + hex.EncodeToString(sum[:]),
		})
	}
	return certs, nil
}

// --- WiFiInfo ---

func (linuxAdapter) WiFiInfo() (WiFiInfo, error) {
	if _, ok := activeWiFiInterface(); !ok {
		return WiFiInfo{Available: false, Reason: "no connected wifi interface found"}, nil
	}

	// --rescan no is load-bearing: without it this subcommand can
	// trigger a live 802.11 probe scan, which would send packets in
	// the passive profile (spec P1, T1).
	out, err := exec.Command("nmcli", "-t", "-f",
		"active,ssid,bssid,chan,freq,rate,signal,security",
		"device", "wifi", "list", "--rescan", "no").Output()
	if err != nil {
		return WiFiInfo{Available: false, Reason: "nmcli not available: " + err.Error()}, nil
	}

	for _, line := range strings.Split(string(out), "\n") {
		fields := splitNmcliTerse(line)
		if len(fields) < 8 || fields[0] != "yes" {
			continue
		}
		channel, _ := strconv.Atoi(fields[3])
		freqMHz, _ := strconv.Atoi(strings.Fields(fields[4])[0])
		rate, _ := strconv.Atoi(strings.Fields(fields[5])[0])
		quality, _ := strconv.Atoi(fields[6])

		return WiFiInfo{
			SSID:      fields[1],
			BSSID:     fields[2],
			RSSI:      quality/2 - 100, // NetworkManager's own reverse quality->dBm formula; approximate
			Channel:   channel,
			Band:      bandForFreq(freqMHz),
			Security:  fields[7],
			PMF:       "", // not exposed by these nmcli fields; wpa_cli needs privileges we don't assume
			LinkSpeed: rate,
			Available: true,
		}, nil
	}
	return WiFiInfo{Available: false, Reason: "connected wifi interface found but nmcli reported no active network"}, nil
}

func activeWiFiInterface() (string, bool) {
	out, err := exec.Command("nmcli", "-t", "-f", "DEVICE,TYPE,STATE", "device", "status").Output()
	if err != nil {
		return "", false
	}
	for _, line := range strings.Split(string(out), "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		if parts[1] == "wifi" && strings.HasPrefix(parts[2], "connected") {
			return parts[0], true
		}
	}
	return "", false
}

func bandForFreq(mhz int) string {
	switch {
	case mhz >= 5925:
		return "6GHz"
	case mhz >= 4900:
		return "5GHz"
	case mhz > 0:
		return "2.4GHz"
	default:
		return ""
	}
}

// splitNmcliTerse splits one nmcli -t line on unescaped colons,
// unescaping "\:" back to ":" within a field (nmcli's terse output
// escapes literal colons inside values, e.g. a BSSID).
func splitNmcliTerse(line string) []string {
	var fields []string
	var cur strings.Builder
	escaped := false
	for _, r := range line {
		switch {
		case escaped:
			cur.WriteRune(r)
			escaped = false
		case r == '\\':
			escaped = true
		case r == ':':
			fields = append(fields, cur.String())
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}
	fields = append(fields, cur.String())
	return fields
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/platform/... -v`
Expected: PASS (5 Linux-specific tests + Task 1's `TestNewReturnsNonNilAdapter`, which now resolves to the real Linux adapter on this machine)

- [ ] **Step 5: Manually sanity-check the real output**

Run:
```bash
cat > /tmp/wifiinfo_check.go << 'EOF'
package main

import (
	"fmt"
	"github.com/Maulana-anjari/wifisec/internal/platform"
)

func main() {
	a := platform.New()
	wifi, _ := a.WiFiInfo()
	fmt.Printf("WiFi: %+v\n", wifi)
	net, _ := a.NetConfig()
	fmt.Printf("Net: %+v\n", net)
}
EOF
go run /tmp/wifiinfo_check.go
rm /tmp/wifiinfo_check.go
```
Expected: prints real SSID/BSSID/channel/etc. for this machine's current connection, and real interface/IP/gateway. Eyeball it for plausibility — this is the first time real data flows through the tool.

- [ ] **Step 6: Commit**

```bash
git add internal/platform/linux.go internal/platform/linux_test.go
git commit -m "feat(platform): add Linux adapter (ip, nmcli --rescan no, /etc/ssl/certs)"
```

---

### Task 3: `internal/guard` — packet counter

**Files:**
- Create: `internal/guard/counter.go`
- Test: `internal/guard/counter_test.go`

**Interfaces:**
- Produces: `type PacketCounter struct{...}`, `func NewPacketCounter(limit int) *PacketCounter`, `func (*PacketCounter) Add(checkID string, n int) error`, `func (*PacketCounter) Total() int`.

- [ ] **Step 1: Write the failing tests**

Create `internal/guard/counter_test.go`:

```go
package guard

import "testing"

func TestPacketCounterAddAccumulates(t *testing.T) {
	c := NewPacketCounter(10)
	if err := c.Add("check.a", 3); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := c.Add("check.b", 4); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := c.Total(); got != 7 {
		t.Errorf("Total() = %d, want 7", got)
	}
}

func TestPacketCounterRejectsOverLimit(t *testing.T) {
	c := NewPacketCounter(5)
	if err := c.Add("check.a", 3); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := c.Add("check.b", 3); err == nil {
		t.Error("expected error when exceeding limit (3+3 > 5)")
	}
	if got := c.Total(); got != 3 {
		t.Errorf("Total() after rejected Add = %d, want 3 (rejected add must not partially apply)", got)
	}
}

func TestPacketCounterZeroLimitRejectsAnyPacket(t *testing.T) {
	c := NewPacketCounter(0)
	if err := c.Add("check.a", 1); err == nil {
		t.Error("expected error: passive profile (limit 0) must reject any packet (spec §5.1)")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/guard/... -v`
Expected: FAIL — package doesn't exist yet.

- [ ] **Step 3: Write the implementation**

Create `internal/guard/counter.go`:

```go
// Package guard enforces profile packet limits (spec §5.1) — the
// second layer of defense after registry.Filter's profile-based
// check exclusion.
package guard

import (
	"fmt"
	"sync"
)

type PacketCounter struct {
	mu      sync.Mutex
	total   int
	byCheck map[string]int
	limit   int
}

// NewPacketCounter creates a counter enforcing the given packet limit
// (0 for the passive profile — spec §5.1: "limit adalah 0, sehingga
// panggilan Add apa pun mengembalikan error").
func NewPacketCounter(limit int) *PacketCounter {
	return &PacketCounter{byCheck: make(map[string]int), limit: limit}
}

// Add records n packets sent by checkID. It returns an error without
// applying any part of the increment if doing so would exceed the
// active profile's limit.
func (c *PacketCounter) Add(checkID string, n int) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.total+n > c.limit {
		return fmt.Errorf("guard: packet limit exceeded (limit %d, attempted +%d from %s, current total %d)", c.limit, n, checkID, c.total)
	}
	c.total += n
	c.byCheck[checkID] += n
	return nil
}

func (c *PacketCounter) Total() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.total
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/guard/... -v`
Expected: PASS (3 tests)

- [ ] **Step 5: Commit**

```bash
git add internal/guard/counter.go internal/guard/counter_test.go
git commit -m "feat(guard): add PacketCounter enforcing profile packet limits"
```

---

### Task 4: `internal/checks` — Checker interface, CheckContext, streaming runner

**Files:**
- Create: `internal/checks/checks.go`
- Create: `internal/checks/runner.go`
- Test: `internal/checks/runner_test.go`

**Interfaces:**
- Consumes: `model.Check` (M1), `registry.CheckDefinition` (M1), `platform.Adapter` (Task 1/2), `guard.PacketCounter` (Task 3).
- Produces: `type ControlServerConfig struct{}`, `type CheckContext struct{...}`, `type Checker interface{...}`, `func Run(ctx, checkers []Checker, cc CheckContext) <-chan model.Check`, `func NewErrorCheck(def registry.CheckDefinition, err error, start time.Time) model.Check`.

- [ ] **Step 1: Write the failing tests**

Create `internal/checks/runner_test.go`:

```go
package checks

import (
	"context"
	"testing"
	"time"

	"github.com/Maulana-anjari/wifisec/internal/model"
	"github.com/Maulana-anjari/wifisec/internal/registry"
)

type fakeChecker struct {
	id    string
	delay time.Duration
}

func (f fakeChecker) Definition() registry.CheckDefinition {
	return registry.CheckDefinition{ID: f.id, Layer: model.LayerLocal, Title: f.id}
}

func (f fakeChecker) Run(ctx context.Context, cc CheckContext) model.Check {
	time.Sleep(f.delay)
	return model.Check{ID: f.id, Status: model.StatusNormal, Confidence: model.ConfidenceHigh}
}

func TestRunStreamsAllResultsAndClosesChannel(t *testing.T) {
	checkers := []Checker{
		fakeChecker{id: "a", delay: 5 * time.Millisecond},
		fakeChecker{id: "b", delay: 1 * time.Millisecond},
		fakeChecker{id: "c"},
	}
	got := map[string]bool{}
	for c := range Run(context.Background(), checkers, CheckContext{}) {
		got[c.ID] = true
	}
	for _, want := range []string{"a", "b", "c"} {
		if !got[want] {
			t.Errorf("missing result for check %q", want)
		}
	}
}

func TestNewErrorCheckReportsError(t *testing.T) {
	def := registry.CheckDefinition{ID: "x", Layer: model.LayerLocal, Title: "X"}
	c := NewErrorCheck(def, errBoom, time.Now())
	if c.Status != model.StatusError {
		t.Errorf("Status = %s, want error", c.Status)
	}
	if c.ID != "x" || c.Error == "" {
		t.Errorf("expected ID and Error populated, got %+v", c)
	}
}

var errBoom = errBoomType{}

type errBoomType struct{}

func (errBoomType) Error() string { return "boom" }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/checks/... -v`
Expected: FAIL — package doesn't exist yet.

- [ ] **Step 3: Write the implementation**

Create `internal/checks/checks.go`:

```go
// Package checks defines the Checker contract every concrete check
// implements (internal/checks/local, internal/checks/wifi, and later
// milestones' dns/tls/net) and orchestrates running them concurrently
// (spec §4.6, §3.2).
package checks

import (
	"context"
	"time"

	"github.com/Maulana-anjari/wifisec/internal/guard"
	"github.com/Maulana-anjari/wifisec/internal/model"
	"github.com/Maulana-anjari/wifisec/internal/platform"
	"github.com/Maulana-anjari/wifisec/internal/registry"
)

// ControlServerConfig configures the optional control server used by
// checks that need a network-side comparison endpoint (spec §10).
// Empty in this milestone — no §6.1 check requires one. Expanded when
// Milestone 4 adds control-server-dependent checks.
type ControlServerConfig struct{}

type CheckContext struct {
	Platform      platform.Adapter
	Counter       *guard.PacketCounter
	ControlServer *ControlServerConfig
	Timeout       time.Duration
}

type Checker interface {
	Definition() registry.CheckDefinition
	Run(ctx context.Context, cc CheckContext) model.Check
}

// NewErrorCheck builds a Check reporting a failed run (spec §4.2
// StatusError), for the common "the platform call itself failed"
// path shared by every checker's Run implementation.
func NewErrorCheck(def registry.CheckDefinition, err error, start time.Time) model.Check {
	return model.Check{
		ID:              def.ID,
		Layer:           def.Layer,
		Title:           def.Title,
		ProfileRequired: def.ProfileRequired,
		Status:          model.StatusError,
		Confidence:      model.ConfidenceLow,
		Control:         model.Control{Performed: false},
		DurationMS:      time.Since(start).Milliseconds(),
		Error:           err.Error(),
	}
}
```

Create `internal/checks/runner.go`:

```go
package checks

import (
	"context"
	"sync"

	"github.com/Maulana-anjari/wifisec/internal/model"
)

// Run executes every checker concurrently, streaming each result to
// the returned channel as it completes (spec §3.2: "paralel, hasil ke
// channel"). The channel is closed once all checkers finish.
func Run(ctx context.Context, checkers []Checker, cc CheckContext) <-chan model.Check {
	out := make(chan model.Check)
	go func() {
		defer close(out)
		var wg sync.WaitGroup
		for _, checker := range checkers {
			wg.Add(1)
			go func(checker Checker) {
				defer wg.Done()
				out <- checker.Run(ctx, cc)
			}(checker)
		}
		wg.Wait()
	}()
	return out
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/checks/... -v`
Expected: PASS (2 tests)

- [ ] **Step 5: Commit**

```bash
git add internal/checks/checks.go internal/checks/runner.go internal/checks/runner_test.go
git commit -m "feat(checks): add Checker interface, CheckContext, concurrent streaming runner"
```

---

### Task 5: `internal/checks/local` — all 7 passive local checks

**Files:**
- Create: `internal/checks/local/interface.go`, `internal/checks/local/gateway.go`, `internal/checks/local/dns_servers.go`, `internal/checks/local/routing.go`, `internal/checks/local/mtu.go`, `internal/checks/local/proxy_system.go`, `internal/checks/local/trust_store.go`
- Create: `internal/checks/local/publicroots.pem` (embedded data)
- Test: `internal/checks/local/local_test.go`

**Interfaces:**
- Consumes: `checks.Checker`, `checks.CheckContext`, `checks.NewErrorCheck` (Task 4); `platform.NetConfig`, `platform.Route`, `platform.ProxyConfig`, `platform.CACert` (Task 1/2); `registry.CheckDefinition` (M1).
- Produces: `NewInterfaceCheck(def) checks.Checker`, `NewGatewayCheck(def) checks.Checker`, `NewDNSServersCheck(def) checks.Checker`, `NewRoutingCheck(def) checks.Checker`, `NewMTUCheck(def) checks.Checker`, `NewProxySystemCheck(def) checks.Checker`, `NewTrustStoreCheck(def) checks.Checker`.

- [ ] **Step 1: Snapshot the public CA bundle for embedding**

Run (from repo root):
```bash
mkdir -p internal/checks/local
cat /etc/ssl/certs/*.pem > internal/checks/local/publicroots.pem
wc -l internal/checks/local/publicroots.pem
```
Expected: a single multi-megabyte-free (~340KB) PEM file with 122 concatenated certificates. This is a frozen build-time snapshot of this dev machine's `ca-certificates` package (Debian/Ubuntu's Mozilla-curated bundle) — the reference list `local.trust_store` classifies "public" against (per the earlier user decision to bundle, not read-at-runtime).

- [ ] **Step 2: Write the failing tests**

Create `internal/checks/local/local_test.go`:

```go
package local

import (
	"context"
	"testing"

	"github.com/Maulana-anjari/wifisec/internal/checks"
	"github.com/Maulana-anjari/wifisec/internal/model"
	"github.com/Maulana-anjari/wifisec/internal/platform"
	"github.com/Maulana-anjari/wifisec/internal/registry"
)

type fakeAdapter struct {
	netConfig    platform.NetConfig
	netConfigErr error
	routes       []platform.Route
	proxy        platform.ProxyConfig
	cas          []platform.CACert
}

func (f fakeAdapter) WiFiInfo() (platform.WiFiInfo, error)      { return platform.WiFiInfo{}, nil }
func (f fakeAdapter) NetConfig() (platform.NetConfig, error)    { return f.netConfig, f.netConfigErr }
func (f fakeAdapter) ProxyConfig() (platform.ProxyConfig, error) { return f.proxy, nil }
func (f fakeAdapter) TrustStoreCAs() ([]platform.CACert, error) { return f.cas, nil }
func (f fakeAdapter) RoutingTable() ([]platform.Route, error)   { return f.routes, nil }

func testDef(id string) registry.CheckDefinition {
	return registry.CheckDefinition{ID: id, Layer: model.LayerLocal, Title: id, ProfileRequired: model.ProfilePassive, SelfEvident: id == "local.trust_store"}
}

func TestInterfaceCheckReportsNetConfig(t *testing.T) {
	a := fakeAdapter{netConfig: platform.NetConfig{Interface: "eth0", IP: "10.0.0.5", Netmask: "255.255.255.0", MTU: 1500}}
	c := NewInterfaceCheck(testDef("local.interface")).Run(context.Background(), checks.CheckContext{Platform: a})
	if c.Status != model.StatusNormal {
		t.Errorf("Status = %s, want normal", c.Status)
	}
	if c.Observed["interface"] != "eth0" {
		t.Errorf("Observed[interface] = %v, want eth0", c.Observed["interface"])
	}
	if c.PacketsSent != 0 {
		t.Errorf("PacketsSent = %d, want 0", c.PacketsSent)
	}
}

func TestGatewayCheckClassifiesPrivateIP(t *testing.T) {
	a := fakeAdapter{netConfig: platform.NetConfig{Gateway: "192.168.1.1"}}
	c := NewGatewayCheck(testDef("local.gateway")).Run(context.Background(), checks.CheckContext{Platform: a})
	if c.Observed["is_private"] != true {
		t.Errorf("Observed[is_private] = %v, want true for 192.168.1.1", c.Observed["is_private"])
	}
}

func TestDNSServersCheckClassifiesPublicResolver(t *testing.T) {
	a := fakeAdapter{netConfig: platform.NetConfig{DNSServers: []string{"8.8.8.8", "192.168.1.1"}}}
	c := NewDNSServersCheck(testDef("local.dns_servers")).Run(context.Background(), checks.CheckContext{Platform: a})
	servers, ok := c.Observed["servers"].([]map[string]any)
	if !ok || len(servers) != 2 {
		t.Fatalf("expected 2 classified servers, got %v", c.Observed["servers"])
	}
}

func TestRoutingCheckReportsDefaultRoute(t *testing.T) {
	a := fakeAdapter{routes: []platform.Route{{Destination: "default", Gateway: "10.0.0.1", Default: true}}}
	c := NewRoutingCheck(testDef("local.routing")).Run(context.Background(), checks.CheckContext{Platform: a})
	if c.Status != model.StatusNormal {
		t.Errorf("Status = %s, want normal", c.Status)
	}
}

func TestMTUCheckFlagsNonStandard(t *testing.T) {
	a := fakeAdapter{netConfig: platform.NetConfig{MTU: 1400}}
	c := NewMTUCheck(testDef("local.mtu")).Run(context.Background(), checks.CheckContext{Platform: a})
	if c.Status != model.StatusAnomalous {
		t.Errorf("Status = %s, want anomalous for non-standard MTU 1400", c.Status)
	}
}

func TestMTUCheckAcceptsStandard(t *testing.T) {
	a := fakeAdapter{netConfig: platform.NetConfig{MTU: 1500}}
	c := NewMTUCheck(testDef("local.mtu")).Run(context.Background(), checks.CheckContext{Platform: a})
	if c.Status != model.StatusNormal {
		t.Errorf("Status = %s, want normal for standard MTU 1500", c.Status)
	}
}

func TestProxySystemCheckReportsEnabled(t *testing.T) {
	a := fakeAdapter{proxy: platform.ProxyConfig{Enabled: true, HTTPProxy: "http://proxy:8080"}}
	c := NewProxySystemCheck(testDef("local.proxy_system")).Run(context.Background(), checks.CheckContext{Platform: a})
	if c.Status != model.StatusAnomalous {
		t.Errorf("Status = %s, want anomalous when a system proxy is configured", c.Status)
	}
}

func TestTrustStoreCheckFindsNonPublicCA(t *testing.T) {
	a := fakeAdapter{cas: []platform.CACert{{Subject: "Acme Corp Proxy CA", Issuer: "Acme Corp Root CA", Fingerprint: "sha256:not-in-bundle"}}}
	c := NewTrustStoreCheck(testDef("local.trust_store")).Run(context.Background(), checks.CheckContext{Platform: a})
	if c.Status != model.StatusAnomalous {
		t.Errorf("Status = %s, want anomalous for a CA not in the bundled public list", c.Status)
	}
	if c.Confidence != model.ConfidenceHigh {
		t.Errorf("Confidence = %s, want high (self_evident per spec §6.1)", c.Confidence)
	}
	if err := model.ValidateCheck(c, true); err != nil {
		t.Errorf("ValidateCheck(selfEvident=true) failed: %v", err)
	}
}

func TestTrustStoreCheckAcceptsEmptyStore(t *testing.T) {
	a := fakeAdapter{cas: nil}
	c := NewTrustStoreCheck(testDef("local.trust_store")).Run(context.Background(), checks.CheckContext{Platform: a})
	if c.Status != model.StatusNormal {
		t.Errorf("Status = %s, want normal for no non-public CAs found", c.Status)
	}
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./internal/checks/local/... -v`
Expected: FAIL — package doesn't exist yet.

- [ ] **Step 4: Write the implementations**

Create `internal/checks/local/interface.go`:

```go
package local

import (
	"context"
	"time"

	"github.com/Maulana-anjari/wifisec/internal/checks"
	"github.com/Maulana-anjari/wifisec/internal/model"
	"github.com/Maulana-anjari/wifisec/internal/registry"
)

type InterfaceCheck struct{ def registry.CheckDefinition }

func NewInterfaceCheck(def registry.CheckDefinition) checks.Checker { return InterfaceCheck{def} }

func (c InterfaceCheck) Definition() registry.CheckDefinition { return c.def }

func (c InterfaceCheck) Run(ctx context.Context, cc checks.CheckContext) model.Check {
	start := time.Now()
	cfg, err := cc.Platform.NetConfig()
	if err != nil {
		return checks.NewErrorCheck(c.def, err, start)
	}
	return model.Check{
		ID:              c.def.ID,
		Layer:           c.def.Layer,
		Title:           c.def.Title,
		ProfileRequired: c.def.ProfileRequired,
		Status:          model.StatusNormal,
		Confidence:      model.ConfidenceHigh,
		Observed: map[string]any{
			"interface": cfg.Interface,
			"ip":        cfg.IP,
			"netmask":   cfg.Netmask,
			"mtu":       cfg.MTU,
		},
		Control:    model.Control{Performed: false},
		DurationMS: time.Since(start).Milliseconds(),
	}
}
```

Create `internal/checks/local/gateway.go`:

```go
package local

import (
	"context"
	"net"
	"time"

	"github.com/Maulana-anjari/wifisec/internal/checks"
	"github.com/Maulana-anjari/wifisec/internal/model"
	"github.com/Maulana-anjari/wifisec/internal/registry"
)

type GatewayCheck struct{ def registry.CheckDefinition }

func NewGatewayCheck(def registry.CheckDefinition) checks.Checker { return GatewayCheck{def} }

func (c GatewayCheck) Definition() registry.CheckDefinition { return c.def }

func (c GatewayCheck) Run(ctx context.Context, cc checks.CheckContext) model.Check {
	start := time.Now()
	cfg, err := cc.Platform.NetConfig()
	if err != nil {
		return checks.NewErrorCheck(c.def, err, start)
	}
	ip := net.ParseIP(cfg.Gateway)
	isPrivate := ip != nil && ip.IsPrivate()
	return model.Check{
		ID:              c.def.ID,
		Layer:           c.def.Layer,
		Title:           c.def.Title,
		ProfileRequired: c.def.ProfileRequired,
		Status:          model.StatusNormal,
		Confidence:      model.ConfidenceHigh,
		Observed: map[string]any{
			"gateway":    cfg.Gateway,
			"is_private": isPrivate,
		},
		Control:    model.Control{Performed: false},
		DurationMS: time.Since(start).Milliseconds(),
	}
}
```

Create `internal/checks/local/dns_servers.go`:

```go
package local

import (
	"context"
	"net"
	"time"

	"github.com/Maulana-anjari/wifisec/internal/checks"
	"github.com/Maulana-anjari/wifisec/internal/model"
	"github.com/Maulana-anjari/wifisec/internal/registry"
)

type DNSServersCheck struct{ def registry.CheckDefinition }

func NewDNSServersCheck(def registry.CheckDefinition) checks.Checker { return DNSServersCheck{def} }

func (c DNSServersCheck) Definition() registry.CheckDefinition { return c.def }

func (c DNSServersCheck) Run(ctx context.Context, cc checks.CheckContext) model.Check {
	start := time.Now()
	cfg, err := cc.Platform.NetConfig()
	if err != nil {
		return checks.NewErrorCheck(c.def, err, start)
	}
	servers := make([]map[string]any, 0, len(cfg.DNSServers))
	anyInternal := false
	for _, s := range cfg.DNSServers {
		ip := net.ParseIP(s)
		internal := ip != nil && ip.IsPrivate()
		anyInternal = anyInternal || internal
		servers = append(servers, map[string]any{"address": s, "is_internal": internal})
	}
	status := model.StatusNormal
	if anyInternal {
		status = model.StatusAnomalous
	}
	confidence := model.ConfidenceMedium
	return model.Check{
		ID:              c.def.ID,
		Layer:           c.def.Layer,
		Title:           c.def.Title,
		ProfileRequired: c.def.ProfileRequired,
		Status:          status,
		Confidence:      confidence,
		Observed:        map[string]any{"servers": servers},
		Control:         model.Control{Performed: false},
		DurationMS:      time.Since(start).Milliseconds(),
	}
}
```

Create `internal/checks/local/routing.go`:

```go
package local

import (
	"context"
	"time"

	"github.com/Maulana-anjari/wifisec/internal/checks"
	"github.com/Maulana-anjari/wifisec/internal/model"
	"github.com/Maulana-anjari/wifisec/internal/registry"
)

type RoutingCheck struct{ def registry.CheckDefinition }

func NewRoutingCheck(def registry.CheckDefinition) checks.Checker { return RoutingCheck{def} }

func (c RoutingCheck) Definition() registry.CheckDefinition { return c.def }

func (c RoutingCheck) Run(ctx context.Context, cc checks.CheckContext) model.Check {
	start := time.Now()
	routes, err := cc.Platform.RoutingTable()
	if err != nil {
		return checks.NewErrorCheck(c.def, err, start)
	}
	hasDefault := false
	for _, r := range routes {
		if r.Default {
			hasDefault = true
			break
		}
	}
	status := model.StatusNormal
	confidence := model.ConfidenceHigh
	if !hasDefault {
		status = model.StatusInconclusive
		confidence = model.ConfidenceLow
	}
	return model.Check{
		ID:              c.def.ID,
		Layer:           c.def.Layer,
		Title:           c.def.Title,
		ProfileRequired: c.def.ProfileRequired,
		Status:          status,
		Confidence:      confidence,
		Observed:        map[string]any{"route_count": len(routes), "has_default_route": hasDefault},
		Control:         model.Control{Performed: false},
		DurationMS:      time.Since(start).Milliseconds(),
	}
}
```

Create `internal/checks/local/mtu.go`:

```go
package local

import (
	"context"
	"time"

	"github.com/Maulana-anjari/wifisec/internal/checks"
	"github.com/Maulana-anjari/wifisec/internal/model"
	"github.com/Maulana-anjari/wifisec/internal/registry"
)

const standardMTU = 1500

type MTUCheck struct{ def registry.CheckDefinition }

func NewMTUCheck(def registry.CheckDefinition) checks.Checker { return MTUCheck{def} }

func (c MTUCheck) Definition() registry.CheckDefinition { return c.def }

func (c MTUCheck) Run(ctx context.Context, cc checks.CheckContext) model.Check {
	start := time.Now()
	cfg, err := cc.Platform.NetConfig()
	if err != nil {
		return checks.NewErrorCheck(c.def, err, start)
	}
	status := model.StatusNormal
	confidence := model.ConfidenceHigh
	if cfg.MTU != 0 && cfg.MTU != standardMTU {
		status = model.StatusAnomalous
		confidence = model.ConfidenceMedium
	}
	return model.Check{
		ID:              c.def.ID,
		Layer:           c.def.Layer,
		Title:           c.def.Title,
		ProfileRequired: c.def.ProfileRequired,
		Status:          status,
		Confidence:      confidence,
		Observed:        map[string]any{"mtu": cfg.MTU, "standard_mtu": standardMTU},
		Control:         model.Control{Performed: false},
		DurationMS:      time.Since(start).Milliseconds(),
	}
}
```

Create `internal/checks/local/proxy_system.go`:

```go
package local

import (
	"context"
	"time"

	"github.com/Maulana-anjari/wifisec/internal/checks"
	"github.com/Maulana-anjari/wifisec/internal/model"
	"github.com/Maulana-anjari/wifisec/internal/registry"
)

type ProxySystemCheck struct{ def registry.CheckDefinition }

func NewProxySystemCheck(def registry.CheckDefinition) checks.Checker { return ProxySystemCheck{def} }

func (c ProxySystemCheck) Definition() registry.CheckDefinition { return c.def }

func (c ProxySystemCheck) Run(ctx context.Context, cc checks.CheckContext) model.Check {
	start := time.Now()
	proxy, err := cc.Platform.ProxyConfig()
	if err != nil {
		return checks.NewErrorCheck(c.def, err, start)
	}
	status := model.StatusNormal
	confidence := model.ConfidenceHigh
	if proxy.Enabled {
		status = model.StatusAnomalous
		confidence = model.ConfidenceMedium
	}
	return model.Check{
		ID:              c.def.ID,
		Layer:           c.def.Layer,
		Title:           c.def.Title,
		ProfileRequired: c.def.ProfileRequired,
		Status:          status,
		Confidence:      confidence,
		Observed: map[string]any{
			"enabled":     proxy.Enabled,
			"http_proxy":  proxy.HTTPProxy,
			"https_proxy": proxy.HTTPSProxy,
			"pac_url":     proxy.PACUrl,
		},
		Control:    model.Control{Performed: false},
		DurationMS: time.Since(start).Milliseconds(),
	}
}
```

Create `internal/checks/local/trust_store.go`:

```go
package local

import (
	"context"
	_ "embed"
	"encoding/pem"
	"time"

	"github.com/Maulana-anjari/wifisec/internal/checks"
	"github.com/Maulana-anjari/wifisec/internal/model"
	"github.com/Maulana-anjari/wifisec/internal/platform"
	"github.com/Maulana-anjari/wifisec/internal/registry"
)

//go:embed publicroots.pem
var publicRootsPEM []byte

// knownPublicSubjects is derived once from the embedded bundle: the
// set of Subject strings this build recognizes as public CAs. Subject
// (not fingerprint) is used for matching because the runtime trust
// store and the embedded bundle may carry the exact same certificate
// re-serialized with different encoding, but the human-readable
// Subject stays stable — an acceptable approximation for classifying
// "public" vs "foreign", not a cryptographic identity check.
var knownPublicSubjects = loadPublicSubjects(publicRootsPEM)

func loadPublicSubjects(data []byte) map[string]bool {
	subjects := make(map[string]bool)
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		cert, err := parseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		subjects[cert] = true
	}
	return subjects
}

type TrustStoreCheck struct{ def registry.CheckDefinition }

func NewTrustStoreCheck(def registry.CheckDefinition) checks.Checker { return TrustStoreCheck{def} }

func (c TrustStoreCheck) Definition() registry.CheckDefinition { return c.def }

func (c TrustStoreCheck) Run(ctx context.Context, cc checks.CheckContext) model.Check {
	start := time.Now()
	cas, err := cc.Platform.TrustStoreCAs()
	if err != nil {
		return checks.NewErrorCheck(c.def, err, start)
	}
	var foreign []platform.CACert
	for _, ca := range cas {
		if !knownPublicSubjects[ca.Subject] {
			foreign = append(foreign, ca)
		}
	}
	if len(foreign) == 0 {
		return model.Check{
			ID:              c.def.ID,
			Layer:           c.def.Layer,
			Title:           c.def.Title,
			ProfileRequired: c.def.ProfileRequired,
			Status:          model.StatusNormal,
			Confidence:      model.ConfidenceHigh,
			Observed:        map[string]any{"non_public_ca_found": false},
			Control:         model.Control{Performed: false},
			DurationMS:      time.Since(start).Milliseconds(),
		}
	}
	// self_evident per spec §6.1: local presence of a foreign CA needs
	// no comparison control to report at high confidence.
	return model.Check{
		ID:              c.def.ID,
		Layer:           c.def.Layer,
		Title:           c.def.Title,
		ProfileRequired: c.def.ProfileRequired,
		Status:          model.StatusAnomalous,
		Confidence:      model.ConfidenceHigh,
		Observed: map[string]any{
			"non_public_ca_found": true,
			"subject":             foreign[0].Subject,
			"issuer":              foreign[0].Issuer,
			"count":               len(foreign),
		},
		Control:    model.Control{Performed: false},
		DurationMS: time.Since(start).Milliseconds(),
	}
}
```

- [ ] **Step 5: Add the missing certificate-parsing helper**

`trust_store.go` above calls `parseCertificate`, a small wrapper kept separate so the embed-loading code stays readable. Create `internal/checks/local/parse.go`:

```go
package local

import "crypto/x509"

// parseCertificate returns just the Subject string of a DER-encoded
// certificate, matching the shape loadPublicSubjects needs.
func parseCertificate(der []byte) (string, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return "", err
	}
	return cert.Subject.String(), nil
}
```

- [ ] **Step 6: Run test to verify it passes**

Run: `go test ./internal/checks/local/... -v`
Expected: PASS (9 tests)

- [ ] **Step 7: Commit**

```bash
git add internal/checks/local/
git commit -m "feat(checks/local): implement all 7 passive local checks (spec §6.1)"
```

---

### Task 6: `internal/checks/wifi` — all 6 passive WiFi checks

**Files:**
- Create: `internal/checks/wifi/security.go`, `internal/checks/wifi/pmf.go`, `internal/checks/wifi/signal.go`, `internal/checks/wifi/channel.go`, `internal/checks/wifi/bssid_vendor.go`, `internal/checks/wifi/link_speed.go`
- Test: `internal/checks/wifi/wifi_test.go`

**Interfaces:**
- Consumes: `checks.Checker`, `checks.CheckContext`, `checks.NewErrorCheck` (Task 4); `platform.WiFiInfo` (Task 1/2); `registry.CheckDefinition` (M1).
- Produces: `NewSecurityCheck(def) checks.Checker`, `NewPMFCheck(def) checks.Checker`, `NewSignalCheck(def) checks.Checker`, `NewChannelCheck(def) checks.Checker`, `NewBSSIDVendorCheck(def) checks.Checker`, `NewLinkSpeedCheck(def) checks.Checker`.

- [ ] **Step 1: Write the failing tests**

Create `internal/checks/wifi/wifi_test.go`:

```go
package wifi

import (
	"context"
	"testing"

	"github.com/Maulana-anjari/wifisec/internal/checks"
	"github.com/Maulana-anjari/wifisec/internal/model"
	"github.com/Maulana-anjari/wifisec/internal/platform"
	"github.com/Maulana-anjari/wifisec/internal/registry"
)

type fakeAdapter struct{ info platform.WiFiInfo }

func (f fakeAdapter) WiFiInfo() (platform.WiFiInfo, error)       { return f.info, nil }
func (f fakeAdapter) NetConfig() (platform.NetConfig, error)     { return platform.NetConfig{}, nil }
func (f fakeAdapter) ProxyConfig() (platform.ProxyConfig, error) { return platform.ProxyConfig{}, nil }
func (f fakeAdapter) TrustStoreCAs() ([]platform.CACert, error)  { return nil, nil }
func (f fakeAdapter) RoutingTable() ([]platform.Route, error)    { return nil, nil }

func testDef(id string) registry.CheckDefinition {
	return registry.CheckDefinition{ID: id, Layer: model.LayerWiFi, Title: id, ProfileRequired: model.ProfilePassive}
}

func TestSecurityCheckFlagsOpenNetwork(t *testing.T) {
	a := fakeAdapter{info: platform.WiFiInfo{Available: true, Security: "open"}}
	c := NewSecurityCheck(testDef("wifi.security")).Run(context.Background(), checks.CheckContext{Platform: a})
	if c.Status != model.StatusAnomalous {
		t.Errorf("Status = %s, want anomalous for open network", c.Status)
	}
}

func TestSecurityCheckAcceptsWPA3(t *testing.T) {
	a := fakeAdapter{info: platform.WiFiInfo{Available: true, Security: "WPA3"}}
	c := NewSecurityCheck(testDef("wifi.security")).Run(context.Background(), checks.CheckContext{Platform: a})
	if c.Status != model.StatusNormal {
		t.Errorf("Status = %s, want normal for WPA3", c.Status)
	}
}

func TestSecurityCheckInconclusiveWhenWiFiUnavailable(t *testing.T) {
	a := fakeAdapter{info: platform.WiFiInfo{Available: false, Reason: "not connected"}}
	c := NewSecurityCheck(testDef("wifi.security")).Run(context.Background(), checks.CheckContext{Platform: a})
	if c.Status != model.StatusInconclusive {
		t.Errorf("Status = %s, want inconclusive when WiFi is unavailable", c.Status)
	}
}

func TestPMFCheckReportsUnknownWhenEmpty(t *testing.T) {
	a := fakeAdapter{info: platform.WiFiInfo{Available: true, PMF: ""}}
	c := NewPMFCheck(testDef("wifi.pmf")).Run(context.Background(), checks.CheckContext{Platform: a})
	if c.Status != model.StatusInconclusive {
		t.Errorf("Status = %s, want inconclusive when PMF is not exposed by the platform", c.Status)
	}
}

func TestSignalCheckReportsRSSI(t *testing.T) {
	a := fakeAdapter{info: platform.WiFiInfo{Available: true, RSSI: -45}}
	c := NewSignalCheck(testDef("wifi.signal")).Run(context.Background(), checks.CheckContext{Platform: a})
	if c.Observed["rssi"] != -45 {
		t.Errorf("Observed[rssi] = %v, want -45", c.Observed["rssi"])
	}
}

func TestChannelCheckReportsBand(t *testing.T) {
	a := fakeAdapter{info: platform.WiFiInfo{Available: true, Channel: 149, Band: "5GHz"}}
	c := NewChannelCheck(testDef("wifi.channel")).Run(context.Background(), checks.CheckContext{Platform: a})
	if c.Observed["band"] != "5GHz" {
		t.Errorf("Observed[band] = %v, want 5GHz", c.Observed["band"])
	}
}

func TestBSSIDVendorCheckExtractsOUI(t *testing.T) {
	a := fakeAdapter{info: platform.WiFiInfo{Available: true, BSSID: "90:9A:4A:23:F9:92"}}
	c := NewBSSIDVendorCheck(testDef("wifi.bssid_vendor")).Run(context.Background(), checks.CheckContext{Platform: a})
	if c.Observed["oui"] != "90:9A:4A" {
		t.Errorf("Observed[oui] = %v, want 90:9A:4A", c.Observed["oui"])
	}
}

func TestLinkSpeedCheckReportsMbps(t *testing.T) {
	a := fakeAdapter{info: platform.WiFiInfo{Available: true, LinkSpeed: 270}}
	c := NewLinkSpeedCheck(testDef("wifi.link_speed")).Run(context.Background(), checks.CheckContext{Platform: a})
	if c.Observed["mbps"] != 270 {
		t.Errorf("Observed[mbps] = %v, want 270", c.Observed["mbps"])
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/checks/wifi/... -v`
Expected: FAIL — package doesn't exist yet.

- [ ] **Step 3: Write the implementations**

Create `internal/checks/wifi/security.go`:

```go
package wifi

import (
	"context"
	"strings"
	"time"

	"github.com/Maulana-anjari/wifisec/internal/checks"
	"github.com/Maulana-anjari/wifisec/internal/model"
	"github.com/Maulana-anjari/wifisec/internal/registry"
)

type SecurityCheck struct{ def registry.CheckDefinition }

func NewSecurityCheck(def registry.CheckDefinition) checks.Checker { return SecurityCheck{def} }

func (c SecurityCheck) Definition() registry.CheckDefinition { return c.def }

func (c SecurityCheck) Run(ctx context.Context, cc checks.CheckContext) model.Check {
	start := time.Now()
	info, err := cc.Platform.WiFiInfo()
	if err != nil {
		return checks.NewErrorCheck(c.def, err, start)
	}
	base := model.Check{
		ID: c.def.ID, Layer: c.def.Layer, Title: c.def.Title, ProfileRequired: c.def.ProfileRequired,
		Control: model.Control{Performed: false}, DurationMS: time.Since(start).Milliseconds(),
	}
	if !info.Available {
		base.Status = model.StatusInconclusive
		base.Confidence = model.ConfidenceLow
		base.Error = info.Reason
		return base
	}
	sec := strings.ToLower(info.Security)
	base.Observed = map[string]any{"security": info.Security}
	switch {
	case sec == "open" || sec == "" || strings.Contains(sec, "wep"):
		base.Status = model.StatusAnomalous
		base.Confidence = model.ConfidenceHigh
	default:
		base.Status = model.StatusNormal
		base.Confidence = model.ConfidenceHigh
	}
	return base
}
```

Create `internal/checks/wifi/pmf.go`:

```go
package wifi

import (
	"context"
	"time"

	"github.com/Maulana-anjari/wifisec/internal/checks"
	"github.com/Maulana-anjari/wifisec/internal/model"
	"github.com/Maulana-anjari/wifisec/internal/registry"
)

type PMFCheck struct{ def registry.CheckDefinition }

func NewPMFCheck(def registry.CheckDefinition) checks.Checker { return PMFCheck{def} }

func (c PMFCheck) Definition() registry.CheckDefinition { return c.def }

func (c PMFCheck) Run(ctx context.Context, cc checks.CheckContext) model.Check {
	start := time.Now()
	info, err := cc.Platform.WiFiInfo()
	if err != nil {
		return checks.NewErrorCheck(c.def, err, start)
	}
	base := model.Check{
		ID: c.def.ID, Layer: c.def.Layer, Title: c.def.Title, ProfileRequired: c.def.ProfileRequired,
		Control: model.Control{Performed: false}, DurationMS: time.Since(start).Milliseconds(),
	}
	if !info.Available {
		base.Status = model.StatusInconclusive
		base.Confidence = model.ConfidenceLow
		base.Error = info.Reason
		return base
	}
	base.Observed = map[string]any{"pmf": info.PMF}
	if info.PMF == "" {
		// Not exposed by this platform's data source (spec §4.7 notes
		// this is a real gap, not a defect) — report honestly rather
		// than guessing "disabled".
		base.Status = model.StatusInconclusive
		base.Confidence = model.ConfidenceLow
		return base
	}
	if info.PMF == "disabled" {
		base.Status = model.StatusAnomalous
		base.Confidence = model.ConfidenceMedium
	} else {
		base.Status = model.StatusNormal
		base.Confidence = model.ConfidenceHigh
	}
	return base
}
```

Create `internal/checks/wifi/signal.go`:

```go
package wifi

import (
	"context"
	"time"

	"github.com/Maulana-anjari/wifisec/internal/checks"
	"github.com/Maulana-anjari/wifisec/internal/model"
	"github.com/Maulana-anjari/wifisec/internal/registry"
)

type SignalCheck struct{ def registry.CheckDefinition }

func NewSignalCheck(def registry.CheckDefinition) checks.Checker { return SignalCheck{def} }

func (c SignalCheck) Definition() registry.CheckDefinition { return c.def }

func (c SignalCheck) Run(ctx context.Context, cc checks.CheckContext) model.Check {
	start := time.Now()
	info, err := cc.Platform.WiFiInfo()
	if err != nil {
		return checks.NewErrorCheck(c.def, err, start)
	}
	base := model.Check{
		ID: c.def.ID, Layer: c.def.Layer, Title: c.def.Title, ProfileRequired: c.def.ProfileRequired,
		Control: model.Control{Performed: false}, DurationMS: time.Since(start).Milliseconds(),
	}
	if !info.Available {
		base.Status = model.StatusInconclusive
		base.Confidence = model.ConfidenceLow
		base.Error = info.Reason
		return base
	}
	quality := "good"
	if info.RSSI < -80 {
		quality = "poor"
	} else if info.RSSI < -67 {
		quality = "fair"
	}
	base.Observed = map[string]any{"rssi": info.RSSI, "quality": quality}
	base.Status = model.StatusNormal
	base.Confidence = model.ConfidenceMedium // RSSI is an approximation, see platform/linux.go
	return base
}
```

Create `internal/checks/wifi/channel.go`:

```go
package wifi

import (
	"context"
	"time"

	"github.com/Maulana-anjari/wifisec/internal/checks"
	"github.com/Maulana-anjari/wifisec/internal/model"
	"github.com/Maulana-anjari/wifisec/internal/registry"
)

type ChannelCheck struct{ def registry.CheckDefinition }

func NewChannelCheck(def registry.CheckDefinition) checks.Checker { return ChannelCheck{def} }

func (c ChannelCheck) Definition() registry.CheckDefinition { return c.def }

func (c ChannelCheck) Run(ctx context.Context, cc checks.CheckContext) model.Check {
	start := time.Now()
	info, err := cc.Platform.WiFiInfo()
	if err != nil {
		return checks.NewErrorCheck(c.def, err, start)
	}
	base := model.Check{
		ID: c.def.ID, Layer: c.def.Layer, Title: c.def.Title, ProfileRequired: c.def.ProfileRequired,
		Control: model.Control{Performed: false}, DurationMS: time.Since(start).Milliseconds(),
	}
	if !info.Available {
		base.Status = model.StatusInconclusive
		base.Confidence = model.ConfidenceLow
		base.Error = info.Reason
		return base
	}
	base.Observed = map[string]any{"channel": info.Channel, "band": info.Band}
	base.Status = model.StatusNormal
	base.Confidence = model.ConfidenceHigh
	return base
}
```

Create `internal/checks/wifi/bssid_vendor.go`:

```go
package wifi

import (
	"context"
	"strings"
	"time"

	"github.com/Maulana-anjari/wifisec/internal/checks"
	"github.com/Maulana-anjari/wifisec/internal/model"
	"github.com/Maulana-anjari/wifisec/internal/registry"
)

type BSSIDVendorCheck struct{ def registry.CheckDefinition }

func NewBSSIDVendorCheck(def registry.CheckDefinition) checks.Checker { return BSSIDVendorCheck{def} }

func (c BSSIDVendorCheck) Definition() registry.CheckDefinition { return c.def }

func (c BSSIDVendorCheck) Run(ctx context.Context, cc checks.CheckContext) model.Check {
	start := time.Now()
	info, err := cc.Platform.WiFiInfo()
	if err != nil {
		return checks.NewErrorCheck(c.def, err, start)
	}
	base := model.Check{
		ID: c.def.ID, Layer: c.def.Layer, Title: c.def.Title, ProfileRequired: c.def.ProfileRequired,
		Control: model.Control{Performed: false}, DurationMS: time.Since(start).Milliseconds(),
	}
	if !info.Available {
		base.Status = model.StatusInconclusive
		base.Confidence = model.ConfidenceLow
		base.Error = info.Reason
		return base
	}
	oui := ouiFromBSSID(info.BSSID)
	// No bundled OUI-to-vendor-name database in this milestone (YAGNI —
	// would need a real IEEE OUI dataset to be trustworthy); reporting
	// the OUI itself is still useful and honest.
	base.Observed = map[string]any{"oui": oui}
	base.Status = model.StatusNormal
	base.Confidence = model.ConfidenceHigh
	return base
}

func ouiFromBSSID(bssid string) string {
	parts := strings.Split(bssid, ":")
	if len(parts) < 3 {
		return ""
	}
	return strings.Join(parts[:3], ":")
}
```

Create `internal/checks/wifi/link_speed.go`:

```go
package wifi

import (
	"context"
	"time"

	"github.com/Maulana-anjari/wifisec/internal/checks"
	"github.com/Maulana-anjari/wifisec/internal/model"
	"github.com/Maulana-anjari/wifisec/internal/registry"
)

type LinkSpeedCheck struct{ def registry.CheckDefinition }

func NewLinkSpeedCheck(def registry.CheckDefinition) checks.Checker { return LinkSpeedCheck{def} }

func (c LinkSpeedCheck) Definition() registry.CheckDefinition { return c.def }

func (c LinkSpeedCheck) Run(ctx context.Context, cc checks.CheckContext) model.Check {
	start := time.Now()
	info, err := cc.Platform.WiFiInfo()
	if err != nil {
		return checks.NewErrorCheck(c.def, err, start)
	}
	base := model.Check{
		ID: c.def.ID, Layer: c.def.Layer, Title: c.def.Title, ProfileRequired: c.def.ProfileRequired,
		Control: model.Control{Performed: false}, DurationMS: time.Since(start).Milliseconds(),
	}
	if !info.Available {
		base.Status = model.StatusInconclusive
		base.Confidence = model.ConfidenceLow
		base.Error = info.Reason
		return base
	}
	base.Observed = map[string]any{"mbps": info.LinkSpeed}
	base.Status = model.StatusNormal
	base.Confidence = model.ConfidenceHigh
	return base
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/checks/wifi/... -v`
Expected: PASS (8 tests)

- [ ] **Step 5: Commit**

```bash
git add internal/checks/wifi/
git commit -m "feat(checks/wifi): implement all 6 passive wifi checks (spec §6.1)"
```

---

### Task 7: `internal/interpret` — rules evaluator + §7.3 scoring, scoped to §6.1

**Files:**
- Create: `internal/interpret/rules.go`
- Create: `internal/interpret/rules.yaml`
- Test: `internal/interpret/rules_test.go`

**Interfaces:**
- Consumes: `model.Check`, `model.Finding`, `model.Verdict` (M1).
- Produces: `func Apply(checks []model.Check) (findings []model.Finding, verdict model.Verdict)`.

- [ ] **Step 1: Write the failing tests**

Create `internal/interpret/rules_test.go`:

```go
package interpret

import (
	"testing"

	"github.com/Maulana-anjari/wifisec/internal/model"
)

func TestApplyProducesWeakEncryptionFinding(t *testing.T) {
	checks := []model.Check{
		{ID: "wifi.security", Status: model.StatusAnomalous, Confidence: model.ConfidenceHigh, Observed: map[string]any{"security": "open"}},
	}
	findings, verdict := Apply(checks)
	if len(findings) != 1 || findings[0].ID != "weak_encryption" {
		t.Fatalf("expected weak_encryption finding, got %+v", findings)
	}
	if findings[0].Severity != model.SeverityCritical {
		t.Errorf("severity = %s, want critical", findings[0].Severity)
	}
	if verdict.Safety != model.SafetyAvoid {
		t.Errorf("safety = %s, want avoid", verdict.Safety)
	}
	if verdict.Score != 60 {
		t.Errorf("score = %d, want 60 (100 - 40 for one critical)", verdict.Score)
	}
}

func TestApplyCleanChecksProduceOKVerdict(t *testing.T) {
	checks := []model.Check{
		{ID: "wifi.security", Status: model.StatusNormal, Confidence: model.ConfidenceHigh, Observed: map[string]any{"security": "WPA3"}},
		{ID: "wifi.pmf", Status: model.StatusNormal, Confidence: model.ConfidenceHigh, Observed: map[string]any{"pmf": "required"}},
	}
	findings, verdict := Apply(checks)
	if len(findings) != 0 {
		t.Errorf("expected no findings, got %+v", findings)
	}
	if verdict.Safety != model.SafetyOK || verdict.Score != 100 {
		t.Errorf("verdict = %+v, want ok/100", verdict)
	}
}

func TestApplyFillsBlindSpotsForSkippedChecks(t *testing.T) {
	checks := []model.Check{
		{ID: "dns.resolve_basic", Status: model.StatusSkipped, Title: "Resolusi DNS dasar", Control: model.Control{Reason: "profile_does_not_allow"}},
	}
	_, verdict := Apply(checks)
	if err := model.ValidateVerdict(checks, verdict); err != nil {
		t.Errorf("ValidateVerdict failed on Apply's own output: %v", err)
	}
	if len(verdict.BlindSpots) == 0 {
		t.Error("expected non-empty blind_spots for a skipped check")
	}
}

func TestApplyFindingsPassValidation(t *testing.T) {
	checks := []model.Check{
		{ID: "local.trust_store", Status: model.StatusAnomalous, Confidence: model.ConfidenceHigh, Observed: map[string]any{"non_public_ca_found": true}},
	}
	findings, _ := Apply(checks)
	ids := map[string]bool{}
	for _, c := range checks {
		ids[c.ID] = true
	}
	for _, f := range findings {
		if err := model.ValidateFinding(f, ids); err != nil {
			t.Errorf("ValidateFinding(%s) failed: %v", f.ID, err)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/interpret/... -v`
Expected: FAIL — package doesn't exist yet.

- [ ] **Step 3: Write `rules.yaml`**

Create `internal/interpret/rules.yaml` (scoped to what §6.1 checks can actually trigger; matches spec §7.2's rule IDs):

```yaml
rules:
  - id: weak_encryption
    severity: critical
    when:
      check: wifi.security
      status: anomalous
    title: "Jaringan WiFi ini tidak terenkripsi dengan aman"
    explanation: |
      Enkripsi WiFi yang terdeteksi lemah atau tidak ada (open/WEP).
      Trafik lapisan link dapat disadap siapa pun dalam jangkauan sinyal.
    impact: [password, email, chat]
    recommendation: "Gunakan VPN atau hindari trafik sensitif di jaringan ini."

  - id: no_pmf
    severity: warning
    when:
      check: wifi.pmf
      status: anomalous
    title: "Protected Management Frames tidak aktif"
    explanation: |
      Frame manajemen WiFi tidak dilindungi, membuka peluang deauth palsu.
    recommendation: "Waspadai koneksi terputus mendadak; itu bisa jadi serangan deauth."

  - id: foreign_ca_present
    severity: warning
    when:
      check: local.trust_store
      status: anomalous
    title: "CA non-publik ditemukan di trust store perangkat"
    explanation: |
      Ditemukan certificate authority yang tidak dikenal publik terpasang
      di perangkat ini. Ini umum dan sah pada perangkat MDM perusahaan,
      tapi juga bisa berarti software MITM lokal.
    recommendation: "Jika ini bukan perangkat kerja dengan MDM, selidiki asal CA tersebut."
    false_positive_hints:
      - "Umum dan sah pada perangkat milik perusahaan dengan MDM."

  - id: dns_internal_resolver
    severity: warning
    when:
      check: local.dns_servers
      status: anomalous
    title: "DNS diarahkan ke resolver internal jaringan"
    explanation: |
      Server DNS yang diberikan jaringan ini adalah alamat privat,
      bukan resolver publik dikenal. Operator jaringan dapat mengamati
      atau memanipulasi resolusi nama domain.
    recommendation: "Pertimbangkan menggunakan DNS-over-HTTPS jika mendukung."
```

- [ ] **Step 4: Write the evaluator + scorer**

Create `internal/interpret/rules.go`:

```go
// Package interpret turns Check results into Findings and a Verdict
// (spec §7). This milestone's rules.yaml covers only findings reachable
// from spec §6.1 (passive) checks; later milestones extend it as more
// checks land.
package interpret

import (
	_ "embed"

	"gopkg.in/yaml.v3"

	"github.com/Maulana-anjari/wifisec/internal/model"
)

//go:embed rules.yaml
var rulesYAML []byte

type rule struct {
	ID                 string   `yaml:"id"`
	Severity           string   `yaml:"severity"`
	When               ruleWhen `yaml:"when"`
	Title              string   `yaml:"title"`
	Explanation        string   `yaml:"explanation"`
	Impact             []string `yaml:"impact"`
	Recommendation     string   `yaml:"recommendation"`
	FalsePositiveHints []string `yaml:"false_positive_hints"`
}

// ruleWhen supports only the single-condition case this milestone's
// rules.yaml needs (spec §7.1 also defines all/any/not; not needed
// until a rule requires combining multiple checks).
type ruleWhen struct {
	Check  string `yaml:"check"`
	Status string `yaml:"status"`
}

var rules = loadRules(rulesYAML)

func loadRules(data []byte) []rule {
	var f struct {
		Rules []rule `yaml:"rules"`
	}
	if err := yaml.Unmarshal(data, &f); err != nil {
		panic("interpret: invalid rules.yaml: " + err.Error()) // embedded, compile-time data — a parse failure is a build defect
	}
	return f.Rules
}

// Apply evaluates every rule against checks and computes the resulting
// Verdict per spec §7.3.
func Apply(checks []model.Check) ([]model.Finding, model.Verdict) {
	byID := make(map[string]model.Check, len(checks))
	for _, c := range checks {
		byID[c.ID] = c
	}

	var findings []model.Finding
	for _, r := range rules {
		c, ok := byID[r.When.Check]
		if !ok || string(c.Status) != r.When.Status {
			continue
		}
		findings = append(findings, model.Finding{
			ID:                 r.ID,
			Severity:           model.Severity(r.Severity),
			Confidence:         c.Confidence,
			Title:              r.Title,
			Explanation:        r.Explanation,
			Impact:             r.Impact,
			BasedOn:            []string{c.ID},
			Recommendation:     r.Recommendation,
			FalsePositiveHints: r.FalsePositiveHints,
		})
	}

	return findings, buildVerdict(checks, findings)
}

func buildVerdict(checks []model.Check, findings []model.Finding) model.Verdict {
	score := 100
	hasCritical := false
	warningPenalty, infoPenalty := 0, 0
	topFindings := make([]string, 0, len(findings))
	for _, f := range findings {
		topFindings = append(topFindings, f.ID)
		switch f.Severity {
		case model.SeverityCritical:
			hasCritical = true
		case model.SeverityWarning:
			warningPenalty += 15
		case model.SeverityInfo:
			infoPenalty += 5
		}
	}
	if hasCritical {
		score -= 40
	}
	if warningPenalty > 45 {
		warningPenalty = 45
	}
	if infoPenalty > 15 {
		infoPenalty = 15
	}
	score -= warningPenalty + infoPenalty

	allFailed := len(checks) > 0
	for _, c := range checks {
		if c.Status != model.StatusError && c.Status != model.StatusSkipped {
			allFailed = false
			break
		}
	}
	var safety model.Safety
	switch {
	case allFailed:
		safety = model.SafetyUnknown
	case hasCritical:
		safety = model.SafetyAvoid
	case score >= 80:
		safety = model.SafetyOK
	case score >= 50:
		safety = model.SafetyCaution
	default:
		safety = model.SafetyAvoid
	}

	return model.Verdict{
		Safety:      safety,
		Score:       score,
		Headline:    headlineFor(safety),
		TopFindings: topFindings,
		BlindSpots:  blindSpotsFor(checks),
		UseCases:    useCasesFor(safety),
	}
}

func blindSpotsFor(checks []model.Check) []string {
	var spots []string
	for _, c := range checks {
		if c.Status == model.StatusSkipped {
			spots = append(spots, c.Title+" tidak diperiksa - profil aktif tidak mengizinkan.")
		}
	}
	return spots
}

func headlineFor(safety model.Safety) string {
	switch safety {
	case model.SafetyOK:
		return "Jaringan ini tampak aman untuk penggunaan umum."
	case model.SafetyCaution:
		return "Jaringan ini memiliki beberapa hal yang perlu diwaspadai."
	case model.SafetyAvoid:
		return "Jaringan ini memiliki risiko signifikan; hindari trafik sensitif."
	default:
		return "Belum cukup data untuk menyimpulkan keamanan jaringan ini."
	}
}

func useCasesFor(safety model.Safety) map[string]string {
	value := "caution"
	switch safety {
	case model.SafetyOK:
		value = "ok"
	case model.SafetyAvoid:
		value = "avoid"
	}
	return map[string]string{
		"browsing_umum":      value,
		"login_akun_pribadi": value,
		"kerja_sensitif":     value,
		"internet_banking":   value,
	}
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `go test ./internal/interpret/... -v`
Expected: PASS (4 tests)

- [ ] **Step 6: Commit**

```bash
git add internal/interpret/
git commit -m "feat(interpret): add rules evaluator and §7.3 verdict scoring (§6.1-scoped rules)"
```

---

### Task 8: Wire real checks into `cmd/wifisec`

**Files:**
- Modify: `cmd/wifisec/main.go`

**Interfaces:**
- Consumes: everything from Tasks 1-7 plus `internal/registry` (M1), `internal/tui` (M1).

- [ ] **Step 1: Rewrite `main.go` to support both the existing fixture-file mode and a new no-argument real-run mode**

Read the current file first (`cat cmd/wifisec/main.go`), then replace it entirely with:

```go
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
```

- [ ] **Step 2: Verify it builds and runs for real**

Run:
```bash
go build ./...
go run ./cmd/wifisec
```
Expected: build succeeds; the TUI launches showing a REAL verdict computed from this machine's actual network state (real SSID in wifi checks, real gateway/DNS in local checks, real trust-store scan). Manually confirm no `unimplemented` warnings print to stderr (all 13 defs should resolve). Also re-run the M1 manual path to confirm it still works: `go run ./cmd/wifisec testdata/fixtures/clean_home.json`.

- [ ] **Step 3: Commit**

```bash
git add cmd/wifisec/main.go
git commit -m "feat(cmd): wire real passive-profile checks into a no-arg run mode"
```

---

### Task 9: T1 (zero packets) + final verification

**Files:**
- Create: `internal/checks/t1_test.go`

**Interfaces:**
- Consumes: everything from Tasks 1-7.

- [ ] **Step 1: Write T1**

Create `internal/checks/t1_test.go`:

```go
package checks_test

import (
	"context"
	"testing"
	"time"

	"github.com/Maulana-anjari/wifisec/internal/checks"
	"github.com/Maulana-anjari/wifisec/internal/checks/local"
	"github.com/Maulana-anjari/wifisec/internal/checks/wifi"
	"github.com/Maulana-anjari/wifisec/internal/guard"
	"github.com/Maulana-anjari/wifisec/internal/model"
	"github.com/Maulana-anjari/wifisec/internal/platform"
	"github.com/Maulana-anjari/wifisec/internal/registry"
)

// TestT1PassiveProfileSendsZeroPackets is spec's own most important
// test (§8.1: "Ini test terpenting di seluruh proyek"): every §6.1
// check, run for real against this machine, must send exactly zero
// packets.
func TestT1PassiveProfileSendsZeroPackets(t *testing.T) {
	reg, err := registry.Load()
	if err != nil {
		t.Fatalf("registry.Load: %v", err)
	}
	defs := reg.Filter(model.ProfilePassive)
	if len(defs) == 0 {
		t.Fatal("no passive-profile checks found in registry")
	}

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

	var checkers []checks.Checker
	for _, def := range defs {
		ctor, ok := factory[def.ID]
		if !ok {
			t.Fatalf("no implementation registered for passive check %q — T1 must exercise every §6.1 check", def.ID)
		}
		checkers = append(checkers, ctor(def))
	}

	counter := guard.NewPacketCounter(model.ProfilePassive.EstimatedPackets()) // 0
	cc := checks.CheckContext{Platform: platform.New(), Counter: counter, Timeout: 10 * time.Second}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var results []model.Check
	for c := range checks.Run(ctx, checkers, cc) {
		results = append(results, c)
		if c.Status == model.StatusError {
			t.Logf("check %s errored (informational, not a T1 failure by itself): %s", c.ID, c.Error)
		}
	}

	if got := counter.Total(); got != 0 {
		t.Errorf("counter.Total() = %d, want 0 (passive profile must send zero packets)", got)
	}
	for _, c := range results {
		if c.PacketsSent != 0 {
			t.Errorf("check %s reported PacketsSent = %d, want 0", c.ID, c.PacketsSent)
		}
	}
}
```

- [ ] **Step 2: Run T1 to verify it passes**

Run: `go test ./internal/checks/... -run TestT1 -v`
Expected: PASS

- [ ] **Step 3: Attempt the network-namespace variant; skip gracefully if unavailable**

Run (checks whether this environment can create an unprivileged network namespace with no default route):
```bash
if unshare --net --map-root-user true 2>/dev/null; then
  echo "netns available"
  unshare --net --map-root-user go test ./internal/checks/... -run TestT1 -v
else
  echo "netns not available in this sandbox (needs CAP_NET_ADMIN / unprivileged userns) — this is expected in many CI/dev containers; do not force it"
fi
```
Expected: either the netns variant passes too (proving zero packets even with no default route reachable), or it's reported as unavailable in this environment. Either outcome is acceptable — do not add privilege-escalation workarounds to force it; note the actual result in your report.

- [ ] **Step 4: Full milestone verification**

Run:
```bash
go build ./...
go vet ./...
go test ./... -v
```
Expected: all pass, no warnings. Confirm against spec §11 M2 exit criteria:
- [ ] T1 passes (in-process; netns variant attempted, result reported honestly)
- [ ] `wifisec` (no args) produces a real, non-fixture verdict on this machine's actual network
- [ ] All 13 §6.1 checks have a working `Checker` implementation (no `unimplemented` warnings from `buildCheckers`)

- [ ] **Step 5: Commit**

```bash
git add internal/checks/t1_test.go
git commit -m "test(checks): add T1 — passive profile sends zero packets"
```
