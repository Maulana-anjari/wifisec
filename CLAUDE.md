# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## State of this repository

This is a **pre-implementation** repository. The only file that exists is `SPEC-wifisec.md` — a binding implementation spec (written in Indonesian) for an AI coding agent to execute. There is no `go.mod`, no source code, and no git repository yet. Before writing any code, read `SPEC-wifisec.md` in full; it is the source of truth and takes precedence over anything below, which is only a summary.

## What this project is

`wifisec` is a Go 1.22+ CLI/TUI (bubbletea + lipgloss) that answers one question: *is this WiFi network safe to use?* It targets Linux and macOS for v1.0. The user is assumed to be a **guest** on the network being inspected, so the tool defaults to sending zero packets, and every increase in intrusiveness requires explicit confirmation.

## Absolute prohibitions (spec §0.1)

These must never be implemented in any form — not as internal utilities, commented-out code, or branch experiments. Treat any request that seems to require one of these as a misunderstanding of the actual requirement — stop and ask rather than implementing it:

- Any mechanism to bypass, evade, or disguise itself from network blocks
- Discovery/enumeration of other devices on the network (ARP scan, mDNS/NetBIOS sweep, ping sweep)
- Security testing against devices or services belonging to others
- Sending packets with spoofed headers
- Storing or transmitting network credentials

## Binding design principles (spec §2)

- **P1 — Secure by default.** The `passive` profile is the default on every process start; previous session state is never read.
- **P2 — Observation is separate from judgment.** `Check` must never contain assessment fields like "blocked" or "dangerous" — judgment lives only in `Finding`/`Verdict`.
- **P3 — `inconclusive` is a first-class status.** A failure without a control comparison must produce `StatusInconclusive`, never a negative conclusion.
- **P4 — Blind spots must be reported.** A `Verdict` that doesn't list what wasn't checked is a bug.
- **P5 — Every behavioral claim needs a test.** E.g., "passive profile sends no packets" is verified by test T1.

## Architecture (spec §3)

```
cmd/wifisec/            entrypoint, flag parsing
internal/
  model/                 data types only — must not import other internal packages
  registry/               declarative check definitions (registry.go + checks.yaml)
  checks/                 check implementations
    runner.go              orchestration, concurrency, streaming
    local/ dns/ tls/ net/  zero-packet checks vs. packet-sending checks, by layer
  platform/               OS adapters: platform.go (interface), linux.go, darwin.go, stub.go (build-tag separated)
  interpret/              checks → findings → verdict (rules.go + rules.yaml)
  guard/                  profile enforcement: profile.go, counter.go (global packet counter)
  tui/                    bubbletea UI — must only import model
  output/                 json.go, report.go
testdata/fixtures/       JSON fixtures for renderer tests
```

**Dependency rule (enforced, architectural bug if violated):** `model` imports no other internal package. `tui` only imports `model`. `checks` never imports `tui`.

**Execution flow:** `main` → parse flags, determine profile (default `passive`) → `guard.Enforce` (may reject/downgrade) → `registry.Filter(profile)` (out-of-profile checks are skipped) → `runner.Run` (parallel, streams to a channel) → TUI renders incrementally → `interpret.Apply` produces findings + verdict.

## Allowed dependencies (spec §3.3)

Only these, plus stdlib (`crypto/tls`, `net`, `net/http`, `context`, `encoding/json`, etc.):

| Package | Purpose |
|---|---|
| `github.com/charmbracelet/bubbletea` | TUI |
| `github.com/charmbracelet/lipgloss` | TUI styling |
| `github.com/miekg/dns` | precise DNS query control |
| `gopkg.in/yaml.v3` | registry and rules |
| `github.com/spf13/pflag` | flag parsing |

Do not add third-party ICMP libraries, DI frameworks, structured logging libraries, or any ORM without explicit approval (spec §0 rule 5).

## The profile/guard system is the most critical component

Build it before any active check exists (spec §5). Four profiles (`passive` → `minimal` → `standard` → `full`) gate what checks may run and how many packets may be sent. Key rules: raising above `passive` requires typing the exact profile name to confirm; a BSSID change mid-run force-downgrades to `passive` and cancels running checks; `--profile` above `standard` requires `--i-own-this-network`; the known-networks whitelist lives at `$XDG_CONFIG_HOME/wifisec/known_networks.yaml`. Never implement a way to persist/restore the last-used profile across sessions, or a flag that bypasses confirmation for `full` besides `--i-own-this-network`.

## Testing strategy (spec §8)

Tests are written **before** implementation and are the part humans review. Nine mandatory tests are specified (T1–T9) in `SPEC-wifisec.md` §8.1 — most critical is **T1**: running every `passive`-profile check must result in `counter.Total() == 0` packets sent, including inside a Linux network namespace with no default route. Six JSON fixtures are required under `testdata/fixtures/` (§8.2) and double as the visual spec for the renderer.

## Milestone order (spec §11)

Guard rails are built before active capabilities — do not skip ahead:

1. **M1 — Foundation:** types, registry loader, fixtures, full TUI renderer from fixtures. No network code at all.
2. **M2 — Passive profile:** platform adapters (Linux/macOS), all §6.1 checks, packet counter.
3. **M3 — Profile system:** rules G1–G7, confirmation dialog, whitelist, exit codes.
4. **M4 — Active checks:** `minimal` then `standard`, then `full`.
5. **M5 — Release:** docs, README with explicit limitations section, 3-OS CI matrix, release artifacts.

## Open questions that must be asked, not guessed (spec §13)

Before starting M2, the following must be confirmed with the user rather than assumed: the control domain(s) used for `dns.resolve_basic`/`tls.cert_issuer`; whether the public CA list is bundled in the binary or read from the system; actual BSSID-retrieval behavior on the target macOS version; and whether `wifi.channel_congestion` (full profile) requires monitor mode and, if so, whether that stays in scope.

## Code style (spec §0 rule 3)

Explicit and boring. Short functions, no speculative abstraction, errors handled at the call site. Avoid generics unless they meaningfully reduce duplication. Avoid reflection entirely.
