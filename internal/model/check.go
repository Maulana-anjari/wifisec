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
