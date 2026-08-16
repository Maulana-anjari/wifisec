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
