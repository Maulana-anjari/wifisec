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
