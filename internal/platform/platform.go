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
