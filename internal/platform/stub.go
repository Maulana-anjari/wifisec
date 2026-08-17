//go:build !linux

package platform

// stubAdapter backs platforms with no real adapter yet (spec §4.7:
// "Jika utilitas tidak tersedia... kembalikan WiFiInfo{Available:
// false, ...} — jangan kembalikan error yang menggagalkan seluruh
// run"). This currently covers darwin (a later milestone adds a real
// darwin.go, which will need to shrink this tag back to
// "!linux && !darwin" so it doesn't shadow the new file) and any other
// unsupported GOOS.
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
