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
