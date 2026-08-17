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
