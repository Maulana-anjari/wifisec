package dns

import (
	stdcontext "context"
	"encoding/json"
	stdnet "net"
	stdhttp "net/http"
	"time"
)

const dohEndpoint = "https://cloudflare-dns.com/dns-query"

type dohResponse struct {
	Answer []struct {
		Type int    `json:"type"`
		Data string `json:"data"`
	} `json:"Answer"`
}

// queryDoH resolves domain's A records via Cloudflare's DNS-over-HTTPS
// JSON API (spec §6.3 "dns.compare_doh" needs an out-of-band control
// independent of the local network's own resolver).
func queryDoH(ctx stdcontext.Context, domain string) ([]string, error) {
	req, err := stdhttp.NewRequestWithContext(ctx, stdhttp.MethodGet, dohEndpoint+"?name="+domain+"&type=A", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-json")
	client := stdhttp.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var parsed dohResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, err
	}
	var addrs []string
	for _, a := range parsed.Answer {
		if a.Type == 1 && stdnet.ParseIP(a.Data) != nil { // type 1 = A
			addrs = append(addrs, a.Data)
		}
	}
	return addrs, nil
}
