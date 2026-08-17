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
