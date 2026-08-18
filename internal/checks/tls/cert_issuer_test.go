package tls

import (
	"context"
	"testing"
	"time"

	"github.com/Maulana-anjari/wifisec/internal/checks"
	"github.com/Maulana-anjari/wifisec/internal/guard"
	"github.com/Maulana-anjari/wifisec/internal/model"
	"github.com/Maulana-anjari/wifisec/internal/platform"
	"github.com/Maulana-anjari/wifisec/internal/registry"
)

type fakeAdapter struct {
	platform.Adapter
	cas []platform.CACert
}

func (f fakeAdapter) TrustStoreCAs() ([]platform.CACert, error) { return f.cas, nil }

func TestCertIssuerNormalWhenFingerprintMatchesBaseline(t *testing.T) {
	def := registry.CheckDefinition{ID: "tls.cert_issuer", EstimatedPackets: 1}
	c := NewCertIssuerCheck(def)
	cc := checks.CheckContext{Platform: fakeAdapter{}, Counter: guard.NewPacketCounter(100), Timeout: 5 * time.Second}
	got := c.Run(context.Background(), cc)
	if got.Status != model.StatusNormal {
		t.Errorf("Status = %v, want normal (example.com's live cert must match the bundled baseline as of the plan's capture date): %#v", got.Status, got.Observed)
	}
	if got.PacketsSent != 1 {
		t.Errorf("PacketsSent = %d, want 1", got.PacketsSent)
	}
}
