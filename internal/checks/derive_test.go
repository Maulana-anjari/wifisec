package checks

import (
	"testing"

	"github.com/Maulana-anjari/wifisec/internal/model"
	"github.com/Maulana-anjari/wifisec/internal/registry"
)

func TestDeriveLatencyChecksNormalOnStableSamples(t *testing.T) {
	latency := model.Check{
		ID: "net.latency_internet", Status: model.StatusNormal,
		Observed: map[string]any{"rtt_samples_ms": []float64{20, 21, 19, 20, 22}, "sent": 5, "lost": 0},
	}
	jitterDef := registry.CheckDefinition{ID: "net.jitter", Layer: model.LayerPerf, Title: "Jitter"}
	lossDef := registry.CheckDefinition{ID: "net.packet_loss", Layer: model.LayerPerf, Title: "Packet loss"}

	jitter, loss := DeriveLatencyChecks(latency, jitterDef, lossDef)

	if jitter.Status != model.StatusNormal {
		t.Errorf("jitter.Status = %v, want normal for stable samples", jitter.Status)
	}
	if jitter.PacketsSent != 0 {
		t.Errorf("jitter.PacketsSent = %d, want 0 (derived, no new packets)", jitter.PacketsSent)
	}
	if loss.Status != model.StatusNormal {
		t.Errorf("loss.Status = %v, want normal for 0 lost", loss.Status)
	}
	if loss.PacketsSent != 0 {
		t.Errorf("loss.PacketsSent = %d, want 0", loss.PacketsSent)
	}
}

func TestDeriveLatencyChecksAnomalousOnHighJitterAndLoss(t *testing.T) {
	latency := model.Check{
		ID: "net.latency_internet", Status: model.StatusNormal,
		Observed: map[string]any{"rtt_samples_ms": []float64{10, 90, 15, 120, 20}, "sent": 10, "lost": 3},
	}
	jitterDef := registry.CheckDefinition{ID: "net.jitter", Layer: model.LayerPerf, Title: "Jitter"}
	lossDef := registry.CheckDefinition{ID: "net.packet_loss", Layer: model.LayerPerf, Title: "Packet loss"}

	jitter, loss := DeriveLatencyChecks(latency, jitterDef, lossDef)

	if jitter.Status != model.StatusAnomalous {
		t.Errorf("jitter.Status = %v, want anomalous for high-variance samples", jitter.Status)
	}
	if loss.Status != model.StatusAnomalous {
		t.Errorf("loss.Status = %v, want anomalous for 30%% loss", loss.Status)
	}
}

func TestDeriveLatencyChecksInconclusiveWhenLatencyInconclusive(t *testing.T) {
	latency := model.Check{ID: "net.latency_internet", Status: model.StatusInconclusive, Observed: nil}
	jitterDef := registry.CheckDefinition{ID: "net.jitter"}
	lossDef := registry.CheckDefinition{ID: "net.packet_loss"}

	jitter, loss := DeriveLatencyChecks(latency, jitterDef, lossDef)
	if jitter.Status != model.StatusInconclusive || loss.Status != model.StatusInconclusive {
		t.Errorf("want both inconclusive when source is inconclusive, got jitter=%v loss=%v", jitter.Status, loss.Status)
	}
}
