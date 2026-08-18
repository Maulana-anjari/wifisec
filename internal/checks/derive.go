package checks

import (
	"math"

	"github.com/Maulana-anjari/wifisec/internal/model"
	"github.com/Maulana-anjari/wifisec/internal/registry"
)

const (
	jitterThresholdMS   = 30.0
	packetLossThreshold = 0.05 // 5%
)

// DeriveLatencyChecks computes net.jitter and net.packet_loss purely
// from net.latency_internet's already-collected samples (spec §6.3:
// both are "dari latency" — 0 additional packets). They must NOT
// re-measure the network themselves: doing so would both double the
// standard profile's real packet spend past its budget and violate
// spec §5.1 (every packet-sending check must call Counter.Add, and
// these two are specified to send none).
func DeriveLatencyChecks(latency model.Check, jitterDef, lossDef registry.CheckDefinition) (jitter, packetLoss model.Check) {
	base := func(def registry.CheckDefinition) model.Check {
		return model.Check{ID: def.ID, Layer: def.Layer, Title: def.Title, ProfileRequired: def.ProfileRequired}
	}
	if latency.Status != model.StatusNormal {
		j, l := base(jitterDef), base(lossDef)
		j.Status, l.Status = model.StatusInconclusive, model.StatusInconclusive
		j.Confidence, l.Confidence = model.ConfidenceLow, model.ConfidenceLow
		// Inherit net.latency_internet's own Control.Reason (e.g.
		// "captive_portal_detected" per spec §6.3, or
		// "internet_unreachable") so a downstream reader learns the
		// actual cause instead of a generic status-derived string. Fall
		// back to the old synthesized reason only if the source Check
		// somehow left Reason empty, so Control.Reason is never blank.
		reason := latency.Control.Reason
		if reason == "" {
			reason = "latency_internet_" + string(latency.Status)
		}
		j.Control = model.Control{Performed: false, Reason: reason}
		l.Control = j.Control
		return j, l
	}

	samples, _ := latency.Observed["rtt_samples_ms"].([]float64)
	sent, _ := latency.Observed["sent"].(int)
	lost, _ := latency.Observed["lost"].(int)

	j := base(jitterDef)
	stddev := stddevMS(samples)
	j.Observed = map[string]any{"stddev_ms": stddev}
	j.Control = model.Control{Performed: true, Result: "computed from net.latency_internet samples"}
	j.Confidence = model.ConfidenceMedium
	if stddev > jitterThresholdMS {
		j.Status = model.StatusAnomalous
	} else {
		j.Status = model.StatusNormal
	}

	l := base(lossDef)
	lossPct := 0.0
	if sent > 0 {
		lossPct = float64(lost) / float64(sent)
	}
	l.Observed = map[string]any{"loss_ratio": lossPct, "sent": sent, "lost": lost}
	l.Control = model.Control{Performed: true, Result: "computed from net.latency_internet samples"}
	l.Confidence = model.ConfidenceMedium
	if lossPct > packetLossThreshold {
		l.Status = model.StatusAnomalous
	} else {
		l.Status = model.StatusNormal
	}

	return j, l
}

func stddevMS(samples []float64) float64 {
	if len(samples) < 2 {
		return 0
	}
	var mean float64
	for _, s := range samples {
		mean += s
	}
	mean /= float64(len(samples))
	var variance float64
	for _, s := range samples {
		variance += (s - mean) * (s - mean)
	}
	variance /= float64(len(samples))
	return math.Sqrt(variance)
}
