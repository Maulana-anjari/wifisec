package net

import (
	stdcontext "context"
	stdnet "net"
	"sync"
	"time"

	"github.com/Maulana-anjari/wifisec/internal/checks"
	"github.com/Maulana-anjari/wifisec/internal/model"
	"github.com/Maulana-anjari/wifisec/internal/registry"
)

const bufferbloatIncreaseThresholdMS = 200.0

type BufferbloatCheck struct{ def registry.CheckDefinition }

func NewBufferbloatCheck(def registry.CheckDefinition) checks.Checker { return BufferbloatCheck{def} }
func (c BufferbloatCheck) Definition() registry.CheckDefinition       { return c.def }

// Run compares idle RTT (a handful of sequential dials) against RTT
// measured while N connections fire concurrently (spec §6.3:
// "Latency saat dibebani" — latency while loaded). This deliberately
// uses connection concurrency, not a bulk data transfer, to induce
// load: generating heavy sustained traffic on someone else's network
// to test for bufferbloat would look uncomfortably close to the kind
// of traffic pattern this tool exists to avoid (CLAUDE.md's
// intrusiveness principle), and spec's own "~20 paket" budget for
// this check reads as 20 connection attempts, not a data volume.
func (c BufferbloatCheck) Run(ctx stdcontext.Context, cc checks.CheckContext) model.Check {
	start := time.Now()
	if err := cc.Counter.Add(c.def.ID, c.def.EstimatedPackets); err != nil {
		return checks.NewErrorCheck(c.def, err, start)
	}
	// Guard against degenerate budget: need at least 2 packets (1 idle + 1 loaded).
	if c.def.EstimatedPackets < 2 {
		return model.Check{
			ID: c.def.ID, Layer: c.def.Layer, Title: c.def.Title, ProfileRequired: c.def.ProfileRequired,
			Status: model.StatusInconclusive, Confidence: model.ConfidenceLow,
			Control:     model.Control{Performed: false, Reason: "budget_too_small"},
			PacketsSent: c.def.EstimatedPackets, DurationMS: time.Since(start).Milliseconds(),
		}
	}
	// Ensure idleN + loadedN <= EstimatedPackets structurally (not just for shipped value).
	idleN := min(5, c.def.EstimatedPackets-1)
	loadedN := c.def.EstimatedPackets - idleN

	idleSamples, _, _ := sampleTCP(ctx, internetTarget, idleN, 3*time.Second)
	loadedSamples := sampleConcurrent(ctx, internetTarget, loadedN, 3*time.Second)

	if len(idleSamples) == 0 || len(loadedSamples) == 0 {
		return model.Check{
			ID: c.def.ID, Layer: c.def.Layer, Title: c.def.Title, ProfileRequired: c.def.ProfileRequired,
			Status: model.StatusInconclusive, Confidence: model.ConfidenceLow,
			Control:     model.Control{Performed: false, Reason: "internet_unreachable"},
			PacketsSent: c.def.EstimatedPackets, DurationMS: time.Since(start).Milliseconds(),
		}
	}

	idleMean := meanMS(msFloats(idleSamples))
	loadedMean := meanMS(msFloats(loadedSamples))
	increase := loadedMean - idleMean

	status := model.StatusNormal
	if increase > bufferbloatIncreaseThresholdMS {
		status = model.StatusAnomalous
	}
	return model.Check{
		ID: c.def.ID, Layer: c.def.Layer, Title: c.def.Title, ProfileRequired: c.def.ProfileRequired,
		Status: status, Confidence: model.ConfidenceMedium,
		Observed:    map[string]any{"idle_rtt_ms": idleMean, "loaded_rtt_ms": loadedMean, "increase_ms": increase},
		Control:     model.Control{Performed: true, Result: "idle vs loaded RTT to same target"},
		PacketsSent: c.def.EstimatedPackets, DurationMS: time.Since(start).Milliseconds(),
	}
}

// sampleConcurrent dials addr n times in parallel and returns the
// connect duration of each successful dial — used to generate the
// "loaded" side of the idle-vs-loaded comparison above.
func sampleConcurrent(ctx stdcontext.Context, addr string, n int, perDialTimeout time.Duration) []time.Duration {
	dialer := stdnet.Dialer{Timeout: perDialTimeout}
	var mu sync.Mutex
	var samples []time.Duration
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			start := time.Now()
			conn, err := dialer.DialContext(ctx, "tcp", addr)
			if err == nil {
				mu.Lock()
				samples = append(samples, time.Since(start))
				mu.Unlock()
				conn.Close()
			}
		}()
	}
	wg.Wait()
	return samples
}
