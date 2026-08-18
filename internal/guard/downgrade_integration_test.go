package guard_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Maulana-anjari/wifisec/internal/checks"
	"github.com/Maulana-anjari/wifisec/internal/guard"
	"github.com/Maulana-anjari/wifisec/internal/model"
	"github.com/Maulana-anjari/wifisec/internal/platform"
	"github.com/Maulana-anjari/wifisec/internal/registry"
)

// bssidFlippingAdapter reports one BSSID for the first call, then a
// different one forever after — simulating an AP change mid-run.
type bssidFlippingAdapter struct{ calls int }

func (a *bssidFlippingAdapter) WiFiInfo() (platform.WiFiInfo, error) {
	a.calls++
	bssid := "AA:AA:AA:AA:AA:AA"
	if a.calls > 1 {
		bssid = "CC:CC:CC:CC:CC:CC"
	}
	return platform.WiFiInfo{Available: true, BSSID: bssid}, nil
}
func (a *bssidFlippingAdapter) NetConfig() (platform.NetConfig, error)     { return platform.NetConfig{}, nil }
func (a *bssidFlippingAdapter) ProxyConfig() (platform.ProxyConfig, error) { return platform.ProxyConfig{}, nil }
func (a *bssidFlippingAdapter) TrustStoreCAs() ([]platform.CACert, error)  { return nil, nil }
func (a *bssidFlippingAdapter) RoutingTable() ([]platform.Route, error)    { return nil, nil }

// slowChecker blocks until ctx is cancelled or a generous timeout
// elapses, so the test can observe cancellation actually propagating.
type slowChecker struct{ def registry.CheckDefinition }

func (c slowChecker) Definition() registry.CheckDefinition { return c.def }
func (c slowChecker) Run(ctx context.Context, cc checks.CheckContext) model.Check {
	select {
	case <-ctx.Done():
		return model.Check{ID: c.def.ID, Status: model.StatusError, Error: "cancelled: " + ctx.Err().Error()}
	case <-time.After(5 * time.Second):
		return model.Check{ID: c.def.ID, Status: model.StatusNormal}
	}
}

func TestT4AutoDowngradeOnBSSIDChangeCancelsRunningChecks(t *testing.T) {
	adapter := &bssidFlippingAdapter{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// downgraded is read from this goroutine after the loop below and
	// written from the Watch goroutine's callback — an atomic.Bool
	// avoids the same data race the production code in cmd/wifisec's
	// runReal must also avoid (see that task's note): a plain bool here
	// would have no synchronized happens-before edge with the read.
	var downgraded atomic.Bool
	go guard.Watch(ctx, adapter, "AA:AA:AA:AA:AA:AA", 5*time.Millisecond, func(string) {
		downgraded.Store(true)
		cancel()
	})

	def := registry.CheckDefinition{ID: "test.slow", Layer: model.LayerLocal, Title: "slow"}
	var got model.Check
	for c := range checks.Run(ctx, []checks.Checker{slowChecker{def: def}}, checks.CheckContext{}) {
		got = c
	}

	if !downgraded.Load() {
		t.Error("expected the watcher to report a BSSID change")
	}
	if got.Status != model.StatusError {
		t.Errorf("Status = %s, want error (the running check must observe ctx cancellation, spec T4/G4)", got.Status)
	}
}
