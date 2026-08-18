package guard

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/Maulana-anjari/wifisec/internal/platform"
)

// fakeWiFiAdapter returns a scripted sequence of BSSIDs, one per
// WiFiInfo() call, repeating the last entry once the script is
// exhausted.
type fakeWiFiAdapter struct {
	mu      sync.Mutex
	bssids  []string
	callIdx int
}

func (f *fakeWiFiAdapter) WiFiInfo() (platform.WiFiInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	idx := f.callIdx
	if idx >= len(f.bssids) {
		idx = len(f.bssids) - 1
	}
	f.callIdx++
	return platform.WiFiInfo{Available: true, BSSID: f.bssids[idx]}, nil
}
func (f *fakeWiFiAdapter) NetConfig() (platform.NetConfig, error)     { return platform.NetConfig{}, nil }
func (f *fakeWiFiAdapter) ProxyConfig() (platform.ProxyConfig, error) { return platform.ProxyConfig{}, nil }
func (f *fakeWiFiAdapter) TrustStoreCAs() ([]platform.CACert, error)  { return nil, nil }
func (f *fakeWiFiAdapter) RoutingTable() ([]platform.Route, error)    { return nil, nil }

func TestWatchFiresOnChangeWhenBSSIDDiffers(t *testing.T) {
	adapter := &fakeWiFiAdapter{bssids: []string{"AA:AA:AA:AA:AA:AA", "BB:BB:BB:BB:BB:BB"}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	changed := make(chan string, 1)
	go Watch(ctx, adapter, "AA:AA:AA:AA:AA:AA", 5*time.Millisecond, func(newBSSID string) {
		changed <- newBSSID
	})

	select {
	case got := <-changed:
		if got != "BB:BB:BB:BB:BB:BB" {
			t.Errorf("onChange got %q, want BB:BB:BB:BB:BB:BB", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("onChange was never called")
	}
}

func TestWatchNeverFiresWhenBSSIDStable(t *testing.T) {
	adapter := &fakeWiFiAdapter{bssids: []string{"AA:AA:AA:AA:AA:AA"}}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	fired := false
	Watch(ctx, adapter, "AA:AA:AA:AA:AA:AA", 5*time.Millisecond, func(string) {
		fired = true
	})
	if fired {
		t.Error("onChange fired despite a stable BSSID")
	}
}

func TestWatchStopsWhenContextCancelled(t *testing.T) {
	adapter := &fakeWiFiAdapter{bssids: []string{"AA:AA:AA:AA:AA:AA"}}
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		Watch(ctx, adapter, "AA:AA:AA:AA:AA:AA", 5*time.Millisecond, func(string) {})
		close(done)
	}()

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Watch did not return after context cancellation")
	}
}
