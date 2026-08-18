package registry

import (
	"testing"

	"github.com/Maulana-anjari/wifisec/internal/model"
)

// TestStandardProfileBudgetCoversRealWorstCaseDemand pins
// model.ProfileStandard.EstimatedPackets() to the real registry it is
// meant to describe, mechanically. That constant (internal/model/profile.go)
// has been wrong three times during M4 development (50, then 52, then
// the current 62) because nothing checked it against checks.yaml — a
// human had to notice by inspection each time.
//
// This test does the arithmetic instead: sum every CheckDefinition
// reachable at ProfileStandard (which, since profiles are cumulative,
// includes the ProfileMinimal-tier checks too), then add 10 more for
// net.latency_gateway's documented port-80-then-443 fallback (spec
// §6.3 / internal/checks/net/latency.go): when port 80 gets no
// response, the check calls Counter.Add a second time and retries on
// port 443, so its real worst-case packet reservation is double its
// flat registry value (20, not 10). That doubling is a known,
// intentional exception — not a bug — and is the only reason this
// test doesn't just assert equality with the raw sum.
//
// If this test starts failing after an intentional change, update
// whichever side is now wrong:
//   - checks.yaml changed (added/removed/reweighted a standard-or-below
//     check) -> the +10 fallback fudge or the constant may need to
//     change with it;
//   - the constant in profile.go was hand-edited without checking the
//     registry -> fix the constant, not this test.
func TestStandardProfileBudgetCoversRealWorstCaseDemand(t *testing.T) {
	r, err := Load()
	if err != nil {
		t.Fatal(err)
	}

	const gatewayFallbackExtra = 10 // net.latency_gateway's port-80->443 retry, see comment above.

	sum := 0
	for _, def := range r.Filter(model.ProfileStandard) {
		sum += def.EstimatedPackets
	}
	sum += gatewayFallbackExtra

	if want := model.ProfileStandard.EstimatedPackets(); sum != want {
		t.Errorf("real worst-case standard-tier packet demand = %d (registry sum + %d fallback fudge), but model.ProfileStandard.EstimatedPackets() = %d — update whichever is now wrong (see comment on this test)",
			sum, gatewayFallbackExtra, want)
	}
}
