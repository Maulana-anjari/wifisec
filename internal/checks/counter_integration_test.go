package checks_test

import (
	"context"
	"testing"
	"time"

	"github.com/Maulana-anjari/wifisec/internal/checks"
	"github.com/Maulana-anjari/wifisec/internal/guard"
	"github.com/Maulana-anjari/wifisec/internal/model"
	"github.com/Maulana-anjari/wifisec/internal/registry"
)

// packetHungryChecker simulates a check that tries to send more
// packets than the active profile's counter allows — exactly the
// scenario spec T3 requires, without needing a real Milestone 4 check.
type packetHungryChecker struct {
	def registry.CheckDefinition
	n   int
}

func (c packetHungryChecker) Definition() registry.CheckDefinition { return c.def }

func (c packetHungryChecker) Run(ctx context.Context, cc checks.CheckContext) model.Check {
	start := time.Now()
	if err := cc.Counter.Add(c.def.ID, c.n); err != nil {
		return checks.NewErrorCheck(c.def, err, start)
	}
	return model.Check{ID: c.def.ID, Status: model.StatusNormal, Confidence: model.ConfidenceHigh}
}

func TestT3PacketLimitRejectionSurfacesAsStatusError(t *testing.T) {
	def := registry.CheckDefinition{ID: "test.packet_hungry", Layer: model.LayerLocal, Title: "Packet-hungry test check"}
	checker := packetHungryChecker{def: def, n: 5}

	// Passive profile: limit is 0, so any Add must fail.
	counter := guard.NewPacketCounter(model.ProfilePassive.EstimatedPackets())
	cc := checks.CheckContext{Counter: counter}

	var got model.Check
	for c := range checks.Run(context.Background(), []checks.Checker{checker}, cc) {
		got = c
	}

	if got.Status != model.StatusError {
		t.Errorf("Status = %s, want error (spec T3: rejected Add must surface as StatusError)", got.Status)
	}
	if got.Error == "" {
		t.Error("expected a non-empty Error message explaining the rejection")
	}
	if counter.Total() != 0 {
		t.Errorf("counter.Total() = %d, want 0 (rejected Add must not partially apply)", counter.Total())
	}
}
