package checks

import (
	"context"
	"testing"
	"time"

	"github.com/Maulana-anjari/wifisec/internal/guard"
	"github.com/Maulana-anjari/wifisec/internal/model"
	"github.com/Maulana-anjari/wifisec/internal/registry"
)

type stubChecker struct {
	def registry.CheckDefinition
	run func(ctx context.Context, cc CheckContext) model.Check
}

func (s stubChecker) Definition() registry.CheckDefinition                 { return s.def }
func (s stubChecker) Run(ctx context.Context, cc CheckContext) model.Check { return s.run(ctx, cc) }

func normalCheck(id string) func(context.Context, CheckContext) model.Check {
	return func(context.Context, CheckContext) model.Check {
		return model.Check{ID: id, Status: model.StatusNormal, Confidence: model.ConfidenceMedium}
	}
}

func TestRunGatedRunsEverythingWhenGateClean(t *testing.T) {
	gate := stubChecker{def: registry.CheckDefinition{ID: "gate"}, run: normalCheck("gate")}
	other := stubChecker{def: registry.CheckDefinition{ID: "other"}, run: normalCheck("other")}
	cc := CheckContext{Counter: guard.NewPacketCounter(100), Timeout: time.Second}

	var got []model.Check
	for c := range RunGated(context.Background(), []Checker{gate, other}, cc, "gate",
		func(c model.Check) bool { return c.Status == model.StatusAnomalous }, "gate_tripped") {
		got = append(got, c)
	}
	if len(got) != 2 {
		t.Fatalf("got %d checks, want 2", len(got))
	}
	for _, c := range got {
		if c.Status != model.StatusNormal {
			t.Errorf("check %s: Status = %v, want normal (gate was clean)", c.ID, c.Status)
		}
	}
}

func TestRunGatedShortCircuitsWhenGateTrips(t *testing.T) {
	gate := stubChecker{def: registry.CheckDefinition{ID: "gate"}, run: func(context.Context, CheckContext) model.Check {
		return model.Check{ID: "gate", Status: model.StatusAnomalous, Confidence: model.ConfidenceHigh, Control: model.Control{Performed: true}}
	}}
	other := stubChecker{def: registry.CheckDefinition{ID: "other", Layer: model.LayerPerf, Title: "Other"}, run: func(context.Context, CheckContext) model.Check {
		t.Error("other checker's Run must not be called when the gate trips")
		return model.Check{}
	}}
	cc := CheckContext{Counter: guard.NewPacketCounter(100), Timeout: time.Second}

	var got []model.Check
	for c := range RunGated(context.Background(), []Checker{gate, other}, cc, "gate",
		func(c model.Check) bool { return c.Status == model.StatusAnomalous }, "gate_tripped") {
		got = append(got, c)
	}
	if len(got) != 2 {
		t.Fatalf("got %d checks, want 2", len(got))
	}
	for _, c := range got {
		if c.ID == "other" {
			if c.Status != model.StatusInconclusive {
				t.Errorf("other.Status = %v, want inconclusive", c.Status)
			}
			if c.Control.Reason != "gate_tripped" {
				t.Errorf("other.Control.Reason = %q, want %q", c.Control.Reason, "gate_tripped")
			}
			if c.PacketsSent != 0 {
				t.Errorf("other.PacketsSent = %d, want 0 (never ran)", c.PacketsSent)
			}
		}
	}
}
