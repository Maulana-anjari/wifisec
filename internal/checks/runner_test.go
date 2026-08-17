package checks

import (
	"context"
	"testing"
	"time"

	"github.com/Maulana-anjari/wifisec/internal/model"
	"github.com/Maulana-anjari/wifisec/internal/registry"
)

type fakeChecker struct {
	id    string
	delay time.Duration
}

func (f fakeChecker) Definition() registry.CheckDefinition {
	return registry.CheckDefinition{ID: f.id, Layer: model.LayerLocal, Title: f.id}
}

func (f fakeChecker) Run(ctx context.Context, cc CheckContext) model.Check {
	time.Sleep(f.delay)
	return model.Check{ID: f.id, Status: model.StatusNormal, Confidence: model.ConfidenceHigh}
}

func TestRunStreamsAllResultsAndClosesChannel(t *testing.T) {
	checkers := []Checker{
		fakeChecker{id: "a", delay: 5 * time.Millisecond},
		fakeChecker{id: "b", delay: 1 * time.Millisecond},
		fakeChecker{id: "c"},
	}
	got := map[string]bool{}
	for c := range Run(context.Background(), checkers, CheckContext{}) {
		got[c.ID] = true
	}
	for _, want := range []string{"a", "b", "c"} {
		if !got[want] {
			t.Errorf("missing result for check %q", want)
		}
	}
}

func TestNewErrorCheckReportsError(t *testing.T) {
	def := registry.CheckDefinition{ID: "x", Layer: model.LayerLocal, Title: "X"}
	c := NewErrorCheck(def, errBoom, time.Now())
	if c.Status != model.StatusError {
		t.Errorf("Status = %s, want error", c.Status)
	}
	if c.ID != "x" || c.Error == "" {
		t.Errorf("expected ID and Error populated, got %+v", c)
	}
}

var errBoom = errBoomType{}

type errBoomType struct{}

func (errBoomType) Error() string { return "boom" }
