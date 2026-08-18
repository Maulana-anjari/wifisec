package checks

import (
	"context"

	"github.com/Maulana-anjari/wifisec/internal/model"
)

// RunGated runs gateID's checker first, synchronously, and waits for
// it to finish before anything else starts. If isTripped(gateResult)
// is true, every other checker is short-circuited to
// StatusInconclusive (Control.Reason: gatedReason) instead of
// actually running — spec §6.3: "net.captive_portal harus berjalan
// dan selesai sebelum check lain di profil ini. Jika portal
// terdeteksi, seluruh check lain berstatus inconclusive." If gateID
// is not present in checkers, RunGated behaves exactly like Run.
func RunGated(ctx context.Context, checkers []Checker, cc CheckContext, gateID string, isTripped func(model.Check) bool, gatedReason string) <-chan model.Check {
	var gate Checker
	rest := make([]Checker, 0, len(checkers))
	for _, c := range checkers {
		if c.Definition().ID == gateID {
			gate = c
			continue
		}
		rest = append(rest, c)
	}
	if gate == nil {
		return Run(ctx, checkers, cc)
	}

	out := make(chan model.Check)
	go func() {
		defer close(out)
		gateResult := gate.Run(ctx, cc)
		out <- gateResult
		if isTripped(gateResult) {
			for _, c := range rest {
				def := c.Definition()
				out <- model.Check{
					ID: def.ID, Layer: def.Layer, Title: def.Title, ProfileRequired: def.ProfileRequired,
					Status: model.StatusInconclusive, Confidence: model.ConfidenceLow,
					Control: model.Control{Performed: false, Reason: gatedReason},
				}
			}
			return
		}
		for c := range Run(ctx, rest, cc) {
			out <- c
		}
	}()
	return out
}
