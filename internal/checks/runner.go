package checks

import (
	"context"
	"sync"

	"github.com/Maulana-anjari/wifisec/internal/model"
)

// Run executes every checker concurrently, streaming each result to
// the returned channel as it completes (spec §3.2: "paralel, hasil ke
// channel"). The channel is closed once all checkers finish.
func Run(ctx context.Context, checkers []Checker, cc CheckContext) <-chan model.Check {
	out := make(chan model.Check)
	go func() {
		defer close(out)
		var wg sync.WaitGroup
		for _, checker := range checkers {
			wg.Add(1)
			go func(checker Checker) {
				defer wg.Done()
				checkCtx := ctx
				if cc.Timeout > 0 {
					var cancel context.CancelFunc
					checkCtx, cancel = context.WithTimeout(ctx, cc.Timeout)
					defer cancel()
				}
				// NOTE: this makes checkCtx carry a real deadline, but
				// today's Checker.Run implementations don't select on
				// ctx.Done() themselves — they call platform.Adapter
				// methods backed by plain exec.Command, which does not
				// observe context cancellation. So a genuinely hung
				// nmcli/ip call is NOT actually interrupted yet; this is
				// the deadline-plumbing half of that fix, not the whole
				// fix (follow-up: exec.CommandContext in the adapter).
				c := checker.Run(checkCtx, cc)
				// Defense-in-depth: assert the structural invariants
				// (spec §4.2) every checker is expected to already
				// satisfy. Doesn't change Status/Observed on the
				// (expected) common case where validation passes —
				// just surfaces a violation honestly via Error instead
				// of silently shipping a malformed Check.
				if err := model.ValidateCheck(c, checker.Definition().SelfEvident); err != nil {
					c.Error = "ValidateCheck: " + err.Error()
				}
				out <- c
			}(checker)
		}
		wg.Wait()
	}()
	return out
}
