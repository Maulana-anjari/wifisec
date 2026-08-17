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
				out <- checker.Run(ctx, cc)
			}(checker)
		}
		wg.Wait()
	}()
	return out
}
