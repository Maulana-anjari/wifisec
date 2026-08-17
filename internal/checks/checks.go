// Package checks defines the Checker contract every concrete check
// implements (internal/checks/local, internal/checks/wifi, and later
// milestones' dns/tls/net) and orchestrates running them concurrently
// (spec §4.6, §3.2).
package checks

import (
	"context"
	"time"

	"github.com/Maulana-anjari/wifisec/internal/guard"
	"github.com/Maulana-anjari/wifisec/internal/model"
	"github.com/Maulana-anjari/wifisec/internal/platform"
	"github.com/Maulana-anjari/wifisec/internal/registry"
)

// ControlServerConfig configures the optional control server used by
// checks that need a network-side comparison endpoint (spec §10).
// Empty in this milestone — no §6.1 check requires one. Expanded when
// Milestone 4 adds control-server-dependent checks.
type ControlServerConfig struct{}

type CheckContext struct {
	Platform      platform.Adapter
	Counter       *guard.PacketCounter
	ControlServer *ControlServerConfig
	Timeout       time.Duration
}

type Checker interface {
	Definition() registry.CheckDefinition
	Run(ctx context.Context, cc CheckContext) model.Check
}

// NewErrorCheck builds a Check reporting a failed run (spec §4.2
// StatusError), for the common "the platform call itself failed"
// path shared by every checker's Run implementation.
func NewErrorCheck(def registry.CheckDefinition, err error, start time.Time) model.Check {
	return model.Check{
		ID:              def.ID,
		Layer:           def.Layer,
		Title:           def.Title,
		ProfileRequired: def.ProfileRequired,
		Status:          model.StatusError,
		Confidence:      model.ConfidenceLow,
		Control:         model.Control{Performed: false},
		DurationMS:      time.Since(start).Milliseconds(),
		Error:           err.Error(),
	}
}
