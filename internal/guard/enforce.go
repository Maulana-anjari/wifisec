package guard

import (
	"errors"

	"github.com/Maulana-anjari/wifisec/internal/model"
)

// ErrRequiresOwnership is returned by Resolve when the requested
// profile is above standard and OwnsNetwork is false (spec G6: "Untuk
// profil di atas standard, --profile memerlukan --i-own-this-network
// sebagai konfirmasi non-interaktif").
var ErrRequiresOwnership = errors.New("guard: profile above standard requires --i-own-this-network")

// ConfirmStep is one interactive confirmation the caller (cmd/wifisec)
// must walk the user through before running checks at a raised
// profile.
type ConfirmStep int

const (
	// ConfirmRaise is the typed-profile-name confirmation required for
	// any profile above passive (spec G2/G3).
	ConfirmRaise ConfirmStep = iota
	// ConfirmFullUnknown is the second confirmation required only for
	// profile full on a network not in the whitelist (spec G5).
	ConfirmFullUnknown
)

// ProfileRequest describes what the caller is asking for and the
// context Resolve needs to compute the required confirmation steps.
type ProfileRequest struct {
	Requested    model.Profile
	OwnsNetwork  bool // --i-own-this-network flag (spec G6)
	KnownNetwork bool // whitelist.Contains result (spec G5, G7)
}

// Resolve computes the ordered confirmation steps required before
// req.Requested may run (spec §5.2 G1–G3, G5, G6). It never blocks —
// interactive confirmation is the caller's job (cmd/wifisec). Resolve
// only rejects combinations that must never be allowed regardless of
// any confirmation (G6); everything else it expresses as a step list.
//
// Passive requires no confirmation at all (spec G1: it's the default,
// and raising TO passive is a no-op, not a raise).
func Resolve(req ProfileRequest) ([]ConfirmStep, error) {
	if req.Requested.Level() > model.ProfileStandard.Level() && !req.OwnsNetwork {
		return nil, ErrRequiresOwnership
	}
	if req.Requested == model.ProfilePassive {
		return nil, nil
	}
	steps := []ConfirmStep{ConfirmRaise}
	if req.Requested == model.ProfileFull && !req.KnownNetwork {
		steps = append(steps, ConfirmFullUnknown)
	}
	return steps, nil
}
