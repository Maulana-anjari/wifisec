package guard

import (
	"errors"
	"testing"

	"github.com/Maulana-anjari/wifisec/internal/model"
)

func TestResolvePassiveNeedsNoConfirmation(t *testing.T) {
	steps, err := Resolve(ProfileRequest{Requested: model.ProfilePassive})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(steps) != 0 {
		t.Errorf("expected no confirmation steps for passive, got %v", steps)
	}
}

func TestResolveMinimalNeedsOneConfirmation(t *testing.T) {
	steps, err := Resolve(ProfileRequest{Requested: model.ProfileMinimal})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(steps) != 1 || steps[0] != ConfirmRaise {
		t.Errorf("expected [ConfirmRaise], got %v", steps)
	}
}

func TestResolveFullOnKnownNetworkNeedsOneConfirmation(t *testing.T) {
	steps, err := Resolve(ProfileRequest{Requested: model.ProfileFull, OwnsNetwork: true, KnownNetwork: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(steps) != 1 || steps[0] != ConfirmRaise {
		t.Errorf("expected [ConfirmRaise] for full on a known network, got %v", steps)
	}
}

func TestResolveFullOnUnknownNetworkNeedsTwoConfirmations(t *testing.T) {
	steps, err := Resolve(ProfileRequest{Requested: model.ProfileFull, OwnsNetwork: true, KnownNetwork: false})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(steps) != 2 || steps[0] != ConfirmRaise || steps[1] != ConfirmFullUnknown {
		t.Errorf("expected [ConfirmRaise, ConfirmFullUnknown] for full on an unknown network, got %v", steps)
	}
}

func TestResolveFullWithoutOwnershipFlagIsRejected(t *testing.T) {
	_, err := Resolve(ProfileRequest{Requested: model.ProfileFull, OwnsNetwork: false})
	if !errors.Is(err, ErrRequiresOwnership) {
		t.Errorf("expected ErrRequiresOwnership, got %v", err)
	}
}

func TestResolveStandardWithoutOwnershipFlagIsAllowed(t *testing.T) {
	// G6 only gates profiles ABOVE standard — standard itself needs no
	// --i-own-this-network flag, only its own G2 typed confirmation.
	steps, err := Resolve(ProfileRequest{Requested: model.ProfileStandard, OwnsNetwork: false})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(steps) != 1 || steps[0] != ConfirmRaise {
		t.Errorf("expected [ConfirmRaise], got %v", steps)
	}
}
