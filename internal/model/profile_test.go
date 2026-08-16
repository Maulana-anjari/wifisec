package model

import "testing"

func TestProfileLevel(t *testing.T) {
	cases := []struct {
		p    Profile
		want int
	}{
		{ProfilePassive, 0},
		{ProfileMinimal, 1},
		{ProfileStandard, 2},
		{ProfileFull, 3},
	}
	for _, c := range cases {
		if got := c.p.Level(); got != c.want {
			t.Errorf("%s.Level() = %d, want %d", c.p, got, c.want)
		}
	}
}

func TestProfileAllows(t *testing.T) {
	if !ProfileStandard.Allows(ProfileMinimal) {
		t.Error("standard should allow minimal-required checks")
	}
	if ProfileMinimal.Allows(ProfileStandard) {
		t.Error("minimal should not allow standard-required checks")
	}
	if !ProfilePassive.Allows(ProfilePassive) {
		t.Error("a profile should allow its own level")
	}
}

func TestProfileEstimatedPacketsMonotonic(t *testing.T) {
	profiles := []Profile{ProfilePassive, ProfileMinimal, ProfileStandard, ProfileFull}
	for i := 1; i < len(profiles); i++ {
		if profiles[i].EstimatedPackets() < profiles[i-1].EstimatedPackets() {
			t.Errorf("%s.EstimatedPackets() < %s.EstimatedPackets(), estimates must not decrease as profile rises", profiles[i], profiles[i-1])
		}
	}
	if ProfilePassive.EstimatedPackets() != 0 {
		t.Errorf("passive.EstimatedPackets() = %d, want 0 (spec P1: passive sends nothing)", ProfilePassive.EstimatedPackets())
	}
}
