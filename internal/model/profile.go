package model

// Profile controls how intrusive checks are allowed to be (spec §4.1).
type Profile string

const (
	ProfilePassive  Profile = "passive"
	ProfileMinimal  Profile = "minimal"
	ProfileStandard Profile = "standard"
	ProfileFull     Profile = "full"
)

var profileLevel = map[Profile]int{
	ProfilePassive:  0,
	ProfileMinimal:  1,
	ProfileStandard: 2,
	ProfileFull:     3,
}

// estimatedPackets is a rough, static per-profile guidance value shown
// in the raise-profile confirmation dialog (spec §5.2 G3). It sums the
// approximate packet counts from spec §6.2-§6.4; it is not a hard
// limit — guard.PacketCounter enforces the real limit at runtime.
var estimatedPackets = map[Profile]int{
	ProfilePassive:  0,
	ProfileMinimal:  2,
	ProfileStandard: 50,
	ProfileFull:     150,
}

// Level returns the numeric ordering for profile comparison:
// passive=0, minimal=1, standard=2, full=3.
func (p Profile) Level() int {
	return profileLevel[p]
}

// EstimatedPackets returns the approximate packet count to display in
// the confirmation dialog (spec §4.1).
func (p Profile) EstimatedPackets() int {
	return estimatedPackets[p]
}

// Allows reports whether this profile permits a check that requires
// the given profile (spec §4.1, §5.2 G-rules).
func (p Profile) Allows(required Profile) bool {
	return p.Level() >= required.Level()
}
