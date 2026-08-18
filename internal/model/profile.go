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
	ProfilePassive: 0,
	ProfileMinimal: 2,
	// 62 = worst-case standard-tier demand, not the flat sum of spec
	// §6.3's table. net.latency_gateway's port-80→port-443 fallback
	// (any gateway that doesn't serve HTTP on port 80 — common)
	// ACCUMULATES Counter.Add across both attempts, so its real
	// worst case is 20 (10+10), not the table's flat 10. That makes
	// the standard tier: 20(gateway)+10(internet)+2(captive_portal)+
	// 4(compare_doh)+2(transparent_proxy)+20(bufferbloat)+2(ipv6) = 60,
	// PLUS the 2 minimal-tier checks (dns.resolve_basic, tls.cert_issuer)
	// that also run — for real, calling Counter.Add — whenever the
	// active profile is standard or above, since profiles are
	// cumulative (spec §4.1). Total: 62. This is a display/limit value,
	// not a hard cap (guard.PacketCounter enforces the real limit at
	// runtime), so overstating it slightly here is the safe direction —
	// unlike the prior value (52), which was provably insufficient
	// whenever the fallback fires and would spuriously StatusError the
	// two minimal-tier checks on a perfectly clean network.
	ProfileStandard: 62,
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
