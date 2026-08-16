package tui

import (
	"fmt"
	"strings"

	"github.com/Maulana-anjari/wifisec/internal/model"
)

// ProfileDialog renders the profile-raise confirmation dialog (spec
// §5.2 G2/G3). It only renders; the caller collects the typed
// confirmation text via the TUI's key handling.
//
// Not yet wired into Model: there is no keybinding that constructs or
// displays a ProfileDialog today, so it is currently dead code. Wiring
// it up — a keybinding to trigger the raise-profile flow, typing state
// on Model, etc. — is real interactive feature work that belongs to
// Milestone 3 ("Sistem profil"), not this milestone.
type ProfileDialog struct {
	Target       model.Profile
	KnownNetwork bool
	Typed        string
}

func (d ProfileDialog) View() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Naikkan profil ke %s?\n", d.Target)
	fmt.Fprintf(&b, "  estimasi paket: ~%d\n", d.Target.EstimatedPackets())
	fmt.Fprintf(&b, "  known network: %v\n", d.KnownNetwork)
	if d.Target == model.ProfileFull {
		b.WriteString("  PERINGATAN: profil full paling intrusif, hanya untuk jaringan milik sendiri.\n")
	}
	fmt.Fprintf(&b, "  ketik %q untuk konfirmasi: %s\n", string(d.Target), d.Typed)
	return b.String()
}

// Confirmed reports whether the typed text exactly matches the target
// profile name (spec G2: full name, exact match required).
func (d ProfileDialog) Confirmed() bool {
	return d.Typed == string(d.Target)
}
