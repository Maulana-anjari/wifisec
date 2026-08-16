package tui

import (
	"fmt"
	"strings"

	"github.com/Maulana-anjari/wifisec/internal/model"
)

// ProfileDialog renders the profile-raise confirmation dialog (spec
// §5.2 G2/G3). It only renders; the caller collects the typed
// confirmation text via the TUI's key handling.
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
