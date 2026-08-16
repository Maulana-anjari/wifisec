package tui

import (
	"os"
	"testing"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
)

// TestMain pins lipgloss's color profile before any test runs. Without
// this, lipgloss's package-level color profile is seeded from TTY/env
// detection, so styled renders (e.g. SeverityStyle in
// screen_findings.go) include ANSI codes or not depending on the
// environment the tests happen to run in — making golden files
// environment-dependent instead of deterministic.
func TestMain(m *testing.M) {
	lipgloss.SetColorProfile(termenv.Ascii)
	os.Exit(m.Run())
}
