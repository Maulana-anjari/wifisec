package tui

import (
	"github.com/charmbracelet/lipgloss"

	"github.com/Maulana-anjari/wifisec/internal/model"
)

const breakpointColumns = 70

var (
	styleCritical = lipgloss.NewStyle().Foreground(lipgloss.Color("9"))
	styleWarning  = lipgloss.NewStyle().Foreground(lipgloss.Color("11"))
	styleInfo     = lipgloss.NewStyle().Foreground(lipgloss.Color("12"))
)

// ProfileGlyph returns the header glyph for a profile (spec §9.3).
func ProfileGlyph(p model.Profile) string {
	switch p {
	case model.ProfilePassive:
		return "●"
	case model.ProfileMinimal:
		return "◐"
	case model.ProfileStandard:
		return "◑"
	case model.ProfileFull:
		return "◆"
	default:
		return "?"
	}
}

// StatusGlyph returns the check-status glyph. Color only reinforces
// this; it is never the sole differentiator (spec §9.3).
func StatusGlyph(s model.CheckStatus) string {
	switch s {
	case model.StatusNormal:
		return "✓"
	case model.StatusAnomalous:
		return "!"
	case model.StatusInconclusive:
		return "?"
	case model.StatusSkipped:
		return "–"
	case model.StatusError:
		return "×"
	default:
		return " "
	}
}

// SeverityStyle returns the lipgloss style for a finding severity.
func SeverityStyle(s model.Severity) lipgloss.Style {
	switch s {
	case model.SeverityCritical:
		return styleCritical
	case model.SeverityWarning:
		return styleWarning
	default:
		return styleInfo
	}
}

// isNarrow reports whether the terminal is below the single breakpoint
// (spec §9.3): side-by-side columns collapse to stacked below 70 cols.
// Width 0 means "unknown" (no WindowSizeMsg received yet) and is not
// treated as narrow.
func isNarrow(width int) bool {
	return width > 0 && width < breakpointColumns
}
