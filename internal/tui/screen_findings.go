package tui

import (
	"fmt"
	"strings"

	"github.com/Maulana-anjari/wifisec/internal/model"
)

func renderFindingsScreen(r model.Result, selected, width int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Findings (%d)\n", len(r.Findings))
	if len(r.Findings) == 0 {
		b.WriteString("  (tidak ada temuan)\n")
		return b.String()
	}
	for i, f := range r.Findings {
		cursor := "  "
		if i == selected {
			cursor = "> "
		}
		style := SeverityStyle(f.Severity)
		fmt.Fprintf(&b, "%s%s %s\n", cursor, glyphForSeverity(f.Severity), style.Render(f.Title))
		for _, hint := range f.FalsePositiveHints {
			fmt.Fprintf(&b, "      hint: %s\n", hint)
		}
	}
	return b.String()
}

func glyphForSeverity(s model.Severity) string {
	switch s {
	case model.SeverityCritical:
		return "▲"
	case model.SeverityWarning:
		return "!"
	default:
		return "·"
	}
}
