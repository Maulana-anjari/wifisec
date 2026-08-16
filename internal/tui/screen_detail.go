package tui

import (
	"fmt"
	"strings"

	"github.com/Maulana-anjari/wifisec/internal/model"
)

func renderDetailScreen(r model.Result, selected, width int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Checks (%d)\n", len(r.Checks))
	if len(r.Checks) == 0 {
		b.WriteString("  (tidak ada check)\n")
		return b.String()
	}
	c := r.Checks[selected]
	fmt.Fprintf(&b, "%s %s  [%s]\n", StatusGlyph(c.Status), c.Title, c.ID)
	fmt.Fprintf(&b, "  layer: %s   status: %s   confidence: %s\n", c.Layer, c.Status, c.Confidence)
	if c.Target != "" {
		fmt.Fprintf(&b, "  target: %s\n", c.Target)
	}
	fmt.Fprintf(&b, "  control performed: %v", c.Control.Performed)
	if c.Control.Reason != "" {
		fmt.Fprintf(&b, "   reason: %s", c.Control.Reason)
	}
	b.WriteString("\n")
	if c.Error != "" {
		fmt.Fprintf(&b, "  error: %s\n", c.Error)
	}
	fmt.Fprintf(&b, "  packets sent: %d   duration: %dms\n", c.PacketsSent, c.DurationMS)
	return b.String()
}
