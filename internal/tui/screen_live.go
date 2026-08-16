package tui

import (
	"fmt"
	"strings"

	"github.com/Maulana-anjari/wifisec/internal/model"
)

func renderLiveScreen(r model.Result, width int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Live (%d checks)\n", len(r.Checks))
	for _, c := range r.Checks {
		fmt.Fprintf(&b, "  %s %s\n", StatusGlyph(c.Status), c.Title)
	}
	return b.String()
}
