package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/Maulana-anjari/wifisec/internal/model"
)

// useCaseOrder is the fixed display order for spec §7.3 use cases.
var useCaseOrder = []string{"browsing_umum", "login_akun_pribadi", "kerja_sensitif", "internet_banking"}

func renderVerdictScreen(r model.Result, width int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s  (score %d)\n", strings.ToUpper(string(r.Verdict.Safety)), r.Verdict.Score)
	b.WriteString(r.Verdict.Headline)
	b.WriteString("\n\n")

	left := renderList("Temuan utama", r.Verdict.TopFindings)
	right := renderList("Tidak diperiksa", r.Verdict.BlindSpots)

	if isNarrow(width) {
		b.WriteString(left)
		b.WriteString("\n")
		b.WriteString(right)
	} else {
		b.WriteString(joinColumns(left, right, width))
	}

	if len(r.Verdict.UseCases) > 0 {
		b.WriteString("\nUse case:\n")
		for _, key := range useCaseOrder {
			if v, ok := r.Verdict.UseCases[key]; ok {
				fmt.Fprintf(&b, "  %-20s %s\n", key, v)
			}
		}
	}
	return b.String()
}

func renderList(title string, items []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s (%d)\n", title, len(items))
	if len(items) == 0 {
		b.WriteString("  (tidak ada)\n")
	}
	for _, item := range items {
		fmt.Fprintf(&b, "  - %s\n", item)
	}
	return b.String()
}

// joinColumns lays two rendered blocks side by side at equal width, so
// "top findings" and "blind spots" carry the same visual weight
// (spec §9.3). Each column is bounded to colWidth via lipgloss, which
// both pads short lines and word-wraps long ones — unlike a raw
// fmt.Fprintf("%-*s %s", ...) pad, which only bounds the left column
// and lets the right column run arbitrarily wide.
func joinColumns(left, right string, width int) string {
	colWidth := width/2 - 1
	if colWidth < 1 {
		colWidth = 1
	}
	colStyle := lipgloss.NewStyle().Width(colWidth)
	leftBlock := colStyle.Render(strings.TrimRight(left, "\n"))
	rightBlock := colStyle.Render(strings.TrimRight(right, "\n"))
	leftLines := strings.Split(leftBlock, "\n")
	rightLines := strings.Split(rightBlock, "\n")
	blank := strings.Repeat(" ", colWidth)

	n := len(leftLines)
	if len(rightLines) > n {
		n = len(rightLines)
	}
	var b strings.Builder
	for i := 0; i < n; i++ {
		l, r := blank, ""
		if i < len(leftLines) {
			l = leftLines[i]
		}
		if i < len(rightLines) {
			r = rightLines[i]
		}
		fmt.Fprintf(&b, "%s %s\n", l, r)
	}
	return b.String()
}
