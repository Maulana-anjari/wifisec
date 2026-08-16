package main

import (
	"encoding/json"
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/Maulana-anjari/wifisec/internal/model"
	"github.com/Maulana-anjari/wifisec/internal/tui"
)

// main is an M1 stub: it renders a pre-built model.Result JSON file so
// the TUI can be exercised manually end to end. Flag parsing, profile
// selection, and running real checks land in later milestones
// (spec §9.1, §11 M2-M4).
func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: wifisec <result.json>")
		os.Exit(1)
	}
	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "read result:", err)
		os.Exit(1)
	}
	var result model.Result
	if err := json.Unmarshal(data, &result); err != nil {
		fmt.Fprintln(os.Stderr, "parse result:", err)
		os.Exit(1)
	}
	if _, err := tea.NewProgram(tui.New(result)).Run(); err != nil {
		fmt.Fprintln(os.Stderr, "tui error:", err)
		os.Exit(1)
	}
}
