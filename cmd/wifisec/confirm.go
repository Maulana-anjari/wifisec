package main

import (
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/Maulana-anjari/wifisec/internal/guard"
	"github.com/Maulana-anjari/wifisec/internal/model"
	"github.com/Maulana-anjari/wifisec/internal/tui"
)

// confirmModel is a small, standalone bubbletea program that walks
// the user through the confirmation steps guard.Resolve computed
// (spec G2/G3/G5). It is deliberately NOT part of internal/tui.Model —
// it runs to completion before tui.New(result) is ever called, so
// internal/tui never needs to import guard.
type confirmModel struct {
	steps   []guard.ConfirmStep
	stepIdx int
	dialog  tui.ProfileDialog
	done    bool
	aborted bool
}

func newConfirmModel(target model.Profile, knownNetwork bool, steps []guard.ConfirmStep) confirmModel {
	return confirmModel{
		steps:  steps,
		dialog: tui.ProfileDialog{Target: target, KnownNetwork: knownNetwork},
	}
}

func (m confirmModel) Init() tea.Cmd { return nil }

func (m confirmModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	keyMsg, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}
	switch keyMsg.Type {
	case tea.KeyEsc, tea.KeyCtrlC:
		m.aborted = true
		return m, tea.Quit
	case tea.KeyEnter:
		if m.dialog.Confirmed() {
			m.stepIdx++
			if m.stepIdx >= len(m.steps) {
				m.done = true
				return m, tea.Quit
			}
			m.dialog.Typed = ""
		}
		return m, nil
	case tea.KeyBackspace:
		if len(m.dialog.Typed) > 0 {
			m.dialog.Typed = m.dialog.Typed[:len(m.dialog.Typed)-1]
		}
		return m, nil
	case tea.KeyRunes:
		m.dialog.Typed += string(keyMsg.Runes)
		return m, nil
	}
	return m, nil
}

func (m confirmModel) View() string {
	if len(m.steps) == 0 {
		return ""
	}
	if m.done {
		return ""
	}
	var warning string
	if m.steps[m.stepIdx] == guard.ConfirmFullUnknown {
		warning = "Jaringan ini tidak ada di whitelist Anda — konfirmasi kedua diperlukan.\n\n"
	}
	return warning + m.dialog.View() + "\n(Enter untuk konfirmasi, Esc untuk batal)\n"
}

// Result reports whether every confirmation step was completed
// without the user aborting.
func (m confirmModel) Result() bool {
	return m.done && !m.aborted
}

// runConfirm runs the confirmation program to completion and reports
// whether the user completed every step. It never returns an error —
// an unreadable terminal or a bubbletea failure is treated the same
// as an abort, since proceeding without confirmation is never safe.
func runConfirm(target model.Profile, knownNetwork bool, steps []guard.ConfirmStep) bool {
	if len(steps) == 0 {
		return true
	}
	p := tea.NewProgram(newConfirmModel(target, knownNetwork, steps))
	final, err := p.Run()
	if err != nil {
		fmt.Fprintln(os.Stderr, "confirmation aborted:", err)
		return false
	}
	return final.(confirmModel).Result()
}
