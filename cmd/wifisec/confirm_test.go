package main

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/Maulana-anjari/wifisec/internal/guard"
	"github.com/Maulana-anjari/wifisec/internal/model"
)

func TestConfirmModelTypingBuildsUpTyped(t *testing.T) {
	m := newConfirmModel(model.ProfileMinimal, true, []guard.ConfirmStep{guard.ConfirmRaise})
	for _, r := range "minimal" {
		updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
		m = updated.(confirmModel)
	}
	if m.dialog.Typed != "minimal" {
		t.Errorf("Typed = %q, want %q", m.dialog.Typed, "minimal")
	}
}

func TestConfirmModelBackspaceRemovesLastRune(t *testing.T) {
	m := newConfirmModel(model.ProfileMinimal, true, []guard.ConfirmStep{guard.ConfirmRaise})
	m.dialog.Typed = "minima"
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyBackspace})
	m = updated.(confirmModel)
	if m.dialog.Typed != "minim" {
		t.Errorf("Typed after backspace = %q, want %q", m.dialog.Typed, "minim")
	}
}

func TestConfirmModelEnterWithWrongTextDoesNotAdvance(t *testing.T) {
	m := newConfirmModel(model.ProfileMinimal, true, []guard.ConfirmStep{guard.ConfirmRaise})
	m.dialog.Typed = "wrong"
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(confirmModel)
	if m.done || m.aborted {
		t.Error("wrong text must not confirm or abort")
	}
	if m.stepIdx != 0 {
		t.Errorf("stepIdx = %d, want 0 (must not advance on wrong text)", m.stepIdx)
	}
}

func TestConfirmModelEnterWithRightTextAdvancesThenCompletes(t *testing.T) {
	m := newConfirmModel(model.ProfileMinimal, true, []guard.ConfirmStep{guard.ConfirmRaise})
	m.dialog.Typed = "minimal"
	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(confirmModel)
	if !m.done {
		t.Error("expected done=true after the only step is confirmed")
	}
	if cmd == nil {
		t.Error("expected a tea.Quit command once done")
	}
}

func TestConfirmModelTwoStepsRequiresBothConfirmations(t *testing.T) {
	m := newConfirmModel(model.ProfileFull, false, []guard.ConfirmStep{guard.ConfirmRaise, guard.ConfirmFullUnknown})
	m.dialog.Typed = "full"
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(confirmModel)
	if m.done {
		t.Fatal("must not be done after only the first of two steps")
	}
	if m.stepIdx != 1 {
		t.Fatalf("stepIdx = %d, want 1 after first step confirmed", m.stepIdx)
	}
	if m.dialog.Typed != "" {
		t.Errorf("Typed should reset between steps, got %q", m.dialog.Typed)
	}

	m.dialog.Typed = "full"
	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(confirmModel)
	if !m.done || cmd == nil {
		t.Error("expected done=true and tea.Quit after the second step is confirmed")
	}
}

func TestConfirmModelEscAborts(t *testing.T) {
	m := newConfirmModel(model.ProfileMinimal, true, []guard.ConfirmStep{guard.ConfirmRaise})
	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m = updated.(confirmModel)
	if !m.aborted || cmd == nil {
		t.Error("expected aborted=true and tea.Quit on Esc")
	}
}

func TestConfirmModelResultReflectsDoneNotAborted(t *testing.T) {
	m := newConfirmModel(model.ProfilePassive, true, nil)
	if m.Result() {
		t.Error("Result() should be false before done")
	}
	m.done = true
	if !m.Result() {
		t.Error("Result() should be true once done and not aborted")
	}
	m.aborted = true
	if m.Result() {
		t.Error("Result() should be false if aborted, even if done was set")
	}
}
