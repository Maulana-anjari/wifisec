package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/Maulana-anjari/wifisec/internal/model"
)

func TestTabCyclesThroughAllFourScreens(t *testing.T) {
	m := New(model.Result{})
	if m.screen != ScreenVerdict {
		t.Fatalf("expected initial screen to be ScreenVerdict, got %v", m.screen)
	}
	wantOrder := []Screen{ScreenFindings, ScreenDetail, ScreenLive, ScreenVerdict}
	for _, want := range wantOrder {
		next, _ := m.Update(tea.KeyMsg{Type: tea.KeyTab})
		m = next.(Model)
		if m.screen != want {
			t.Fatalf("after tab, screen = %v, want %v", m.screen, want)
		}
	}
}

func TestQuitKeySetsQuittingAndReturnsQuitCmd(t *testing.T) {
	m := New(model.Result{})
	next, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("q")})
	m = next.(Model)
	if !m.quitting {
		t.Error("expected quitting to be true after 'q'")
	}
	if cmd == nil {
		t.Error("expected a non-nil tea.Cmd (tea.Quit) after 'q'")
	}
}

func TestViewRendersHeaderWithProfileGlyphAndPacketCount(t *testing.T) {
	r := model.Result{
		Profile: model.ProfileStandard,
		Checks:  []model.Check{{PacketsSent: 3}, {PacketsSent: 2}},
	}
	m := New(r)
	next, _ := m.Update(tea.WindowSizeMsg{Width: 100, Height: 40})
	m = next.(Model)
	out := m.View()
	if !strings.Contains(out, ProfileGlyph(model.ProfileStandard)) {
		t.Errorf("expected profile glyph in header, got:\n%s", out)
	}
	if !strings.Contains(out, "5") {
		t.Errorf("expected total packet count (5) in header, got:\n%s", out)
	}
}
