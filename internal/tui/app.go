package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/Maulana-anjari/wifisec/internal/model"
)

type Screen int

const (
	ScreenVerdict Screen = iota
	ScreenFindings
	ScreenDetail
	ScreenLive
	screenCount
)

// Model is the top-level bubbletea model. It only imports internal/model
// (spec §3.1: tui only imports model).
type Model struct {
	result       model.Result
	screen       Screen
	width        int
	findingIndex int
	checkIndex   int
	quitting     bool
}

// New builds a Model that renders the given result, starting on the
// verdict screen (spec §9.3).
func New(result model.Result) Model {
	return Model{result: result, screen: ScreenVerdict}
}

func (m Model) Init() tea.Cmd { return nil }

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		return m, nil
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			m.quitting = true
			return m, tea.Quit
		case "tab", "right":
			m.screen = (m.screen + 1) % screenCount
			return m, nil
		case "shift+tab", "left":
			m.screen = (m.screen + screenCount - 1) % screenCount
			return m, nil
		case "down", "j":
			m.moveSelection(1)
			return m, nil
		case "up", "k":
			m.moveSelection(-1)
			return m, nil
		case "enter":
			if m.screen == ScreenFindings {
				m.screen = ScreenDetail
			}
			return m, nil
		}
	}
	return m, nil
}

func (m Model) View() string {
	if m.quitting {
		return ""
	}
	var b strings.Builder
	b.WriteString(m.renderHeader())
	b.WriteString("\n")
	switch m.screen {
	case ScreenVerdict:
		b.WriteString(renderVerdictScreen(m.result, m.width))
	case ScreenFindings:
		b.WriteString(renderFindingsScreen(m.result, m.findingIndex, m.width))
	case ScreenDetail:
		b.WriteString(renderDetailScreen(m.result, m.checkIndex, m.width))
	case ScreenLive:
		b.WriteString(renderLiveScreen(m.result, m.width))
	}
	return b.String()
}

func (m Model) renderHeader() string {
	glyph := ProfileGlyph(m.result.Profile)
	return fmt.Sprintf("wifisec  %s %s  paket:%d  %s",
		glyph, m.result.Profile, totalPackets(m.result.Checks), m.result.StartedAt.Format("15:04:05"))
}

func totalPackets(checks []model.Check) int {
	total := 0
	for _, c := range checks {
		total += c.PacketsSent
	}
	return total
}

func (m *Model) moveSelection(delta int) {
	switch m.screen {
	case ScreenFindings:
		n := len(m.result.Findings)
		if n == 0 {
			return
		}
		m.findingIndex = clampIndex(m.findingIndex+delta, n)
	case ScreenDetail:
		n := len(m.result.Checks)
		if n == 0 {
			return
		}
		m.checkIndex = clampIndex(m.checkIndex+delta, n)
	}
}

func clampIndex(i, n int) int {
	if i < 0 {
		return 0
	}
	if i >= n {
		return n - 1
	}
	return i
}
