package tui

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/Maulana-anjari/wifisec/internal/model"
)

var update = flag.Bool("update", false, "regenerate golden files")

// TestRenderFixturesGolden is T5 (spec §8.1): every fixture is
// rendered on every screen and compared against a checked-in golden
// file. No network access happens anywhere in this test.
func TestRenderFixturesGolden(t *testing.T) {
	fixtures, err := filepath.Glob(filepath.Join("..", "..", "testdata", "fixtures", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(fixtures) == 0 {
		t.Fatal("no fixtures found under testdata/fixtures")
	}

	screens := []struct {
		name   string
		screen Screen
	}{
		{"verdict", ScreenVerdict},
		{"findings", ScreenFindings},
		{"detail", ScreenDetail},
		{"live", ScreenLive},
	}

	for _, path := range fixtures {
		path := path
		name := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))

		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var result model.Result
		if err := json.Unmarshal(data, &result); err != nil {
			t.Fatalf("%s: %v", path, err)
		}

		for _, sc := range screens {
			sc := sc
			t.Run(name+"/"+sc.name, func(t *testing.T) {
				m := New(result)
				next, _ := m.Update(tea.WindowSizeMsg{Width: 100, Height: 40})
				m = next.(Model)
				m = gotoScreen(m, sc.screen)
				got := m.View()

				goldenPath := filepath.Join("..", "..", "testdata", "golden", name+"."+sc.name+".golden")
				if *update {
					if err := os.MkdirAll(filepath.Dir(goldenPath), 0o755); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(goldenPath, []byte(got), 0o644); err != nil {
						t.Fatal(err)
					}
				}

				want, err := os.ReadFile(goldenPath)
				if err != nil {
					t.Fatalf("missing golden file %s (run with -update to create it): %v", goldenPath, err)
				}
				if got != string(want) {
					t.Errorf("golden mismatch for %s/%s\n--- got ---\n%s\n--- want ---\n%s", name, sc.name, got, want)
				}
			})
		}
	}
}

func gotoScreen(m Model, target Screen) Model {
	for i := 0; i < int(target); i++ {
		next, _ := m.Update(tea.KeyMsg{Type: tea.KeyTab})
		m = next.(Model)
	}
	return m
}
