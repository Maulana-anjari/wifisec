package whitelist

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPathUsesXDGConfigHome(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "/tmp/wifisec-xdg-test")
	got, err := Path()
	if err != nil {
		t.Fatalf("Path() error: %v", err)
	}
	want := "/tmp/wifisec-xdg-test/wifisec/known_networks.yaml"
	if got != want {
		t.Errorf("Path() = %q, want %q", got, want)
	}
}

func TestPathFallsBackToHomeConfigWhenXDGUnset(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "")
	home := t.TempDir()
	t.Setenv("HOME", home)
	got, err := Path()
	if err != nil {
		t.Fatalf("Path() error: %v", err)
	}
	want := filepath.Join(home, ".config", "wifisec", "known_networks.yaml")
	if got != want {
		t.Errorf("Path() = %q, want %q", got, want)
	}
}

func TestLoadMissingFileReturnsEmptyList(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	l, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if len(l.Networks) != 0 {
		t.Errorf("expected empty list for missing file, got %d entries", len(l.Networks))
	}
}

func TestAddThenContains(t *testing.T) {
	l := &List{}
	if l.Contains("sha256:abc") {
		t.Fatal("empty list should not contain anything")
	}
	l.Add("sha256:abc", "home")
	if !l.Contains("sha256:abc") {
		t.Error("expected list to contain the added hash")
	}
}

func TestAddIsIdempotent(t *testing.T) {
	l := &List{}
	l.Add("sha256:abc", "home")
	l.Add("sha256:abc", "home again")
	if len(l.Networks) != 1 {
		t.Errorf("expected 1 entry after adding the same hash twice, got %d", len(l.Networks))
	}
}

func TestSaveThenLoadRoundTrips(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	l := &List{}
	l.Add("sha256:home-network", "rumah")
	if err := l.Save(); err != nil {
		t.Fatalf("Save() error: %v", err)
	}

	path, _ := Path()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected file at %s: %v", path, err)
	}

	loaded, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if !loaded.Contains("sha256:home-network") {
		t.Error("round-tripped list should contain the saved hash")
	}
}
