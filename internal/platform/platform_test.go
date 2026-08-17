package platform

import "testing"

func TestNewReturnsNonNilAdapter(t *testing.T) {
	a := New()
	if a == nil {
		t.Fatal("New() returned nil")
	}
}
