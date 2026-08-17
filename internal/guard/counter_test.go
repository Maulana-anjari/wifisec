package guard

import "testing"

func TestPacketCounterAddAccumulates(t *testing.T) {
	c := NewPacketCounter(10)
	if err := c.Add("check.a", 3); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := c.Add("check.b", 4); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := c.Total(); got != 7 {
		t.Errorf("Total() = %d, want 7", got)
	}
}

func TestPacketCounterRejectsOverLimit(t *testing.T) {
	c := NewPacketCounter(5)
	if err := c.Add("check.a", 3); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := c.Add("check.b", 3); err == nil {
		t.Error("expected error when exceeding limit (3+3 > 5)")
	}
	if got := c.Total(); got != 3 {
		t.Errorf("Total() after rejected Add = %d, want 3 (rejected add must not partially apply)", got)
	}
}

func TestPacketCounterZeroLimitRejectsAnyPacket(t *testing.T) {
	c := NewPacketCounter(0)
	if err := c.Add("check.a", 1); err == nil {
		t.Error("expected error: passive profile (limit 0) must reject any packet (spec §5.1)")
	}
}
