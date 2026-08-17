// Package guard enforces profile packet limits (spec §5.1) — the
// second layer of defense after registry.Filter's profile-based
// check exclusion.
package guard

import (
	"fmt"
	"sync"
)

type PacketCounter struct {
	mu      sync.Mutex
	total   int
	byCheck map[string]int
	limit   int
}

// NewPacketCounter creates a counter enforcing the given packet limit
// (0 for the passive profile — spec §5.1: "limit adalah 0, sehingga
// panggilan Add apa pun mengembalikan error").
func NewPacketCounter(limit int) *PacketCounter {
	return &PacketCounter{byCheck: make(map[string]int), limit: limit}
}

// Add records n packets sent by checkID. It returns an error without
// applying any part of the increment if doing so would exceed the
// active profile's limit.
func (c *PacketCounter) Add(checkID string, n int) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.total+n > c.limit {
		return fmt.Errorf("guard: packet limit exceeded (limit %d, attempted +%d from %s, current total %d)", c.limit, n, checkID, c.total)
	}
	c.total += n
	c.byCheck[checkID] += n
	return nil
}

func (c *PacketCounter) Total() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.total
}
