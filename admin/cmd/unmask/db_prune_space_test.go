package main

import "testing"

// The room a step needs is what it writes plus a margin; a filesystem with
// exactly that much is short.
func TestSpaceShort(t *testing.T) {
	const need = 1000
	if spaceWithMargin(need) != 1100 {
		t.Errorf("margin: %d", spaceWithMargin(need))
	}
	for _, c := range []struct {
		free  int64
		short bool
	}{
		{1000, true},
		{1099, true},
		{1100, false},
		{5000, false},
	} {
		if got := spaceShort(need, c.free); got != c.short {
			t.Errorf("spaceShort(%d, %d) = %v, want %v", need, c.free, got, c.short)
		}
	}
}
