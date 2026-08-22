package handlers

import "testing"

// The residue segment promises its own breakdown, and the promise is
// arithmetic: abandons + unchallenged + passthrough + re-bound + skew must add
// up to what the segment shows.  Skew is the balance, so it is what absorbs a
// component someone forgets to subtract -- which reads as "counting noise"
// when it is really a whole category filed under the wrong name.
//
// Re-bound passes moved into this residue rather than carrying a segment of
// their own: in production they are a low single-digit share of a day on the
// busiest node and nothing at all on several others, and a bar segment
// invisible on most installs
// teaches the eye to skip the card.  They must still be NAMED here, because
// the one thing they must never be is silently part of the human share again.
func TestResidueBreakdownAddsUp(t *testing.T) {
	// The handler's arithmetic, isolated: other = total - the named shares,
	// and skew = other - the named components of the residue.
	const (
		total       = 1000
		benign      = 100
		blocked     = 50
		bypassed    = 30
		human       = 700
		abandon     = 40
		unchall     = 20
		passthrough = 15
		rebound     = 25
	)
	other := total - benign - blocked - bypassed - human
	skew := other - abandon - unchall - passthrough - rebound

	if other != 120 {
		t.Fatalf("other = %d, want 120 (the re-bound share belongs inside it now)", other)
	}
	if skew != 20 {
		t.Errorf("skew = %d, want 20; a component left unsubtracted hides inside skew", skew)
	}
	// And the whole card still sums to the total, which is the invariant the
	// composition exists to keep.
	sum := benign + blocked + bypassed + human + other
	if sum != total {
		t.Fatalf("segments sum to %d, not %d", sum, total)
	}
}
