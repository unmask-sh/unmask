package handlers

import (
	"fmt"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/events"
)

// Rows arrive newest-first.  Build a run of sessions, each `perSession` rows
// long, so row i belongs to session i/perSession.
func sessionRows(n, perSession int) []events.Row {
	out := make([]events.Row, n)
	for i := range out {
		out[i] = events.Row{BeaconToken: fmt.Sprintf("s%02d", i/perSession)}
	}
	return out
}

func tokensOf(rows []events.Row) map[string]int {
	m := map[string]int{}
	for _, r := range rows {
		m[r.BeaconToken]++
	}
	return m
}

// The page window cuts through sessions at both edges.  The page must show the
// sessions whose newest row is inside the window -- whole, reaching outside for
// the missing rows -- and must not show the neighbours' sessions at all.  Get
// the ownership rule wrong in the obvious way (keep every session that touches
// the window) and the boundary sessions render on both pages.
func TestOwnedSessionRowsCompletesWithoutDuplicating(t *testing.T) {
	const per, pageSize, bleed = 3, 9, 8
	// 30 rows = sessions s00..s09, window is rows [8, 17) so it starts and
	// ends mid-session.
	all := sessionRows(30, per)
	owned, hasMore := ownedSessionRows(all, bleed, pageSize)

	got := tokensOf(owned)
	// Window rows 8..16 touch s02 (rows 6-8), s03, s04, s05 (rows 15-17).
	// Newest row of s02 is row 6 -- before the window -- so the previous page
	// owns it.  s05's newest row is 15, inside, so this page owns it.
	for _, tok := range []string{"s03", "s04", "s05"} {
		if got[tok] != per {
			t.Errorf("%s: got %d rows, want all %d (the session is cut across the page edge)", tok, got[tok], per)
		}
	}
	if got["s02"] != 0 {
		t.Errorf("s02 belongs to the previous page (its newest row is outside the window), got %d rows", got["s02"])
	}
	if !hasMore {
		t.Error("hasMore must be true while rows remain past the window")
	}
}

// Two adjacent pages must partition the sessions: every session appears on
// exactly one of them, and no row is dropped.  This is the property the naive
// "fetch a few extra rows" version breaks.
func TestAdjacentPagesPartitionSessions(t *testing.T) {
	const per, pageSize, bleed = 3, 9, 8
	all := sessionRows(60, per) // s00..s19

	// Page at offset 9: window is rows [9,18) of the DB, which in a bled read
	// starting at 9-bleed sits at index `bleed`.
	pageA, _ := ownedSessionRows(all[1:], bleed, pageSize) // read from row 1
	// Next page at offset 18: bled read starts at 10, so its window is at
	// index bleed again.
	pageB, _ := ownedSessionRows(all[10:], bleed, pageSize)

	a, b := tokensOf(pageA), tokensOf(pageB)
	for tok := range a {
		if b[tok] > 0 {
			t.Errorf("%s appears on both pages -- the operator sees it twice", tok)
		}
	}
	for tok, n := range a {
		if n != per {
			t.Errorf("page A shows %s with %d/%d rows", tok, n, per)
		}
	}
	for tok, n := range b {
		if n != per {
			t.Errorf("page B shows %s with %d/%d rows", tok, n, per)
		}
	}
}

// Rows with no beacon token (forward-auth `check`, anything from before the
// token existed) are a session of one: in when the row is in the window, out
// otherwise.  They must not be pulled in from the bleed.
func TestOwnedSessionRowsKeepsTokenlessRowsInsideTheWindow(t *testing.T) {
	rows := make([]events.Row, 12)
	for i := range rows {
		rows[i] = events.Row{} // no token
	}
	owned, _ := ownedSessionRows(rows, 4, 5)
	if len(owned) != 5 {
		t.Errorf("tokenless rows: got %d, want exactly the 5 in the window", len(owned))
	}
}

// The last page reads past nothing, so the pager must not offer a next page.
func TestOwnedSessionRowsReportsTheEndOfTheLog(t *testing.T) {
	all := sessionRows(12, 3)
	_, hasMore := ownedSessionRows(all, 4, 100) // window covers the rest
	if hasMore {
		t.Error("hasMore must be false once the window reaches the end of the rows")
	}
}
