package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The rendered row, not the class name on its own: the stylesheet mentions the
// class too, so matching that alone is true on every page.
const rankNotice = `<tr class="rank-unavailable">`

// A ranking that could not be read must not look like a window with no traffic.
//
// The hunt page ran four aggregate scans with the request context and threw
// their errors away, so a failed query rendered an empty table -- the same
// thing the page shows when nothing happened.  For someone hunting a bot those
// are opposite answers, and the page picked the reassuring one.
//
// Two halves, and the second is what makes the first worth having: the failure
// has to be visible, and a genuinely empty window must stay quiet.  A page that
// cries wolf on every quiet hour teaches the operator to ignore the notice.
func TestHuntRankingFailureIsVisibleAndEmptyIsNot(t *testing.T) {
	h := newTestHandler(t)
	cur := h.snapshotSettings()
	cur.Server.BasePath = "/unmask"
	h.SetSettings(cur)

	render := func() string {
		r := httptest.NewRequest(http.MethodGet, "/unmask/admin/hunt/?range=1h", nil)
		rr := httptest.NewRecorder()
		h.AdminHuntIndex(rr, r)
		if rr.Code != http.StatusOK {
			t.Fatalf("status %d", rr.Code)
		}
		return rr.Body.String()
	}

	// (a) A database with no events at all: every ranking is legitimately
	// empty, and the page must say nothing about it.
	quiet := render()
	if strings.Contains(quiet, rankNotice) {
		t.Error("an empty window was reported as a failed lookup")
	}

	// (b) The rankings, and only the rankings, run out of time -- the real
	// failure, reproduced without making the test slow.
	orig := rankQueryTimeout
	rankQueryTimeout = time.Nanosecond
	broken := render()
	rankQueryTimeout = orig
	if !strings.Contains(broken, rankNotice) {
		t.Error("a ranking that could not be read rendered as an ordinary empty table")
	}
	// The notice has to say it is missing rather than zero, or it explains
	// nothing an empty table did not already imply.
	if !strings.Contains(broken, "0 件という意味ではありません") &&
		!strings.Contains(broken, "not empty") {
		t.Error("the notice does not distinguish missing from zero")
	}

	if again := render(); strings.Contains(again, rankNotice) {
		t.Error("the notice stuck around after the rankings could be read again")
	}
}
