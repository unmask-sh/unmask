package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A 30-day card whose query failed must not render as a zero with an
// empty-state hint that sends the operator to check their nginx include:
// the figures are unknown, so the strip shows a dash and the card says in
// place that its query errored.  The harness has no aggregate tables, so
// DailyPassByDay fails here the way it would on a locked or broken
// database.
func TestStatsFailedCardShowsDashNotZero(t *testing.T) {
	h := newTestHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/stats/default/?range=24h", nil)
	req.SetPathValue("site", "default")
	rr := httptest.NewRecorder()
	h.AdminStats(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("stats page status %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "DailyPassByDay") {
		t.Skip("DailyPassByDay did not fail in this harness; the dash rendering has nothing to check")
	}
	// The banner names it.
	if !strings.Contains(body, "読み込めませんでした") {
		t.Error("the page must say the card could not be loaded")
	}
	// The 30-day strip: five dashes, no zero that reads as a real count.
	i := strings.Index(body, `id="chart"`)
	if i < 0 {
		t.Fatal("30-day card not on the page")
	}
	strip := body[:i]
	if k := strings.LastIndex(strip, "font-size:1.4rem"); k > 0 {
		strip = strip[k-2000:]
	}
	if n := strings.Count(strip, ">—<"); n < 5 {
		t.Errorf("the 30-day figures must render as dashes when their card failed, got %d dash(es)", n)
	}
	// And the empty-state hint that blames the nginx include must not appear.
	if strings.Contains(body, "include していない") || strings.Contains(body, "may be missing") {
		t.Error("a failed card must not show the no-access-log hint: the data was not fetched, not absent")
	}
	if !strings.Contains(body, `class="muted card-failed"`) {
		t.Error("the card must say in place that its query failed")
	}
}

// A request the client abandoned mid-page is not a failure of any card: the
// response is discarded, so the handler renders nothing and marks nothing.
// (Every stats-card failure logged on the busiest node over three days was a
// client that went away while the last cards ran.)
func TestStatsClientGoneRendersNothing(t *testing.T) {
	h := newTestHandler(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/stats/default/?range=24h", nil).WithContext(ctx)
	req.SetPathValue("site", "default")
	rr := httptest.NewRecorder()
	h.AdminStats(rr, req)
	if rr.Body.Len() != 0 {
		t.Errorf("an abandoned request must render nothing, got %d bytes", rr.Body.Len())
	}
	if strings.Contains(rr.Body.String(), "読み込めませんでした") {
		t.Error("an abandoned request must not be reported as failed cards")
	}
}
