package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestRetentionStatsPerMetricOK: a successful query marks the metric known; a
// cancelled context (the real-world timeout) marks the metrics unknown AND sets
// TimedOut, so the template can render "??" for exactly the values it could not
// read instead of a misleading 0.
func TestRetentionStatsPerMetricOK(t *testing.T) {
	h := newTestHandler(t)

	// Healthy path: the unmask_event table exists and is empty -> the count /
	// oldest are known (and zero), not "??".
	ok := h.retentionStats(context.Background(), time.UTC)
	if !ok.EventsRowsOK {
		t.Error("events count over a live empty table must be known")
	}
	if ok.EventsRows != 0 {
		t.Errorf("empty table events rows = %d, want 0", ok.EventsRows)
	}
	if ok.TimedOut {
		t.Error("a healthy query must not set TimedOut")
	}

	// Timeout path: an already-cancelled context fails every query with
	// context.Canceled -> metrics unknown + TimedOut set.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	to := h.retentionStats(ctx, time.UTC)
	if to.EventsRowsOK || to.EventsOldestOK {
		t.Error("a cancelled context must leave the event metrics unknown (rendered ??)")
	}
	if !to.TimedOut {
		t.Error("a cancelled context must set TimedOut")
	}
	// The banner lands on the card whose numbers are missing: every section
	// failed here, so both per-card flags are up.  (A cookie_minute-only
	// timeout used to put its banner on the events-prune card.)
	if !to.EventsTimedOut || !to.CookieTimedOut {
		t.Errorf("per-card flags after a full timeout: events=%v cookie=%v, want both true",
			to.EventsTimedOut, to.CookieTimedOut)
	}
	if ok.EventsTimedOut || ok.CookieTimedOut {
		t.Error("healthy queries must not raise the per-card timeout flags")
	}
}

// TestRetentionCookieMinuteRowEstimate: the nginx-log card's row count is the
// same O(1) endpoint estimate the events card uses (sqlite: rowid range), not
// a full COUNT(*) — a 25-day window's millions of rows outran the query budget on a
// modest host.  Dense after an oldest-first prune; flagged approximate.
func TestRetentionCookieMinuteRowEstimate(t *testing.T) {
	h := newTestHandler(t)
	// The shared test schema omits this table on purpose (the "??" test
	// leans on its absence); create the production shape here.
	if _, err := h.DB.Exec(`CREATE TABLE unmask_cookie_minute (
		bucket_min INTEGER NOT NULL, site VARCHAR(64) NOT NULL,
		kind VARCHAR(32) NOT NULL, cnt INTEGER NOT NULL DEFAULT 0,
		PRIMARY KEY (bucket_min, site, kind))`); err != nil {
		t.Fatal(err)
	}
	ins := func(bucket int) {
		if _, err := h.DB.Exec(
			`INSERT INTO unmask_cookie_minute (bucket_min, site, kind, cnt) VALUES (?, 'default', 'total', 1)`, bucket); err != nil {
			t.Fatal(err)
		}
	}
	for b := 100; b < 105; b++ {
		ins(b)
	}
	// Oldest-first prune (buckets 100,101 gone) leaves a dense rowid range of 3.
	if _, err := h.DB.Exec(`DELETE FROM unmask_cookie_minute WHERE bucket_min < 102`); err != nil {
		t.Fatal(err)
	}
	v := h.retentionStats(context.Background(), time.UTC)
	if !v.CookieMinuteRowsOK || !v.CookieMinuteRowsApprox {
		t.Fatalf("want OK+approx, got OK=%v approx=%v", v.CookieMinuteRowsOK, v.CookieMinuteRowsApprox)
	}
	if v.CookieMinuteRows != 3 {
		t.Errorf("dense rowid estimate = %d, want 3", v.CookieMinuteRows)
	}
	// An upsert that lands on UPDATE allocates no rowid, so the estimate
	// does not drift when counters increment.
	if _, err := h.DB.Exec(
		`INSERT INTO unmask_cookie_minute (bucket_min, site, kind, cnt) VALUES (104, 'default', 'total', 1)
		 ON CONFLICT(bucket_min, site, kind) DO UPDATE SET cnt = cnt + 1`); err != nil {
		t.Fatal(err)
	}
	if v := h.retentionStats(context.Background(), time.UTC); v.CookieMinuteRows != 3 {
		t.Errorf("estimate after an upsert-update = %d, want 3", v.CookieMinuteRows)
	}
}

// TestRetentionTimeoutFlagIsPerCard: the banner flags are per card, and only a
// deadline raises them.  A plain query error (here: unmask_cookie_minute
// dropped) marks the metric unknown ("??") but must not raise ANY timeout
// banner -- and must not touch the other card, whose metrics stay readable.
func TestRetentionTimeoutFlagIsPerCard(t *testing.T) {
	h := newTestHandler(t)
	if _, err := h.DB.Exec(`DROP TABLE IF EXISTS unmask_cookie_minute`); err != nil {
		t.Fatal(err)
	}
	v := h.retentionStats(context.Background(), time.UTC)
	if v.CookieMinuteRowsOK {
		t.Error("count over a missing table must be unknown")
	}
	if v.TimedOut || v.EventsTimedOut || v.CookieTimedOut {
		t.Errorf("a plain query error is not a timeout: TimedOut=%v events=%v cookie=%v",
			v.TimedOut, v.EventsTimedOut, v.CookieTimedOut)
	}
	if !v.EventsRowsOK {
		t.Error("the events card's metrics must stay readable")
	}
}

// TestRetentionStatsRowEstimate: the event row count is the O(1) id-range
// estimate (MAX(id)-MIN(id)+1), not a full COUNT(*).  It stays near-exact after
// oldest-first pruning (a dense range) and is flagged approximate.
func TestRetentionStatsRowEstimate(t *testing.T) {
	h := newTestHandler(t)
	ins := func(id int) {
		if _, err := h.DB.Exec(
			`INSERT INTO unmask_event (id, ip_address, phase, date_created) VALUES (?, x'7f000001', 'access', '2026-01-01 00:00:00')`, id); err != nil {
			t.Fatal(err)
		}
	}
	for id := 1; id <= 5; id++ {
		ins(id)
	}
	// Oldest-first prune (ids 1,2 gone) leaves a dense range 3..5 -> estimate 3,
	// which is exact.
	if _, err := h.DB.Exec(`DELETE FROM unmask_event WHERE id IN (1,2)`); err != nil {
		t.Fatal(err)
	}
	v := h.retentionStats(context.Background(), time.UTC)
	if !v.EventsRowsOK || !v.EventsRowsApprox {
		t.Fatalf("want OK+approx, got OK=%v approx=%v", v.EventsRowsOK, v.EventsRowsApprox)
	}
	if v.EventsRows != 3 { // MAX(5)-MIN(3)+1
		t.Errorf("dense range estimate = %d, want 3", v.EventsRows)
	}
	// A middle gap makes it a (small) OVERESTIMATE — the accepted trade for O(1):
	// deleting id 4 leaves {3,5} (2 rows) but the id range still spans 3..5 = 3.
	if _, err := h.DB.Exec(`DELETE FROM unmask_event WHERE id = 4`); err != nil {
		t.Fatal(err)
	}
	if v := h.retentionStats(context.Background(), time.UTC); v.EventsRows != 3 {
		t.Errorf("id-range estimate after a middle gap = %d, want 3 (range 3..5)", v.EventsRows)
	}
}

// TestRetentionTabRendersUnknownAsQQ: the retention tab renders the current-size
// line even when a metric could not be read, showing "??" for the unknown value
// (here the cookie-minute count, whose table is absent in the test schema, takes
// the same query-error -> "??" path a real timeout takes) while a readable
// metric (the empty events table) shows its number.
func TestRetentionTabRendersUnknownAsQQ(t *testing.T) {
	h := newTestHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/settings/?tab=retention", nil)
	req.SetPathValue("tab", "retention")
	rr := httptest.NewRecorder()
	h.AdminSettingsIndex(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	// The unreadable metric renders "??" with the explanatory title.
	if !strings.Contains(body, `>??<`) {
		t.Error("an unreadable retention metric must render ?? rather than being hidden")
	}
	// The line is always present now (no hide-on-zero), and the page closes.
	if !strings.Contains(body, "</html>") {
		t.Error("retention tab render truncated")
	}
}
