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
}

// TestRetentionTabRendersUnknownAsQQ: the retention tab renders the current-size
// line even when a metric could not be read, showing "??" for the unknown value
// (here the cookie-minute count, whose table is absent in the test schema, takes
// the same query-error -> "??" path a real timeout takes) while a readable
// metric (the empty events table) shows its number.
func TestRetentionTabRendersUnknownAsQQ(t *testing.T) {
	h := newTestHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/settings/?tab=retention", nil)
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
