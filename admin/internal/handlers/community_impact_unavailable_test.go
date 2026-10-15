package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// After a 30-day scan failed (its budget ran out on a large database) the
// Community Bans page shows an em dash that says why, not the "computing…"
// spinner, and the poll endpoint tells the page to stop polling: on such a
// database the page sat on the spinner for good while every poll started the
// scan over.
func TestCommunityBansImpactUnavailableAfterAFailedScan(t *testing.T) {
	h := newTestHandler(t)
	h.communityHits.mu.Lock()
	h.communityHits.failedAt = time.Now()
	h.communityHits.mu.Unlock()

	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/api/community-bans/impact", nil)
	rr := httptest.NewRecorder()
	h.AdminCommunityBansImpact(rr, req)
	var body struct {
		Known       bool `json:"known"`
		Computing   bool `json:"computing"`
		Unavailable bool `json:"unavailable"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid JSON: %v (%s)", err, rr.Body.String())
	}
	if body.Known || body.Computing || !body.Unavailable {
		t.Fatalf("after a failed scan the poll must answer unavailable, got %s", rr.Body.String())
	}
	if h.communityHits.Refreshing() {
		t.Fatal("the poll re-dispatched the scan inside the retry window")
	}

	req = httptest.NewRequest(http.MethodGet, "/unmask/admin/bans/community/", nil)
	req.Header.Set("Accept-Language", "en")
	rr = httptest.NewRecorder()
	h.AdminCommunityBansIndex(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("page: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	page := rr.Body.String()
	if !strings.Contains(page, `class="impact-num impact-unavailable"`) {
		t.Error("the page does not show the unavailable em dash")
	}
	if !strings.Contains(page, "did not finish within its two-minute budget") {
		t.Error("the em dash does not carry the reason")
	}
	if strings.Contains(page, `class="impact-num impact-computing"`) || strings.Contains(page, `data-computing="1"`) {
		t.Error("the page still shows the computing spinner (and would poll)")
	}
}
