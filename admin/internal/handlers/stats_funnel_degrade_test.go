package handlers

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"
)

// A funnel that could not be read is one failed card, not a dead page.
//
// The stats page answered 500 when the funnel query failed, while every other
// card degrades to "could not load".  On a large install the funnel's raw 24h
// scan (after a restart, until the hourly rollup is ready; and on every site-
// or host-filtered view) cannot finish inside its budget, so the page was
// gone exactly when the operator wanted it.  It must render with the funnel
// named in the banner, and recover once the funnel can be read again.
func TestStatsPageSurvivesFunnelFailure(t *testing.T) {
	h := newTestHandler(t)
	render := func() (int, string) {
		req := httptest.NewRequest(http.MethodGet, "/unmask/admin/stats/default/?range=1h", nil)
		req.SetPathValue("site", "default")
		rr := httptest.NewRecorder()
		h.AdminStats(rr, req)
		return rr.Code, rr.Body.String()
	}

	// The banner lists the cards that could not be loaded, by name.  Other
	// cards fail in this harness too (it has no aggregate tables), so the
	// check is whether the funnel is among them, not whether the banner is up.
	failedCards := func(body string) string {
		m := regexp.MustCompile(`color:#b45309;font-size:\.76rem">([^<]*)</span>`).FindStringSubmatch(body)
		if m == nil {
			return ""
		}
		return m[1]
	}

	orig := funnelQueryTimeout
	funnelQueryTimeout = time.Nanosecond
	code, body := render()
	funnelQueryTimeout = orig
	if code != http.StatusOK {
		t.Fatalf("a failed funnel took the page down: status %d", code)
	}
	if list := failedCards(body); !strings.Contains(list, "funnel") {
		t.Errorf("the banner does not name the funnel as a card that could not be loaded: %q", list)
	}

	code, body = render()
	if code != http.StatusOK {
		t.Fatalf("status %d after the funnel could be read again", code)
	}
	if list := failedCards(body); strings.Contains(list, "funnel") {
		t.Errorf("the funnel is still reported as failed after it could be read again: %q", list)
	}
}
