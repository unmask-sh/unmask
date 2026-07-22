package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestHuntRankingSearchAndFilterHiding renders the bot-hunt page end to end
// (TestAdminTemplatesParse only parses it, so a data-dependent break slips
// through) and pins two ranking behaviours:
//
//   - each IP / JA4 / UA ranking row carries a 🔍 "filter raw log by this key"
//     link folded into the req column (ip= / ja4= / ua= search params);
//   - the whole ranking grid is hidden once a value filter is active, so a
//     narrowed search doesn't show rankings that ignore the filter.
//
// Markers use the attribute forms (class="..." href=, class="rank-grid") so the
// always-present <style> block (which also defines .req-search / .rank-grid)
// can't produce a false positive.
func TestHuntRankingSearchAndFilterHiding(t *testing.T) {
	h := newTestHandler(t)
	// One recent event so every ranking (IP / JA4 / UA) has a row to decorate.
	// datetime('now') lands inside the 1h window the rankings query bounds to.
	if _, err := h.DB.Exec(
		`INSERT INTO unmask_event (ip_address, ja4, user_agent, host, phase, date_created) ` +
			`VALUES (x'7f000001', 't13d1516h2_8daaf6152771_b186095e22b6', 'FakeBot/1.0', 'example.com', 'serve', datetime('now'))`,
	); err != nil {
		t.Fatalf("seed event: %v", err)
	}

	get := func(qs string) string {
		req := httptest.NewRequest(http.MethodGet, "/unmask/admin/hunt/"+qs, nil)
		rr := httptest.NewRecorder()
		h.AdminHuntIndex(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("GET %s: want 200, got %d\n%s", qs, rr.Code, rr.Body.String())
		}
		return rr.Body.String()
	}

	// No filter: rankings visible, req-search links present, UA filter input present.
	noFilter := get("?range=1h")
	if !strings.Contains(noFilter, `class="rank-grid"`) {
		t.Error("no-filter: <div class=\"rank-grid\"> must be visible")
	}
	if !strings.Contains(noFilter, `class="req-search" href=`) {
		t.Error("no-filter: req-search 🔍 anchor must render on ranking rows")
	}
	if !strings.Contains(noFilter, `name="ua"`) {
		t.Error("no-filter: UA filter input must be present")
	}
	for _, want := range []string{`&ip=`, `&ja4=`, `&ua=`} {
		if !strings.Contains(noFilter, want) {
			t.Errorf("no-filter: a req-search link is missing the %q search param", want)
		}
	}

	// Filter active: rankings hidden, but the filter bar (UA input) still shows.
	filtered := get("?range=1h&ip=127.0.0.1")
	if strings.Contains(filtered, `class="rank-grid"`) {
		t.Error("filtered: rank-grid must be hidden while a filter is active")
	}
	if !strings.Contains(filtered, `name="ua"`) {
		t.Error("filtered: UA filter input must still be present (filter bar stays)")
	}
}
