package handlers

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"
)

// The KPI row is the challenge's funnel and its operating state, counted in
// requests throughout: the abandonment tile shows how many requests loaded a
// challenge and left, with the share and its denominator underneath, so no
// tile in the row is a bare percentage.  The row says what it is a breakdown
// of, because the card above it splits all traffic by what it is and counts
// some of the same requests under other names.
func TestOverviewKPIRowIsRequestsAndSaysWhatItCovers(t *testing.T) {
	h := newTestHandler(t)
	s := h.snapshotSettings()
	s.Server.BasePath = "/unmask"
	h.SetSettings(s)
	when := time.Now().UTC().Add(-time.Hour).Format("2006-01-02 15:04:05.000")
	// The tile counts plain transparent PoW only: no rule forced the
	// challenge, and the chain is pow_only (countUnruledPoW).
	seed := func(phase string, n int) {
		for i := 0; i < n; i++ {
			if _, err := h.DB.Exec(`INSERT INTO unmask_event (site, host, ip_address, phase, payload_json, date_created)
				VALUES ('', '', X'0a000001', ?, '{"chmode":"pow_only"}', ?)`, phase, when); err != nil {
				t.Fatal(err)
			}
		}
	}
	// Ten challenges whose JS ran, three of them abandoned.
	seed("load", 10)
	seed("abandon", 3)

	rr := httptest.NewRecorder()
	h.AdminTopOverview(rr, httptest.NewRequest(http.MethodGet, "/unmask/admin/", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("overview: %d", rr.Code)
	}
	body := rr.Body.String()

	if !strings.Contains(body, `class="meta kpi-note"`) {
		t.Error("the row must say what it is a breakdown of")
	}
	// The abandonment tile: a count on top, the share and denominator below.
	re := regexp.MustCompile(`(?s)<div class="label">離脱<span.*?<div class="value">([^<]*)</div>\s*<div class="sub">([^<]*)</div>`)
	m := re.FindStringSubmatch(body)
	if m == nil {
		t.Fatal("the abandonment tile is not on the page")
	}
	value, sub := strings.TrimSpace(m[1]), strings.TrimSpace(m[2])
	if value != "3" {
		t.Errorf("the tile's headline must be the request count, got %q", value)
	}
	if strings.Contains(value, "%") {
		t.Errorf("no tile in this row is a bare percentage, got %q", value)
	}
	if !strings.Contains(sub, "10") || !strings.Contains(sub, "30.0") || !strings.Contains(sub, "%") {
		t.Errorf("the line below must carry the denominator and the share, got %q", sub)
	}
}
