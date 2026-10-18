package handlers

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/i18n"
)

// The requests tile beside the composition card follows the card's
// denominator: with the bypassed requests out of it, the requests unmask
// judged and a second line naming what was left out; with them in, every
// request.  And a segment out of the denominator says "excluded" where its
// share was.
func TestRequestsTileFollowsTheScope(t *testing.T) {
	h := newTestHandler(t)
	s := h.snapshotSettings()
	s.Server.BasePath = "/unmask"
	h.SetSettings(s)
	const site = "example.com"
	if _, err := h.DB.Exec(`CREATE TABLE unmask_cookie_minute (
		bucket_min INTEGER NOT NULL, site VARCHAR(64) NOT NULL,
		kind VARCHAR(32) NOT NULL, cnt INTEGER NOT NULL DEFAULT 0,
		PRIMARY KEY (bucket_min, site, kind))`); err != nil {
		t.Fatal(err)
	}
	for k, n := range map[string]int{"total": 10000, "bypass_pass": 3000} {
		if _, err := h.DB.Exec(`INSERT INTO unmask_cookie_minute (bucket_min, site, kind, cnt)
			VALUES (strftime('%s','now')/60, ?, ?, ?)`, site, k, n); err != nil {
			t.Fatal(err)
		}
	}
	get := func(comp string) string {
		req := httptest.NewRequest(http.MethodGet, "/unmask/admin/?site="+site+"&comp="+comp, nil)
		req.AddCookie(&http.Cookie{Name: i18n.CookieName, Value: "en"})
		rr := httptest.NewRecorder()
		h.AdminTopOverview(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("overview ?comp=%s: %d", comp, rr.Code)
		}
		return rr.Body.String()
	}
	tile := regexp.MustCompile(`(?s)id="kpi-requests".*?<div class="value">([^<]*)</div>\s*<div class="sub">([^<]*)</div>`)
	allBody, judBody := get("all"), get("judged")
	if m := tile.FindStringSubmatch(allBody); m == nil || m[1] != "10,000" || m[2] != "every request in the access log" {
		t.Errorf("all traffic: tile = %q", m)
	}
	if m := tile.FindStringSubmatch(judBody); m == nil || m[1] != "7,000" || m[2] != "judged requests only · excluding 3,000 passed through" {
		t.Errorf("judged: tile = %q", m)
	}
	if !regexp.MustCompile(`data-key="bypass"[\s\S]*?<b class="comp-share">excluded</b>`).MatchString(judBody) {
		t.Error("the bypass chip does not say it is excluded from the judged share")
	}
	if !regexp.MustCompile(`data-key="bypass"[\s\S]*?<b class="comp-share">30\.0%</b>`).MatchString(allBody) {
		t.Error("the bypass chip has no share of all traffic")
	}
}
