package handlers

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"
)

// The pass tiles' headline is every request the gate admitted -- the solves
// plus the requests that came back on the cookie a solve minted -- in the
// same unit as "challenge fired" beside it, with the two shares on the line
// below.  Without the access-log feed the cookie share is unknown and the
// headline is the solves alone, said so on the tile.  (2026-09-09: a
// headline of solves alone read as "2 million challenged, 20 thousand
// passed".)
func TestOverviewPassTilesCountAdmittedRequests(t *testing.T) {
	h := newTestHandler(t)
	s := h.snapshotSettings()
	s.Server.BasePath = "/unmask"
	h.SetSettings(s)
	now := time.Now().UTC()
	seedEvent := func(phase string, n int) {
		for i := 0; i < n; i++ {
			if _, err := h.DB.Exec(`INSERT INTO unmask_event (site, host, ip_address, phase, date_created) VALUES ('', '', X'0a000001', ?, ?)`,
				phase, now.Add(-time.Hour).Format("2006-01-02 15:04:05.000")); err != nil {
				t.Fatal(err)
			}
		}
	}
	seedEvent("bv_pow_only", 3)
	seedEvent("bv_captcha_only", 2)

	get := func() string {
		rr := httptest.NewRecorder()
		h.AdminTopOverview(rr, httptest.NewRequest(http.MethodGet, "/unmask/admin/", nil))
		if rr.Code != http.StatusOK {
			t.Fatalf("overview: %d", rr.Code)
		}
		return rr.Body.String()
	}
	tile := func(body, class string) (value, sub string) {
		re := regexp.MustCompile(`(?s)<div class="kpi ` + class + `">.*?<div class="value">([^<]*)</div>.*?<div class="sub sub-cookie">([^<]*)</div>`)
		m := re.FindStringSubmatch(body)
		if m == nil {
			t.Fatalf("tile %s not found", class)
		}
		return strings.TrimSpace(m[1]), strings.TrimSpace(m[2])
	}

	// No access-log counters at all: the headline is the solves, and the
	// tile says the cookie share is missing.
	body := get()
	if v, sub := tile(body, "k-pow"); v != "3" || !strings.Contains(sub, "3") || !strings.Contains(sub, "access-log") {
		t.Errorf("without the feed the PoW tile shows the solves alone and says so: value=%q sub=%q", v, sub)
	}

	// With the feed: 150 requests on a PoW cookie and 40 on a CAPTCHA cookie.
	if _, err := h.DB.Exec(`CREATE TABLE IF NOT EXISTS unmask_cookie_minute (
		bucket_min INTEGER NOT NULL, site TEXT NOT NULL, kind TEXT NOT NULL, cnt INTEGER NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	bucketMin := now.Unix()/60 - 10
	for kind, n := range map[string]int{"total": 1000, "pow": 150, "captcha": 40, "challenge_served": 700} {
		if _, err := h.DB.Exec(`INSERT INTO unmask_cookie_minute (bucket_min, site, kind, cnt) VALUES (?,?,?,?)`, bucketMin, "", kind, n); err != nil {
			t.Fatal(err)
		}
	}
	body = get()
	if v, sub := tile(body, "k-pow"); v != "153" || !strings.Contains(sub, "3") || !strings.Contains(sub, "150") {
		t.Errorf("PoW tile: want 153 = 3 solves + 150 on a cookie, got value=%q sub=%q", v, sub)
	}
	if v, sub := tile(body, "k-captcha"); v != "42" || !strings.Contains(sub, "2") || !strings.Contains(sub, "40") {
		t.Errorf("CAPTCHA tile: want 42 = 2 solves + 40 on a cookie, got value=%q sub=%q", v, sub)
	}
}
