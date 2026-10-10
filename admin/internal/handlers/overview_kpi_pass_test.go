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
// same unit as "challenge fired" beside them, with the two shares on the line
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
	// A pass tile: the figure, and the solve / cookie line under it.
	tile := func(body, key string) (value, sub string) {
		re := regexp.MustCompile(`(?s)data-kpi="` + key + `">.*?<div class="value">([^<]*)</div>.*?<div class="sub sub-cookie">([^<]*)</div>`)
		m := re.FindStringSubmatch(body)
		if m == nil {
			t.Fatalf("the %s tile is not on the page", key)
		}
		return strings.TrimSpace(m[1]), strings.TrimSpace(m[2])
	}

	// No access-log counters at all: the headline is the solves (3 + 2), and
	// the stage says the cookie share is missing.
	body := get()
	for key, want := range map[string]string{"pow": "3", "captcha": "2"} {
		if v, sub := tile(body, key); v != want || !strings.Contains(sub, want) || !strings.Contains(sub, "access-log") {
			t.Errorf("without the feed the %s tile shows the solves alone and says so: value=%q sub=%q", key, v, sub)
		}
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
	// 153 = 3 solves + 150 on a PoW cookie; 42 = 2 + 40 on the CAPTCHA side;
	// the line below each carries the split.
	for key, want := range map[string][3]string{"pow": {"153", "3", "150"}, "captcha": {"42", "2", "40"}} {
		v, sub := tile(body, key)
		if v != want[0] {
			t.Errorf("%s tile: want %s solves + cookie, got %q (sub %q)", key, want[0], v, sub)
		}
		for _, w := range want[1:] {
			if !strings.Contains(sub, w) {
				t.Errorf("the %s breakdown lacks %s: %q", key, w, sub)
			}
		}
		if strings.Contains(sub, "access-log") {
			t.Errorf("with the feed the %s tile must not say the cookie share is missing: %q", key, sub)
		}
	}

}
