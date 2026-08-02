package handlers

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/i18n"
)

// "Non-human traffic" is counted in requests, and both halves have to be there:
// the crawlers we pass on purpose as well as the requests we answered with a
// challenge nobody cleared.
//
// Requests rather than distinct clients because that is the unit of the
// question, and because the figures either side of this one on the page -- the
// hero above, the crawler card below -- are both request counts.  Counting
// clients put three numbers in two units next to each other and read the
// opposite way round from the load: a search engine sweeping a site from a
// handful of addresses looked smaller than a botnet spreading a few requests
// over thousands.
func TestNonHumanTrafficCountsRequestsOnBothSides(t *testing.T) {
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
	put := func(kind string, n int) {
		t.Helper()
		if _, err := h.DB.Exec(
			`INSERT INTO unmask_cookie_minute (bucket_min, site, kind, cnt)
			 VALUES (strftime('%s','now')/60, ?, ?, ?)`, site, kind, n); err != nil {
			t.Fatal(err)
		}
	}
	// 10,000 requests: 2,000 from crawlers we passed, 3,100 challenged of which
	// 100 were then cleared -> 3,000 blocked.  Non-human = 5,000 = 50%.
	put("total", 10000)
	put("crawler_pass", 2000)
	put("challenge_served", 3100)
	put("pow", 80)
	put("captcha", 20)

	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/?site="+site, nil)
	req.AddCookie(&http.Cookie{Name: i18n.CookieName, Value: "en"})
	rr := httptest.NewRecorder()
	h.AdminTopOverview(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("overview: %d", rr.Code)
	}
	body := rr.Body.String()

	tile := regexp.MustCompile(`(?s)<div class="kpi">\s*<div class="label">Non-human traffic.*?<div class="value">(.*?)</div>.*?<div class="sub">(.*?)</div>`).
		FindStringSubmatch(body)
	if tile == nil {
		t.Fatal("the non-human tile is missing from the overview")
	}
	value, sub := tile[1], stripTags(tile[2])

	// Exact counters, so these are exact -- no estimate to allow for.
	for _, want := range []string{"2,000 benign", "3,000 malicious", "10,000 requests"} {
		if !strings.Contains(sub, want) {
			t.Errorf("the tile does not read %q: %q", want, sub)
		}
	}
	if strings.Contains(sub, "client") {
		t.Errorf("the tile still describes its denominator as clients: %q", sub)
	}
	pct := regexp.MustCompile(`([0-9.]+)%`).FindStringSubmatch(value)
	if pct == nil {
		t.Fatalf("the tile has no percentage: %q", value)
	}
	var got float64
	fmt.Sscanf(pct[1], "%f", &got)
	if got != 50.0 {
		t.Errorf("non-human = %.1f%%, want 50.0 (2,000 passed crawlers + 3,000 blocked of 10,000)", got)
	}
}

// A challenge served in the last minute of the window can be cleared in the
// first minute after it, so at the edge the passes can outrun the serves.  A
// negative blocked count would render as a negative percentage.
func TestBlockedRequestsNeverGoNegative(t *testing.T) {
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
	for kind, n := range map[string]int{"total": 100, "challenge_served": 5, "pow": 40} {
		if _, err := h.DB.Exec(
			`INSERT INTO unmask_cookie_minute (bucket_min, site, kind, cnt)
			 VALUES (strftime('%s','now')/60, ?, ?, ?)`, site, kind, n); err != nil {
			t.Fatal(err)
		}
	}
	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/?site="+site, nil)
	req.AddCookie(&http.Cookie{Name: i18n.CookieName, Value: "en"})
	rr := httptest.NewRecorder()
	h.AdminTopOverview(rr, req)
	tile := regexp.MustCompile(`(?s)<div class="kpi">\s*<div class="label">Non-human traffic.*?<div class="value">(.*?)</div>.*?<div class="sub">(.*?)</div>`).
		FindStringSubmatch(rr.Body.String())
	if tile == nil {
		t.Fatal("the non-human tile is missing from the overview")
	}
	value, sub := tile[1], stripTags(tile[2])
	if strings.Contains(sub, "-") {
		t.Errorf("more passes than serves in the window produced a negative count: %q", sub)
	}
	if strings.Contains(value, "-") {
		t.Errorf("the percentage went negative: %q", value)
	}
	if !strings.Contains(sub, "0 malicious") {
		t.Errorf("want the blocked half floored at zero, got %q", sub)
	}
}

// The benign half is a consequence of the operator's own settings, not a
// property of the traffic, so the popover has to say so -- otherwise "benign
// bot" reads as unmask's verdict and the number looks broken the moment
// someone puts a crawler group behind a challenge and watches it switch sides.
// It also has to name its unit, since the number beside it on the page (the
// crawler card) is a request count of the same traffic on a different basis.
func TestNonHumanPopoverExplainsBenignAndItsUnit(t *testing.T) {
	for _, tc := range []struct {
		lang i18n.Lang
		want []string
	}{
		{i18n.LangJA, []string{"意図的に素通し", "リクエスト数", "GPTBot"}},
		{i18n.LangEN, []string{"deliberately lets through", "requests", "GPTBot"}},
	} {
		help := i18n.T(tc.lang, "overview.kpi.nonhuman_help")
		if help == "" || help == "overview.kpi.nonhuman_help" {
			t.Fatalf("%s: the non-human popover copy is missing", tc.lang)
		}
		for _, w := range tc.want {
			if !strings.Contains(help, w) {
				t.Errorf("%s popover does not mention %q: %s", tc.lang, w, help)
			}
		}
		// The figures are exact counters now; a leftover estimate caveat would
		// be telling the operator not to trust a number they can reconcile.
		for _, gone := range []string{"HyperLogLog", "推定値", "estimates"} {
			if strings.Contains(help, gone) {
				t.Errorf("%s popover still calls the figures %q, but they are exact counts", tc.lang, gone)
			}
		}
	}
}

func stripTags(s string) string {
	return regexp.MustCompile(`<[^>]*>`).ReplaceAllString(s, "")
}
