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
	// 10,000 requests, 2,000 of them from crawlers we passed on purpose.
	put("total", 10000)
	put("crawler_pass", 2000)
	// 3,100 challenges served, 100 of them cleared -> 3,000 blocked.  The
	// blocked half comes from the event log, not from this table: its 'pow' /
	// 'captcha' count every request from a client already carrying a pass
	// cookie, which on a site with regulars outnumbers the challenges and
	// drove the figure to zero.
	ev := func(phase string, n int) {
		t.Helper()
		for i := 0; i < n; i++ {
			if _, err := h.DB.Exec(`INSERT INTO unmask_event (site, host, ip_address, phase, date_created)
				VALUES (?, '', x'7f000001', ?, datetime('now'))`, site, phase); err != nil {
				t.Fatal(err)
			}
		}
	}
	ev("serve", 3100)
	ev("bv_pow_only", 80)
	ev("bv_captcha_only", 20)

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
	if _, err := h.DB.Exec(
		`INSERT INTO unmask_cookie_minute (bucket_min, site, kind, cnt)
		 VALUES (strftime('%s','now')/60, ?, 'total', 100)`, site); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 40; i++ {
		if _, err := h.DB.Exec(`INSERT INTO unmask_event (site, host, ip_address, phase, date_created)
			VALUES (?, '', x'7f000001', 'bv_pow_only', datetime('now'))`, site); err != nil {
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

// crawler_pass starts at the upgrade, but unmask_crawler_minute has been
// recording the same requests all along -- same classifier, same condition,
// same pass, differing only in that one is per site and the other install-wide.
// The default view reads the longer-lived table so the benign half answers for
// the whole window immediately instead of filling in over the following day.
func TestInstallWideBenignReadsTheTableWithHistory(t *testing.T) {
	h := newTestHandler(t)
	s := h.snapshotSettings()
	s.Server.BasePath = "/unmask"
	h.SetSettings(s)
	for _, ddl := range []string{
		`CREATE TABLE unmask_cookie_minute (bucket_min INTEGER NOT NULL, site VARCHAR(64) NOT NULL,
		 kind VARCHAR(32) NOT NULL, cnt INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (bucket_min, site, kind))`,
		`CREATE TABLE unmask_crawler_minute (bucket_min INTEGER NOT NULL, category VARCHAR(16) NOT NULL,
		 total INTEGER NOT NULL DEFAULT 0, served INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (bucket_min, category))`,
	} {
		if _, err := h.DB.Exec(ddl); err != nil {
			t.Fatal(err)
		}
	}
	for kind, n := range map[string]int{"total": 10000, "challenge_served": 1000, "crawler_pass": 40} {
		if _, err := h.DB.Exec(`INSERT INTO unmask_cookie_minute (bucket_min, site, kind, cnt)
			VALUES (strftime('%s','now')/60, 'a.example', ?, ?)`, kind, n); err != nil {
			t.Fatal(err)
		}
	}
	// The same traffic as the counter has seen so far, plus the day before it
	// existed: 3,000 crawler requests, 200 of them challenged.
	if _, err := h.DB.Exec(`INSERT INTO unmask_crawler_minute (bucket_min, category, total, served)
		VALUES (strftime('%s','now')/60, 'search-engine', 3000, 200)`); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/", nil)
	req.AddCookie(&http.Cookie{Name: i18n.CookieName, Value: "en"})
	rr := httptest.NewRecorder()
	h.AdminTopOverview(rr, req)
	tile := regexp.MustCompile(`(?s)<div class="label">Non-human traffic.*?<div class="sub">(.*?)</div>`).
		FindStringSubmatch(rr.Body.String())
	if tile == nil {
		t.Fatal("the non-human tile is missing")
	}
	sub := stripTags(tile[1])
	if !strings.Contains(sub, "2,800 benign") {
		t.Errorf("the default view is reading the young per-site counter (40) instead of the table with history (2,800): %q", sub)
	}
}
