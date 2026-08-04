package handlers

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
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
	// 3,100 challenges fired, 100 of them cleared -> 3,000 blocked.  The fires
	// come from this table (the access log sees a deny, which serves no page
	// and so writes no event); the clears are events, one row per occurrence.
	put("challenge_served", 3100)
	ev := func(phase string, n int) {
		t.Helper()
		for i := 0; i < n; i++ {
			if _, err := h.DB.Exec(`INSERT INTO unmask_event (site, host, ip_address, phase, date_created)
				VALUES (?, '', x'7f000001', ?, datetime('now'))`, site, phase); err != nil {
				t.Fatal(err)
			}
		}
	}
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

	value, sub := compositionCard(t, body)

	// Exact counters, so these are exact -- no estimate to allow for.
	for _, want := range []string{
		legendEntry("overview.kpi.nonhuman_benign", "2,000"),
		legendEntry("overview.kpi.nonhuman_bad", "3,000"),
		legendEntry("overview.kpi.nonhuman_human", "5,000"),
	} {
		if !strings.Contains(sub, want) {
			t.Errorf("the card does not read %q: %q", want, sub)
		}
	}
	// The denominator sits in the card header beside the percentage.
	if !strings.Contains(body, "10,000 requests") {
		t.Error("the card does not say what the percentage is a share of")
	}
	if strings.Contains(sub, "client") {
		t.Errorf("the card still describes its denominator as clients: %q", sub)
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
	value, sub := compositionCard(t, rr.Body.String())
	if strings.Contains(sub, "-") {
		t.Errorf("more passes than serves in the window produced a negative count: %q", sub)
	}
	if strings.Contains(value, "-") {
		t.Errorf("the percentage went negative: %q", value)
	}
	if !strings.Contains(sub, legendEntry("overview.kpi.nonhuman_bad", "0")) {
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
		{i18n.LangJA, []string{"意図的に素通し", "リクエスト数", "GPTBot", "判定せずに通した", "実訪問者数そのものではありません"}},
		{i18n.LangEN, []string{"deliberately lets through", "requests", "GPTBot", "without being judged", "not a count of real visitors"}},
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
	_, sub := compositionCard(t, rr.Body.String())
	if !strings.Contains(sub, legendEntry("overview.kpi.nonhuman_benign", "2,800")) {
		t.Errorf("the default view is reading the young per-site counter (40) instead of the table with history (2,800): %q", sub)
	}
}

// A visitor who loaded the challenge and walked away was not stopped by
// unmask, and the abandons are recorded -- so they come out of the blocked
// figure rather than being disclosed in a footnote on every number that uses
// it.  Measured on the fleet before this: 283 of ~9,900 on one node (2.9%),
// 175 of ~246,000 on another.
func TestAbandonsAreSubtractedFromTheBlockedHalf(t *testing.T) {
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
	for k, n := range map[string]int{"total": 10000, "challenge_served": 1000} {
		if _, err := h.DB.Exec(`INSERT INTO unmask_cookie_minute (bucket_min, site, kind, cnt)
			VALUES (strftime('%s','now')/60, ?, ?, ?)`, site, k, n); err != nil {
			t.Fatal(err)
		}
	}
	ev := func(phase string, n int) {
		t.Helper()
		for i := 0; i < n; i++ {
			if _, err := h.DB.Exec(`INSERT INTO unmask_event (site, host, ip_address, phase, date_created)
				VALUES (?, '', x'7f000001', ?, datetime('now'))`, site, phase); err != nil {
				t.Fatal(err)
			}
		}
	}
	// 1,000 challenges fired, 100 cleared, 50 people gave up -> 850 blocked.
	ev("bv_pow_only", 100)
	ev("abandon", 50)

	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/?site="+site, nil)
	req.AddCookie(&http.Cookie{Name: i18n.CookieName, Value: "en"})
	rr := httptest.NewRecorder()
	h.AdminTopOverview(rr, req)
	body := rr.Body.String()
	if !strings.Contains(body, legendEntry("overview.kpi.nonhuman_bad", "850")) {
		m := legendPattern("overview.kpi.nonhuman_bad").FindString(body)
		t.Errorf("blocked reads %q, want 850: the visitors who walked away are still counted as stopped", m)
	}
	// The hero uses the same figure, so the two must not diverge again.
	if !strings.Contains(body, ">850<") {
		t.Error("the hero and the tile disagree on the blocked count")
	}
	// And with the abandons taken out, no figure needs to disclose them.
	for _, gone := range []string{"僅かに含む", "gave up", "includes the few real visitors"} {
		if strings.Contains(body, gone) {
			t.Errorf("a caveat about abandoners survives (%q) although they are subtracted", gone)
		}
	}
}

// legendEntry: what the composition legend reads for one segment, built from
// the catalog rather than spelled out.  These assertions are about the number
// the card shows, not about the wording around it, and hard-coding the English
// phrasing made a legend reorder look like six broken counters.
func legendEntry(key, count string) string {
	return i18n.Tf(i18n.LangEN, key, count)
}

// legendPattern: the same entry with any count, for the failure messages that
// want to quote back whatever the card really said.
func legendPattern(key string) *regexp.Regexp {
	const mark = "\x00"
	return regexp.MustCompile(strings.ReplaceAll(
		regexp.QuoteMeta(legendEntry(key, mark)), mark, `[0-9,]+`))
}

// compositionCard: the percentage and the legend line from the traffic
// composition card.  It lives above the KPI row rather than in it -- the row
// holds operational counters and this is the diagnostic figure -- so the tests
// read it from one place instead of each knowing the markup.
func compositionCard(t *testing.T, body string) (pct, legend string) {
	t.Helper()
	i := strings.Index(body, `class="bcd-card comp-card"`)
	if i < 0 {
		t.Fatal("the traffic composition card is missing from the overview")
	}
	card := body[i:]
	if j := strings.Index(card, "</div>\n</div>"); j > 0 {
		card = card[:j]
	}
	m := regexp.MustCompile(`(?s)<div class="comp-pct">(.*?)</div>`).FindStringSubmatch(card)
	if m == nil {
		t.Fatal("the composition card has no percentage")
	}
	l := regexp.MustCompile(`(?s)<div class="comp-legend">(.*?)</div>\s*</div>`).FindStringSubmatch(card)
	if l == nil {
		// No legend when there is no data; the caller's assertions say so.
		return stripTags(m[1]), ""
	}
	return stripTags(m[1]), strings.Join(strings.Fields(stripTags(l[1])), " ")
}

// The composition figure sits in its own full-width card rather than in the KPI
// row.  The row holds operational counters -- events, challenges, passes, bans
// -- and this is the diagnostic one: the single number that says what a site is
// dealing with independent of its size.  It also carries four figures, which a
// 13rem tile could only render at 0.7rem across two wrapped lines.
func TestCompositionHasItsOwnCard(t *testing.T) {
	b, err := os.ReadFile("../../assets/templates/overview.html")
	if err != nil {
		t.Fatal(err)
	}
	tpl := string(b)

	card := strings.Index(tpl, `class="bcd-card comp-card"`)
	grid := strings.Index(tpl, `<div class="kpi-grid">`)
	if card < 0 {
		t.Fatal("the composition card is gone")
	}
	if card > grid {
		t.Error("the composition card sits below the KPI row; it is the headline figure, not a footnote")
	}
	// It must not also be a tile: two copies of one number invite the reader to
	// look for a difference between them.
	row := tpl[grid:]
	row = row[:strings.Index(row, "\n</div>")]
	if strings.Contains(row, "nonhuman_benign") {
		t.Error("the KPI row still carries the composition; it is in two places at once")
	}

	// The bar's segments are shares of one total, so they have to be driven by
	// the same total the percentage is.  ($. because the card renders inside a
	// range over the two denominators -- both views exist in the DOM so the
	// toggle is a visibility flip rather than a page load.)
	for _, f := range []string{"pctOf $.KPIReqBenign $t", "pctOf $.KPIReqBlocked $t", "pctOf $.KPIReqHuman $t"} {
		if !strings.Contains(tpl, f) {
			t.Errorf("the bar segment %q is not sized against the shared total", f)
		}
	}
}

// The KPI row holds counters an operator can act on.  A "total events" tile
// used to sit at its head: the sum of serve + load + passes + abandons +
// rebinds + errors, in an internal unit, whose main parts are the tiles beside
// it and whose only unique reading -- how many rows the hunt log holds -- is
// the first thing the hunt page shows.  Explaining it did not make it useful,
// so it went.
func TestNoTotalEventsTile(t *testing.T) {
	b, err := os.ReadFile("../../assets/templates/overview.html")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "overview.kpi.events") {
		t.Error("the total-events tile is back; its parts are already tiles of their own")
	}
	// And the query behind it should be gone too, not merely unrendered.
	h, err := os.ReadFile("overview_admin.go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(h), "kpiEvents") {
		t.Error("the landing page still counts every event row for a tile that no longer exists")
	}
}

// Each share of the bar is labelled with its percentage: the bar shows the
// shape, the percentage names it, and the count is the detail behind it.  A
// share too small to round to 0.1% reads as "<0.1%" rather than "0.0%", which
// beside a five-figure count looks like a broken number.
func TestCompositionLegendShowsShares(t *testing.T) {
	b, err := os.ReadFile("../../assets/templates/overview.html")
	if err != nil {
		t.Fatal(err)
	}
	tpl := string(b)
	for _, f := range []string{"pctLabel $.KPIReqBenign $t", "pctLabel $.KPIReqBlocked $t", "pctLabel $.KPIReqHuman $t"} {
		if !strings.Contains(tpl, f) {
			t.Errorf("the legend entry %q has no share", f)
		}
	}
}

// A deny serves no challenge page, so it writes no serve event -- while the
// access log records it like any other fired challenge.  Reading the fires
// from the event log therefore undercounts wherever the action is deny:
// measured on unmask.sh, 493 serve events against 6,329 log fires, so the
// dashboard reported 5.4% malicious where the truth was 69%.
//
// The hero, the challenges-fired tile and the composition card all read the
// same figure, so a page that disagrees with itself cannot come back.
func TestDeniedRequestsCountAsChallengesFired(t *testing.T) {
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
	for k, n := range map[string]int{"total": 10000, "challenge_served": 6000} {
		if _, err := h.DB.Exec(`INSERT INTO unmask_cookie_minute (bucket_min, site, kind, cnt)
			VALUES (strftime('%s','now')/60, ?, ?, ?)`, site, k, n); err != nil {
			t.Fatal(err)
		}
	}
	// Only 100 of those 6,000 served an actual page (the rest were denied), so
	// the event log knows about 100.
	for i := 0; i < 100; i++ {
		if _, err := h.DB.Exec(`INSERT INTO unmask_event (site, host, ip_address, phase, date_created)
			VALUES (?, '', x'7f000001', 'serve', datetime('now'))`, site); err != nil {
			t.Fatal(err)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/?site="+site, nil)
	req.AddCookie(&http.Cookie{Name: i18n.CookieName, Value: "en"})
	rr := httptest.NewRecorder()
	h.AdminTopOverview(rr, req)
	body := rr.Body.String()

	_, sub := compositionCard(t, body)
	if !strings.Contains(sub, legendEntry("overview.kpi.nonhuman_bad", "6,000")) {
		t.Errorf("the card counted the served pages, not the fired challenges: %q", sub)
	}
	// The hero shows the same number.
	if !strings.Contains(body, ">6,000<") {
		t.Error("the hero disagrees with the card about how much was stopped")
	}
}

// Traffic a bypass rule let through is neither a bot we identified nor a
// person, and it used to land in the human share -- on unmask.sh the package
// repo made that 30% of all traffic, package managers counted as people.
func TestBypassedTrafficIsCountedApart(t *testing.T) {
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
	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/?site="+site, nil)
	req.AddCookie(&http.Cookie{Name: i18n.CookieName, Value: "en"})
	rr := httptest.NewRecorder()
	h.AdminTopOverview(rr, req)
	_, sub := compositionCard(t, rr.Body.String())

	if !strings.Contains(sub, legendEntry("overview.kpi.nonhuman_bypass", "3,000")) {
		t.Errorf("bypassed traffic has no share of its own: %q", sub)
	}
	if !strings.Contains(sub, legendEntry("overview.kpi.nonhuman_human", "7,000")) {
		t.Errorf("bypassed traffic is still inside the human share: %q", sub)
	}
}

// The four segments are shares of one total, so any request counted twice
// surfaces as a negative human remainder.  It did: a listed crawler fetching a
// bypassed path was both crawler_pass and bypass_pass, and tool1-us rendered
// "人間 -2,493" against 718,238 requests.
func TestSegmentsNeverOversubscribeTheTotal(t *testing.T) {
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
	// Deliberately oversubscribed: the halves add up to more than the total,
	// which is what a double count looks like from here.
	for k, n := range map[string]int{"total": 1000, "crawler_pass": 600, "bypass_pass": 600} {
		if _, err := h.DB.Exec(`INSERT INTO unmask_cookie_minute (bucket_min, site, kind, cnt)
			VALUES (strftime('%s','now')/60, ?, ?, ?)`, site, k, n); err != nil {
			t.Fatal(err)
		}
	}
	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/?site="+site, nil)
	req.AddCookie(&http.Cookie{Name: i18n.CookieName, Value: "en"})
	rr := httptest.NewRecorder()
	h.AdminTopOverview(rr, req)
	_, sub := compositionCard(t, rr.Body.String())
	if strings.Contains(sub, "-") {
		t.Errorf("a segment went negative: %q", sub)
	}
}
