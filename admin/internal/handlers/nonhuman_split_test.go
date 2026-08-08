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
	// 4,900 requests arrived already holding a pass cookie.  These have to be
	// in the fixture: the human share is a COUNT of them, not what is left when
	// the other segments are taken away, so a fixture without them describes an
	// install whose visitors all show up for the first time.  With the 100
	// clears below they make the 5,000 asserted at the bottom.
	put("pow", 4800)
	put("captcha", 100)
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
		// Every request is accounted for, so there is no residue.
		legendEntry("overview.kpi.nonhuman_other", "0"),
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
		// The human share is a count, and the copy has to say so: while it was a
		// remainder it silently held the abandons and anything passed without a
		// challenge, and the popover's job is to stop the label over-claiming.
		{i18n.LangJA, []string{"意図的に素通し", "リクエスト数", "GPTBot", "判定せずに通した", "残りを引いた数ではありません", "その他"}},
		{i18n.LangEN, []string{"deliberately lets through", "requests", "GPTBot", "without being judged", "not left over", "Other"}},
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

// dropPopups: remove the help text nested inside a fragment before its tags are
// stripped.  The legend carries an info popup now (the "other" breakdown), and
// folding prose into the figures makes every assertion about what the card
// READS match on a sentence instead -- "no segment went negative" started
// failing on the minus sign in a balance line meant to be signed.
var popupRe = regexp.MustCompile(`(?s)<span class="info-popup[^"]*">.*?</span></span>`)

func dropPopups(s string) string { return popupRe.ReplaceAllString(s, "") }

// All four figures on the composition card are shares of ONE total, so they
// have to come from the one table that keeps that total's books.
//
// This test used to assert the opposite: the install-wide view read the benign
// half from the crawler table, on the reasoning that it predates the per-site
// counter and so answers for the whole window right after an upgrade instead
// of filling in over a day.  That was a cosmetic gain paid for with the
// invariant -- the crawler table counts a crawler that hit a bypassed path,
// and the same request already counted as bypassed, so the shares
// oversubscribed the total and the human remainder could not be computed at
// all.  Measured on the install where it surfaced: 535,977 requests double
// counted in a day, and the card rendered "human" as unknown.
func TestCompositionSharesDivideOneTotal(t *testing.T) {
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
	// A crawler table carrying far MORE than the counter -- the shape that used
	// to win.  It must be ignored: those 2,800 are not accounted for in the
	// 10,000 total, so folding them in makes the shares exceed it.
	if _, err := h.DB.Exec(`INSERT INTO unmask_crawler_minute (bucket_min, category, total, served)
		VALUES (strftime('%s','now')/60, 'search-engine', 3000, 200)`); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/", nil)
	req.AddCookie(&http.Cookie{Name: i18n.CookieName, Value: "en"})
	rr := httptest.NewRecorder()
	h.AdminTopOverview(rr, req)
	_, sub := compositionCard(t, rr.Body.String())
	if !strings.Contains(sub, legendEntry("overview.kpi.nonhuman_benign", "40")) {
		t.Errorf("the benign half is not the counter that shares the total (40): %q", sub)
	}
	if strings.Contains(sub, legendEntry("overview.kpi.nonhuman_benign", "2,800")) {
		t.Error("the benign half came from the crawler table again; its requests are not part of the total the other shares divide")
	}
	// And the shares still fit inside the total: oversubscription shows up as an
	// unknown residue, which is the whole point of giving it a segment.
	if strings.Contains(sub, legendEntry("overview.kpi.nonhuman_other", "—")) {
		t.Error("the residue is unknown, so the shares still oversubscribe the total")
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
	// payload_json carries the chain and the reason the challenge fired, as
	// every real event does -- the abandon rate reads them to tell an ordinary
	// visitor apart from a client a rule targeted.
	ev := func(phase string, n int) {
		t.Helper()
		for i := 0; i < n; i++ {
			if _, err := h.DB.Exec(`INSERT INTO unmask_event (site, host, ip_address, phase, payload_json, date_created)
				VALUES (?, '', x'7f000001', ?, '{"chmode":"pow_only"}', datetime('now'))`, site, phase); err != nil {
				t.Fatal(err)
			}
		}
	}
	// 1,000 challenges fired, 150 of them ran their JS, 100 cleared -> 50 people
	// gave up and 850 were stopped.
	ev("load", 150)
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
	return stripTags(m[1]), strings.Join(strings.Fields(stripTags(dropPopups(l[1]))), " ")
}

// compositionPopup: the "other" segment's breakdown, which compositionCard
// deliberately strips out of the legend.
func compositionPopup(t *testing.T, body string) string {
	t.Helper()
	m := regexp.MustCompile(`(?s)<span class="info-popup comp-other-pop">(.*?)</span></span>`).FindStringSubmatch(body)
	if m == nil {
		t.Fatal("the other segment carries no breakdown")
	}
	// Tags carry the row layout, so stripping them naively runs label, figure
	// and description together; a space at each tag boundary keeps them as the
	// separate words a reader sees.
	return strings.Join(strings.Fields(stripTags(
		strings.ReplaceAll(strings.ReplaceAll(m[1], "<br>", " | "), "<", " <"))), " ")
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
	for _, f := range []string{"pctOf $.KPIReqBenign $t", "pctOf $.KPIReqBlocked $t", "pctOf $.KPIReqHuman $t", "pctOf $.KPIReqOther $t"} {
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
	for _, f := range []string{"pctLabel $.KPIReqBenign $t", "pctLabel $.KPIReqBlocked $t", "pctLabel $.KPIReqHuman $t", "pctLabel $.KPIReqOther $t"} {
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
	// The other 7,000 carry no counter of any kind, so they are traffic this
	// install let through without judging OR challenging -- which is a
	// description of the residue, not of a person.  They used to be promoted to
	// "human" for no better reason than being what was left.
	if !strings.Contains(sub, legendEntry("overview.kpi.nonhuman_other", "7,000")) {
		t.Errorf("unclassified traffic did not land in the residue: %q", sub)
	}
	if !strings.Contains(sub, legendEntry("overview.kpi.nonhuman_human", "0")) {
		t.Errorf("traffic with no pass cookie is still counted as human: %q", sub)
	}
}

// "Other" has to say what is in it, or it is a shrug with a number attached.
// Two things are, both real and neither belonging to a named share: the people
// who loaded the challenge and left, and requests let through with no challenge
// at all.  The breakdown has to ADD UP to the segment -- a popover that lists
// parts summing to something else is worse than no popover, because it invites
// the reader to trust arithmetic that is not being done.
func TestOtherSegmentBreaksDownIntoItsParts(t *testing.T) {
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
	// 10,000 requests: 1,000 challenged, 6,000 arrived with a pass cookie, and
	// 3,000 that no counter names -- judged and let through with no challenge.
	for k, n := range map[string]int{"total": 10000, "challenge_served": 1000, "pow": 6000} {
		if _, err := h.DB.Exec(`INSERT INTO unmask_cookie_minute (bucket_min, site, kind, cnt)
			VALUES (strftime('%s','now')/60, ?, ?, ?)`, site, k, n); err != nil {
			t.Fatal(err)
		}
	}
	for _, e := range []struct {
		phase string
		n     int
	}{{"load", 250}, {"bv_pow_only", 200}, {"abandon", 50}} {
		for i := 0; i < e.n; i++ {
			if _, err := h.DB.Exec(`INSERT INTO unmask_event (site, host, ip_address, phase, payload_json, date_created)
				VALUES (?, '', x'7f000001', ?, '{"chmode":"pow_only"}', datetime('now'))`, site, e.phase); err != nil {
				t.Fatal(err)
			}
		}
	}
	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/?site="+site, nil)
	req.AddCookie(&http.Cookie{Name: i18n.CookieName, Value: "en"})
	rr := httptest.NewRecorder()
	h.AdminTopOverview(rr, req)
	body := rr.Body.String()
	_, sub := compositionCard(t, body)

	// blocked = 1,000 fired - 200 cleared - 50 abandoned = 750.
	// human   = 6,000 with a cookie + 200 that cleared one here = 6,200.
	// other   = 10,000 - 0 - 750 - 0 - 6,200 = 3,050, being the 3,000 nothing
	//           named plus the 50 who walked away.
	for _, want := range []string{
		legendEntry("overview.kpi.nonhuman_bad", "750"),
		legendEntry("overview.kpi.nonhuman_human", "6,200"),
		legendEntry("overview.kpi.nonhuman_other", "3,050"),
	} {
		if !strings.Contains(sub, want) {
			t.Errorf("the card does not read %q: %q", want, sub)
		}
	}
	pop := compositionPopup(t, body)
	// Label and figure sit apart in the markup but adjacent once tags are
	// stripped, so "label figure" is the readable contract; each row's
	// explanation follows on its own quiet line and is asserted separately.
	for _, want := range []string{
		i18n.T(i18n.LangEN, "overview.kpi.other_abandon_label") + " 50",
		i18n.T(i18n.LangEN, "overview.kpi.other_abandon_desc"),
		i18n.T(i18n.LangEN, "overview.kpi.other_unchallenged_label") + " 3,000",
		i18n.T(i18n.LangEN, "overview.kpi.other_unchallenged_desc"),
	} {
		if !strings.Contains(pop, want) {
			t.Errorf("the breakdown does not name %q: %q", want, pop)
		}
	}
	// 50 + 3,000 is the whole 3,050, and the balance says so.  Rendered at zero
	// rather than dropped: "0" is the statement that the parts explain the
	// whole, and a reader cannot tell an absent line from an unwritten one.
	if !strings.Contains(pop, i18n.T(i18n.LangEN, "overview.kpi.other_skew_label")+" 0") {
		t.Errorf("the breakdown does not close: no balance line reading 0: %q", pop)
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

// The abandon rate answers "is the challenge too heavy for real people", so it
// must not count clients the operator deliberately targeted.  Counting every
// abandon made it a readout of how much targeted traffic the rules were turning
// away: on one node 65,634 of 65,676 abandons carried force_reason=ua_target at
// captcha_only, so the tile read 99.2% while ordinary visitors abandoned 32
// times.  Switching to the `abandon` beacon alone does not fix it either -- the
// residential browser farm sends the beacon faithfully, and that reading was
// still 83.6%.
func TestAbandonRateCountsOnlyUnruledPoW(t *testing.T) {
	h := newTestHandler(t)
	s := h.snapshotSettings()
	s.Server.BasePath = "/unmask"
	h.SetSettings(s)
	const site = "example.com"

	ev := func(phase, reason, mode string, n int) {
		t.Helper()
		pj := `{"force_reason":"` + reason + `","chmode":"` + mode + `"}`
		if reason == "" {
			pj = `{"chmode":"` + mode + `"}`
		}
		for i := 0; i < n; i++ {
			if _, err := h.DB.Exec(`INSERT INTO unmask_event (site, host, ip_address, phase, payload_json, date_created)
				VALUES (?, '', x'7f000001', ?, ?, datetime('now'))`, site, phase, pj); err != nil {
				t.Fatal(err)
			}
		}
	}
	// A targeted population that loads and walks away from a CAPTCHA, and a
	// small ordinary one facing the transparent PoW.
	ev("load", "ua_target", "captcha_only", 900)
	ev("abandon", "ua_target", "captcha_only", 800)
	ev("load", "", "pow_only", 100)
	ev("abandon", "", "pow_only", 5)
	ev("bv_pow_only", "", "pow_only", 95)

	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/?site="+site, nil)
	req.AddCookie(&http.Cookie{Name: i18n.CookieName, Value: "en"})
	rr := httptest.NewRecorder()
	h.AdminTopOverview(rr, req)
	body := rr.Body.String()

	// 5 of 100, not 905 of 1,000 and not 805 of 1,000.
	//
	// Extracted and compared whole rather than with Contains: "905 of 100 ..."
	// CONTAINS "5 of 100 ...", so a substring check passes on the exact wrong
	// value this test exists to catch.  It did -- the first version of this
	// assertion went green against the old behaviour.
	want := i18n.Tf(i18n.LangEN, "overview.kpi.abandon_sub", "5", "100")
	got := regexp.MustCompile(`[0-9,]+ of [0-9,]+ did not finish[^<]*`).FindString(body)
	if got != want {
		t.Errorf("the abandon tile reads %q, want %q: it is still counting clients a rule targeted", got, want)
	}
	// ...and the rate is theirs, not the farm's.
	if strings.Contains(body, ">80.0<") || strings.Contains(body, ">88.5<") {
		t.Error("the abandon rate is the targeted population's, not the ordinary visitors'")
	}
}
