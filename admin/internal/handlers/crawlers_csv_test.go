package handlers

import (
	"encoding/csv"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/classify"
	"github.com/unmask-sh/unmask/admin/internal/nginxconf"
	"github.com/unmask-sh/unmask/admin/internal/nginxlog"
	"github.com/unmask-sh/unmask/admin/internal/user"
)

// The crawler CSV is the per-site crawler counters summed into the operator's
// days: one row per day, site, category and crawler, the rows the card reads
// once a site is picked, for whoever has to report them.

// csvRequest is a GET for the CSV with the pickers' cookies: tz (an IANA
// name, "" for none) and site ("" for none).
func csvRequest(query, tz, site string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/stats/crawlers.csv"+query, nil)
	req = asRole(req, user.RoleViewer)
	if tz != "" {
		// As the picker writes it: encodeURIComponent of the zone name.
		req.AddCookie(&http.Cookie{Name: tzCookieName, Value: strings.ReplaceAll(tz, "/", "%2F")})
	}
	if site != "" {
		req.AddCookie(&http.Cookie{Name: "unmask_site", Value: site})
	}
	return req
}

// fetchCSV runs the handler and parses what it sent: the header row apart,
// then the records as "a,b,c" lines for easy comparison.
func fetchCSV(t *testing.T, h *Handler, req *http.Request) (resp *httptest.ResponseRecorder, header string, lines []string) {
	t.Helper()
	rr := httptest.NewRecorder()
	h.AdminCrawlersCSV(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
	}
	recs, err := csv.NewReader(strings.NewReader(rr.Body.String())).ReadAll()
	if err != nil {
		t.Fatalf("the response is not CSV: %v\n%s", err, rr.Body.String())
	}
	if len(recs) == 0 {
		t.Fatal("the response has no header row")
	}
	for _, rec := range recs[1:] {
		lines = append(lines, strings.Join(rec, ","))
	}
	return rr, strings.Join(recs[0], ","), lines
}

func sameLines(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range want {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// hourUTC is the hour bucket of a UTC wall-clock hour.
func hourUTC(t *testing.T, s string) int64 {
	t.Helper()
	ts, err := time.Parse("2006-01-02 15", s)
	if err != nil {
		t.Fatal(err)
	}
	return ts.Unix() / 3600
}

func needZone(t *testing.T, name string) {
	t.Helper()
	if _, err := time.LoadLocation(name); err != nil {
		t.Skipf("no zone database on this host (%s: %v)", name, err)
	}
}

// seedCSV: two hours either side of midnight in Tokyo (15:00 UTC), on two
// sites, with a crawler that has no published ranges and a host that was
// filed under "(other)".  The install-wide table holds rows of its own for
// the same hours and for the day before: none of them is the file's.
func seedCSV(t *testing.T, h *Handler) {
	t.Helper()
	h14, h15 := hourUTC(t, "2026-03-10 14"), hourUTC(t, "2026-03-10 15")
	addCrawlerRow(t, h, h14, "a.example.com", "search-engine", "Googlebot", 100, 10, 80, 0)
	addCrawlerRow(t, h, h14-1, "a.example.com", "search-engine", "Googlebot", 20, 0, 20, 0) // same UTC day, an hour earlier
	addCrawlerRow(t, h, h15, "a.example.com", "search-engine", "Googlebot", 40, 4, 30, 0)
	addCrawlerRow(t, h, h15, "a.example.com", "search-engine", "Yeti", 9, 0, 0, 6)
	addCrawlerRow(t, h, h15, "b.example.com", "ai-training", "GPTBot", 50, 50, 0, 0)
	addCrawlerRow(t, h, h14, "(other)", "search-engine", "Googlebot", 70, 7, 0, 0)
	addInstallWideRow(t, h, h14, "search-engine", "Googlebot", 190, 17)
	addInstallWideRow(t, h, h14-24, "search-engine", "Googlebot", 5000, 50) // from before the per-site rows began
}

func TestCrawlersCSVRowsAndHeaders(t *testing.T) {
	h := crawlerHandler(t)
	seedCSV(t, h)
	rr, header, lines := fetchCSV(t, h, csvRequest("?from=2026-03-10&to=2026-03-10", "", ""))

	if want := "date,site,category,crawler,total,challenged,passed,verified,named_pass,range_published"; header != want {
		t.Errorf("header = %s\nwant     %s", header, want)
	}
	// UTC days (no TZ cookie): every seeded hour is 2026-03-10.  Sorted by
	// date, site, category, crawler.  Googlebot's and GPTBot's vendors
	// publish ranges, Yeti's does not; none of GPTBot's requests here came
	// from them.  Nothing of the install-wide table is in the file, least of
	// all the day from before the per-site rows began.
	want := []string{
		"2026-03-10,(other),search-engine,Googlebot,70,7,63,0,0,1",
		"2026-03-10,a.example.com,search-engine,Googlebot,160,14,146,130,0,1",
		"2026-03-10,a.example.com,search-engine,Yeti,9,0,9,0,6,0",
		"2026-03-10,b.example.com,ai-training,GPTBot,50,50,0,0,0,1",
	}
	if !sameLines(lines, want) {
		t.Errorf("rows =\n  %s\nwant\n  %s", strings.Join(lines, "\n  "), strings.Join(want, "\n  "))
	}

	if got := rr.Header().Get("Content-Type"); got != "text/csv; charset=utf-8" {
		t.Errorf("Content-Type = %q", got)
	}
	if got, want := rr.Header().Get("Content-Disposition"), `attachment; filename="unmask-crawlers-2026-03-10_2026-03-10.csv"`; got != want {
		t.Errorf("Content-Disposition = %q, want %q", got, want)
	}
	if got := rr.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
}

// The days are the operator's: with the TZ picker on Tokyo the hour at 15:00
// UTC is the first of the next day there, and a range of dates is read as
// Tokyo dates.
func TestCrawlersCSVDaysFollowTheOperatorsZone(t *testing.T) {
	needZone(t, "Asia/Tokyo")
	h := crawlerHandler(t)
	seedCSV(t, h)

	_, _, lines := fetchCSV(t, h, csvRequest("?from=2026-03-10&to=2026-03-11", "Asia/Tokyo", ""))
	want := []string{
		"2026-03-10,(other),search-engine,Googlebot,70,7,63,0,0,1",
		"2026-03-10,a.example.com,search-engine,Googlebot,120,10,110,100,0,1", // 13:00 and 14:00 UTC
		"2026-03-11,a.example.com,search-engine,Googlebot,40,4,36,30,0,1",     // 15:00 UTC = 00:00 the next day
		"2026-03-11,a.example.com,search-engine,Yeti,9,0,9,0,6,0",
		"2026-03-11,b.example.com,ai-training,GPTBot,50,50,0,0,0,1",
	}
	if !sameLines(lines, want) {
		t.Errorf("Tokyo, two days: rows =\n  %s\nwant\n  %s", strings.Join(lines, "\n  "), strings.Join(want, "\n  "))
	}

	// One Tokyo day: the window ends where the day does, an hour bucket early
	// or late would bring a neighbour's row in.
	rr, _, lines := fetchCSV(t, h, csvRequest("?range=custom&from=2026-03-11&to=2026-03-11", "Asia/Tokyo", ""))
	if !sameLines(lines, want[2:]) {
		t.Errorf("Tokyo, 2026-03-11 alone: rows =\n  %s\nwant\n  %s", strings.Join(lines, "\n  "), strings.Join(want[2:], "\n  "))
	}
	if got, want := rr.Header().Get("Content-Disposition"), `attachment; filename="unmask-crawlers-2026-03-11_2026-03-11.csv"`; got != want {
		t.Errorf("Content-Disposition = %q, want %q (the dates are the operator's)", got, want)
	}
}

// A zone half an hour off the hour: the buckets are UTC hours, so the one
// that holds local midnight belongs to the day it starts on, and a day's
// window takes the buckets that start on that day -- never a row dated the
// day before the first one asked for.
func TestCrawlersCSVHalfHourZone(t *testing.T) {
	needZone(t, "Asia/Kolkata") // UTC+5:30: midnight is 18:30 UTC
	h := crawlerHandler(t)
	addCrawlerRow(t, h, hourUTC(t, "2026-03-10 18"), "a.example.com", "search-engine", "Googlebot", 3, 0, 0, 0) // 23:30 on the 10th there
	addCrawlerRow(t, h, hourUTC(t, "2026-03-10 19"), "a.example.com", "search-engine", "Googlebot", 5, 0, 0, 0) // 00:30 on the 11th
	_, _, lines := fetchCSV(t, h, csvRequest("?from=2026-03-11&to=2026-03-11", "Asia/Kolkata", ""))
	if want := []string{"2026-03-11,a.example.com,search-engine,Googlebot,5,0,5,0,0,1"}; !sameLines(lines, want) {
		t.Errorf("the 11th: rows = %v, want %v", lines, want)
	}
	_, _, lines = fetchCSV(t, h, csvRequest("?from=2026-03-10&to=2026-03-10", "Asia/Kolkata", ""))
	if want := []string{"2026-03-10,a.example.com,search-engine,Googlebot,3,0,3,0,0,1"}; !sameLines(lines, want) {
		t.Errorf("the 10th: rows = %v, want %v", lines, want)
	}
}

// The site picker narrows the file to one site, as it narrows the page: that
// site's rows, without the other sites'.
func TestCrawlersCSVFollowsTheSitePicker(t *testing.T) {
	h := crawlerHandler(t)
	seedCSV(t, h)
	want := []string{
		"2026-03-10,a.example.com,search-engine,Googlebot,160,14,146,130,0,1",
		"2026-03-10,a.example.com,search-engine,Yeti,9,0,9,0,6,0",
	}
	for name, req := range map[string]*http.Request{
		"the picker's cookie": csvRequest("?from=2026-03-10&to=2026-03-10", "", "a.example.com"),
		"?site=":              csvRequest("?from=2026-03-10&to=2026-03-10&site=a.example.com", "", ""),
	} {
		if _, _, lines := fetchCSV(t, h, req); !sameLines(lines, want) {
			t.Errorf("%s: rows =\n  %s\nwant\n  %s", name, strings.Join(lines, "\n  "), strings.Join(want, "\n  "))
		}
	}
	// "default" is the picker's "every site", as on the pages.
	if _, _, lines := fetchCSV(t, h, csvRequest("?from=2026-03-10&to=2026-03-10", "", "default")); len(lines) != 4 {
		t.Errorf("site=default: %d rows, want all 4", len(lines))
	}
	// A site with nothing: the header alone.
	if _, _, lines := fetchCSV(t, h, csvRequest("?from=2026-03-10&to=2026-03-10", "", "nobody.example.com")); len(lines) != 0 {
		t.Errorf("a site with no rows: %v", lines)
	}
}

// The window is the statistics page's: its presets, its custom range, and 30
// days when the request names none it knows.
func TestCrawlersCSVWindow(t *testing.T) {
	h := crawlerHandler(t)
	nowHour := time.Now().Unix() / 3600
	addCrawlerRow(t, h, nowHour-2, "a.example.com", "search-engine", "Googlebot", 1, 0, 0, 0)       // two hours ago
	addCrawlerRow(t, h, nowHour-24*10, "a.example.com", "search-engine", "Googlebot", 10, 0, 0, 0)  // ten days ago
	addCrawlerRow(t, h, nowHour-24*40, "a.example.com", "search-engine", "Googlebot", 100, 0, 0, 0) // forty days ago
	total := func(query string) int {
		t.Helper()
		_, _, lines := fetchCSV(t, h, csvRequest(query, "", ""))
		sum := 0
		for _, l := range lines {
			n, err := strconv.Atoi(strings.Split(l, ",")[4])
			if err != nil {
				t.Fatalf("%q: total of %q: %v", query, l, err)
			}
			sum += n
		}
		return sum
	}
	for query, want := range map[string]int{
		"":                                   11,  // 30 days by default
		"?range=30d":                         11,  //
		"?range=24h":                         1,   // the page's default range, when it hands it over
		"?range=7d":                          1,   //
		"?range=all":                         111, // everything on hand
		"?range=nonsense":                    11,  // not a range: the default
		"?range=custom":                      11,  // a custom range without its dates
		"?range=custom&from=2026-99-01&to=x": 11,  // or with dates that are none
		"?range=custom&from=2026-03-11&to=2026-03-10": 11, // or that run backwards
	} {
		if got := total(query); got != want {
			t.Errorf("%q: the file's requests add up to %d, want %d", query, got, want)
		}
	}
	// A trailing window names its two dates like a custom one does.
	rr, _, _ := fetchCSV(t, h, csvRequest("", "", ""))
	if cd := rr.Header().Get("Content-Disposition"); !regexp.MustCompile(`^attachment; filename="unmask-crawlers-\d{4}-\d{2}-\d{2}_\d{4}-\d{2}-\d{2}\.csv"$`).MatchString(cd) {
		t.Errorf("Content-Disposition = %q", cd)
	}
}

// A text cell that a spreadsheet would run as a formula is disarmed with a
// leading apostrophe.  The site is a Host header: whatever a client sent.
func TestCrawlersCSVFormulaGuard(t *testing.T) {
	for in, want := range map[string]string{
		"":                  "",
		"a.example.com":     "a.example.com",
		"(other)":           "(other)",
		"=1+1":              "'=1+1",
		"+1":                "'+1",
		"-evil.example.com": "'-evil.example.com",
		"@SUM(A1)":          "'@SUM(A1)",
		"\tx":               "'\tx",
		"\rx":               "'\rx",
		"a=b":               "a=b", // only a leading character makes a formula
		"'already":          "'already",
		"2026-03-10":        "2026-03-10",
		"=HYPERLINK(\"x\")": "'=HYPERLINK(\"x\")",
	} {
		if got := csvText(in); got != want {
			t.Errorf("csvText(%q) = %q, want %q", in, got, want)
		}
	}

	// And through the handler: the site, the category and the crawler.
	h := crawlerHandler(t)
	hour := hourUTC(t, "2026-03-10 12")
	addCrawlerRow(t, h, hour, `=cmd|' /C calc'!A0`, "search-engine", "Googlebot", 1, 0, 0, 0)
	addCrawlerRow(t, h, hour, "-dash.example.com", "+cat", "@crawler", 2, 1, 0, 0)
	rr := httptest.NewRecorder()
	h.AdminCrawlersCSV(rr, csvRequest("?from=2026-03-10&to=2026-03-10", "", ""))
	recs, err := csv.NewReader(strings.NewReader(rr.Body.String())).ReadAll()
	if err != nil || len(recs) != 3 {
		t.Fatalf("parse: %v, %d records\n%s", err, len(recs), rr.Body.String())
	}
	if recs[1][1] != "'-dash.example.com" || recs[1][2] != "'+cat" || recs[1][3] != "'@crawler" {
		t.Errorf("row 1 = %q, want the site, category and crawler each behind an apostrophe", recs[1])
	}
	if recs[2][1] != `'=cmd|' /C calc'!A0` {
		t.Errorf("row 2 site = %q, want it behind an apostrophe", recs[2][1])
	}
	for _, rec := range recs[1:] {
		for i, cell := range rec {
			if cell != "" && strings.ContainsRune("=+-@\t\r", rune(cell[0])) {
				t.Errorf("cell %d of %q starts a formula", i, rec)
			}
		}
	}
}

// A read that fails is a 500 with a line of text, not half a file under a
// 200; and with no database there is nothing to read from.
func TestCrawlersCSVErrors(t *testing.T) {
	h := crawlerHandler(t)
	if _, err := h.DB.Exec(`DROP TABLE unmask_crawler_site_hourly`); err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	h.AdminCrawlersCSV(rr, csvRequest("", "", ""))
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("status %d, want 500", rr.Code)
	}
	if body := rr.Body.String(); !strings.Contains(body, "could not read the crawler counters") || strings.Contains(body, "unmask_crawler_site_hourly") {
		t.Errorf("body = %q, want the short message and nothing of the database's", body)
	}
	if ct := rr.Header().Get("Content-Type"); strings.Contains(ct, "csv") || rr.Header().Get("Content-Disposition") != "" {
		t.Errorf("the failure is served as a download: Content-Type %q, Content-Disposition %q", ct, rr.Header().Get("Content-Disposition"))
	}

	rr = httptest.NewRecorder()
	(&Handler{}).AdminCrawlersCSV(rr, csvRequest("", "", ""))
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("no database: status %d, want 503", rr.Code)
	}
}

// The card's link hands the page's window to the CSV: the statistics page
// its own range (a custom one by its two dates), the dashboard 30 days.  The
// site is not in it -- the picker's cookie rides the request -- and every
// role that opens the pages gets the link.
func TestCrawlerCardCSVLink(t *testing.T) {
	h := crawlerHandler(t)
	link := func(fn http.HandlerFunc, target, role string) string {
		t.Helper()
		card := crawlerCard(t, crawlerPage(t, fn, target, "a.example.com", role))
		m := regexp.MustCompile(`<a class="ai-csv" href="([^"]*)">Daily CSV</a>`).FindStringSubmatch(card)
		if m == nil {
			t.Fatalf("%s as %s: no CSV link in the card's heading", target, role)
		}
		return m[1]
	}
	const csvPath = "/unmask/admin/stats/crawlers.csv"
	for _, role := range []string{user.RoleViewer, user.RoleAdmin} {
		for target, want := range map[string]string{
			"/unmask/admin/stats/default/":                                            csvPath + "?range=24h",
			"/unmask/admin/stats/default/?range=7d":                                   csvPath + "?range=7d",
			"/unmask/admin/stats/default/?range=30d":                                  csvPath + "?range=30d",
			"/unmask/admin/stats/default/?range=custom&from=2026-03-01&to=2026-03-10": csvPath + "?range=custom&amp;from=2026-03-01&amp;to=2026-03-10",
			// A custom range that is none: the page reads the last day, and so does the link.
			"/unmask/admin/stats/default/?range=custom&from=nonsense&to=2026-03-10": csvPath + "?range=24h",
		} {
			if got := link(h.AdminStats, target, role); got != want {
				t.Errorf("%s as %s: link = %s, want %s", target, role, got, want)
			}
		}
		for _, target := range []string{"/unmask/admin/", "/unmask/admin/?range=7d", "/unmask/admin/?partial=day"} {
			if got := link(h.AdminTopOverview, target, role); got != csvPath+"?range=30d" {
				t.Errorf("%s as %s: link = %s, want the last 30 days", target, role, got)
			}
		}
	}
	// Every range the statistics page offers is one the CSV reads as given.
	for _, rng := range []string{"1h", "3h", "6h", "12h", "24h", "7d", "30d", "90d", "180d", "365d", "all"} {
		win := crawlersCSVWindow(httptest.NewRequest(http.MethodGet, csvPath+"?range="+rng, nil), time.Unix(1_800_000_000, 0), time.UTC)
		def := crawlersCSVWindow(httptest.NewRequest(http.MethodGet, csvPath, nil), time.Unix(1_800_000_000, 0), time.UTC)
		if rng != "30d" && win.fromHour == def.fromHour {
			t.Errorf("range=%s is read as the default window", rng)
		}
	}
}

// TestCrawlersCSVReadsWhatTheLogReaderCounted: the whole path with nothing
// stood in -- the reader classifies and names the crawler from the shipped
// list, asks the shipped ranges whether the address is the vendor's, and
// writes its rows; the CSV reads them back per site.  The two ends agree on
// what each column means, which neither side's own tests can say.
func TestCrawlersCSVReadsWhatTheLogReaderCounted(t *testing.T) {
	h := crawlerHandler(t)
	const ua = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
	category := classify.LookupTag(ua)
	crawler := classify.LookupCrawlerIn(ua, category)
	if category == "" || crawler == "" {
		t.Fatalf("the shipped crawler list does not know %q (category %q, crawler %q)", ua, category, crawler)
	}
	// An address the vendor publishes, out of the ranges as shipped.
	var vendorIP string
	for _, s := range nginxconf.FlattenBypassPresets([]string{"google-common"}) {
		if p, err := netip.ParsePrefix(s); err == nil && p.Addr().Is4() {
			vendorIP = p.Addr().String()
			break
		}
	}
	if vendorIP == "" {
		t.Fatal("the google-common preset loaded no IPv4 prefix; embed broken?")
	}

	before := time.Now().UTC()
	r := nginxlog.Start("", h.DB)
	r.SetCrawlerClassifier(classify.LookupTag)
	r.SetCrawlerNamer(classify.LookupCrawlerIn)
	r.SetCrawlerRangeCheck(func(name, ip string) bool {
		_, in := nginxconf.CrawlerVendorRange(name, ip)
		return in
	})
	r.BumpCrawler("a.example.com", ua, vendorIP, false)   // the crawler itself, passed
	r.BumpCrawler("a.example.com", ua, "192.0.2.1", true) // its name from elsewhere, challenged
	r.BumpCrawler("b.example.com", ua, "192.0.2.1", true)
	r.Close() // the final flush

	_, _, lines := fetchCSV(t, h, csvRequest("", "", ""))
	day := before.Format("2006-01-02")
	want := []string{
		day + ",a.example.com," + category + "," + crawler + ",2,1,1,1,0,1",
		day + ",b.example.com," + category + "," + crawler + ",1,1,0,0,0,1",
	}
	if !sameLines(lines, want) {
		t.Errorf("rows =\n  %s\nwant\n  %s", strings.Join(lines, "\n  "), strings.Join(want, "\n  "))
	}
}
