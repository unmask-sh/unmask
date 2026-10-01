package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/assets"
	"github.com/unmask-sh/unmask/admin/internal/classify"
	"github.com/unmask-sh/unmask/admin/internal/dashboard"
	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/events"
	"github.com/unmask-sh/unmask/admin/internal/i18n"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The baselines these tests count against: far above anything the binary
// ships with, so no bump of the built-in ones (and no real release) ever
// moves the answers.
const (
	testCurChrome  = 300
	testCurFirefox = 320
)

func pinBrowserBaselines(t *testing.T) {
	t.Helper()
	prev, had := settings.HubBrowserBaselines()
	settings.SetHubBrowserBaselines(settings.HubBrowserBaselinesData{Chrome: testCurChrome, Firefox: testCurFirefox})
	t.Cleanup(func() {
		if had {
			settings.SetHubBrowserBaselines(prev)
		} else {
			settings.SetHubBrowserBaselines(settings.HubBrowserBaselinesData{})
		}
	})
}

func chromeUA(major string) string {
	return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + major + ".0.0.0 Safari/537.36"
}

// The mark: nothing up to nine releases behind, the count from ten on, "EOL"
// for a browser that no longer ships, and nothing for the browsers whose
// number is not a release count.
func TestUAOldBadge(t *testing.T) {
	pinBrowserBaselines(t)
	const minus = "\u2212"
	cases := []struct{ ua, want string }{
		{chromeUA("300"), ""},
		{chromeUA("291"), ""},
		{chromeUA("290"), minus + "10"},
		{chromeUA("109"), minus + "191"},
		{chromeUA("301"), ""}, // past the baseline: not behind
		{chromeUA("290") + " Edg/290.0.0.0", minus + "10"},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:310.0) Gecko/20100101 Firefox/310.0", minus + "10"},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:311.0) Gecko/20100101 Firefox/311.0", ""},
		{"Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko", "EOL"},
		{"Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)", "EOL"},
		{"Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/25.0 Chrome/121.0.0.0 Mobile Safari/537.36", ""},
		{"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.1 Safari/605.1.15", ""},
		{"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", ""},
		{"curl/8.5.0", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := uaOldBadge(classify.UASummary(c.ua)); got != c.want {
			t.Errorf("uaOldBadge(%.70s) = %q, want %q", c.ua, got, c.want)
		}
	}
	// A Firefox ESR in support trails stable on purpose.
	esr := settings.GlobalConfig{}.FirefoxESRMajors()[0]
	ua := fmt.Sprintf("Mozilla/5.0 (X11; Linux x86_64; rv:%d.0) Gecko/20100101 Firefox/%d.0", esr, esr)
	if got := uaOldBadge(classify.UASummary(ua)); got != "" {
		t.Errorf("the supported Firefox ESR (%d) is marked %q", esr, got)
	}
}

// The sentence behind the mark names the count and the release it counts
// against, in the reader's language, and there is none without a mark.
func TestUAOldNote(t *testing.T) {
	pinBrowserBaselines(t)
	en, ja := i18n.Lang("en"), i18n.Lang("ja")
	if got := uaOldNote(en, chromeUA("109")); !strings.Contains(got, "191 releases behind") || !strings.Contains(got, "(300;") {
		t.Errorf("note = %q, want the count and the current release", got)
	}
	if got := uaOldNote(ja, chromeUA("109")); !strings.Contains(got, "191 版古い") || !strings.Contains(got, "現行は 300") {
		t.Errorf("note (ja) = %q, want the count and the current release", got)
	}
	ff := "Mozilla/5.0 (Windows NT 6.1; rv:52.0) Gecko/20100101 Firefox/52.0"
	if got := uaOldNote(en, ff); !strings.Contains(got, "268 releases behind") || !strings.Contains(got, "(320;") {
		t.Errorf("Firefox note = %q, want it counted against Firefox's own release", got)
	}
	if got := uaOldNote(en, "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"); !strings.Contains(got, "Internet Explorer") {
		t.Errorf("IE note = %q", got)
	}
	for _, ua := range []string{chromeUA("300"), chromeUA("295"), "curl/8.5.0", ""} {
		if got := uaOldNote(en, ua); got != "" {
			t.Errorf("uaOldNote(%.40s) = %q, want none", ua, got)
		}
	}
}

// The note goes wherever the mark goes and nowhere else.  The stats page, the
// hunt ranking and the advisor hand uaOldNote the raw UA without asking first
// whether the cell renders as a bot (which shows the bot's name and no mark),
// so the two have to agree on their own -- including for a crawler whose UA
// is shaped like an old Chrome.
func TestUAOldNoteFollowsTheMark(t *testing.T) {
	pinBrowserBaselines(t)
	tmpl, err := loadDashboardTemplate()
	if err != nil {
		t.Fatal(err)
	}
	en := i18n.Lang("en")
	marked := 0
	for _, ua := range []string{
		chromeUA("109"),
		chromeUA("300"),
		"Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko",
		"Mozilla/5.0 (Windows NT 6.1; rv:52.0) Gecko/20100101 Firefox/52.0",
		// a listed crawler in a Chrome-shaped UA, and a bot that only names itself
		"Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36 (compatible; ExampleSiteBot/1.0)",
		// not on the crawler list: reads as the Chrome it is built from
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/91.0.4472.124 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		"curl/8.5.0",
		"UI-E2E rawua padding padding",
		"",
	} {
		var sb strings.Builder
		if err := tmpl.ExecuteTemplate(&sb, "ua_cell", ua); err != nil {
			t.Fatal(err)
		}
		mark := strings.Contains(sb.String(), `class="ua-old"`)
		note := uaOldNote(en, ua) != ""
		if mark != note {
			t.Errorf("mark=%v note=%v for %.60q: the cell and its popover disagree (cell: %s)", mark, note, ua, sb.String())
		}
		if mark {
			marked++
		}
	}
	if marked != 4 {
		t.Errorf("%d of the samples are marked, want 4 (the old Chrome, the old Firefox, Internet Explorer, the old headless Chrome)", marked)
	}
}

// The hunt log marks the rows: an old browser has its name highlighted with
// the count beside it and the sentence in the cell's popover; a current one
// renders as it always did.  The ranking above the log and the stats page
// share the mark (the same cell), and the live tail carries it as a field.
func TestHuntMarksOldBrowsers(t *testing.T) {
	pinBrowserBaselines(t)
	h := newTestHandler(t)
	old, cur := chromeUA("109"), chromeUA("300")
	const ie = "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko"
	for _, ua := range []string{old, cur, ie} {
		if _, err := h.DB.Exec(`INSERT INTO unmask_event
			(site,host,scheme,port,ip_address,user_agent,ja4,ja4_verdict,ja4_verdict_id,
			 phase,flags,reload_count,cookie_bv,cookie_br,payload_json,date_created)
			VALUES ('','','https',443,x'7f000001',?,'','',0,'serve',0,0,'','','{}',datetime('now'))`, ua); err != nil {
			t.Fatal(err)
		}
	}
	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/hunt/?range=24h", nil)
	rr := httptest.NewRecorder()
	h.AdminHuntIndex(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("hunt: %d", rr.Code)
	}
	body := rr.Body.String()
	rows := rowsOnly(body)

	const mark = `<span class="ua-old"><span class="ua-old-n">Chrome 109</span><span class="ua-lag">` + "\u2212" + `191</span></span>`
	if !strings.Contains(rows, mark) {
		t.Errorf("the old browser's row does not carry the mark %s", mark)
	}
	if !strings.Contains(rows, `<span class="ua-lag">EOL</span>`) {
		t.Error("the Internet Explorer row is not marked EOL")
	}
	if strings.Contains(rows, `<span class="ua-old-n">Chrome 300`) || !strings.Contains(rows, "Chrome 300") {
		t.Error("the current browser's row must render unmarked")
	}
	// Once in the log, and once in the UA ranking above it.  (The column
	// help carries a sample of the mark, with a count of its own.)
	if n := strings.Count(body, mark); n != 2 {
		t.Errorf("the old browser is marked %d times on the page, want 2 (the log and the ranking)", n)
	}
	// The sentence rides the cell, for its popover.
	if !strings.Contains(rows, `data-note="191 releases behind`) && !strings.Contains(rows, `data-note="現行の安定版より 191 版古い`) {
		t.Error("the marked cell carries no note for its popover")
	}
	if n := strings.Count(rows, ` data-note="`); n != 2 {
		t.Errorf("%d cells carry a note, want 2 (the old browser and IE; the current one has nothing to say)", n)
	}
	// The ranking's cells explain the mark the same way: the page as a whole
	// has the two notes twice, once in the log and once in the ranking.
	if n := strings.Count(body, `data-note="191 releases behind`) + strings.Count(body, `data-note="現行の安定版より 191 版古い`); n != 2 {
		t.Errorf("the old browser's note appears %d times on the page, want 2 (the log and the ranking)", n)
	}
	if n := strings.Count(body, ` data-note="`); n != 4 {
		t.Errorf("%d cells on the page carry a note, want 4 (two browsers, in the log and in the ranking)", n)
	}

	// The stats page renders the same cell.
	tmpl, err := loadDashboardTemplate()
	if err != nil {
		t.Fatal(err)
	}
	var sb strings.Builder
	if err := tmpl.ExecuteTemplate(&sb, "ua_cell", old); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sb.String(), mark) {
		t.Errorf("ua_cell renders %q, want the mark", sb.String())
	}
	sb.Reset()
	if err := tmpl.ExecuteTemplate(&sb, "ua_cell", cur); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sb.String(), "ua-old") {
		t.Errorf("ua_cell marks a current browser: %q", sb.String())
	}

	// The live tail's row carries the mark for the client to draw.
	b, _ := json.Marshal(streamRow{UAShort: classify.UASummary(old), UAOld: uaOldBadge(classify.UASummary(old))})
	if !strings.Contains(string(b), `"ua_old":"`+"\u2212"+`191"`) {
		t.Errorf("the tail row is %s, want ua_old", b)
	}
	b, _ = json.Marshal(streamRow{UAShort: classify.UASummary(cur), UAOld: uaOldBadge(classify.UASummary(cur))})
	if strings.Contains(string(b), "ua_old") {
		t.Errorf("the tail row of a current browser carries ua_old: %s", b)
	}
	// And the page's script draws it from that field.
	raw, err := assets.Templates.ReadFile("templates/hunt.html")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `if (ev.ua_old && ev.ua_short) {`) || !strings.Contains(string(raw), `'</span><span class="ua-lag">' + escapeText(ev.ua_old) + '</span></span>'`) {
		t.Error("the live tail no longer draws the old-browser mark")
	}
}

// The stats page's UA columns wear the mark through the shared cell, and each
// of those cells explains it: the sentence is on the cell for the popover,
// and absent where there is no mark.  Several of the page's tables are fed
// here -- a cookie-reuse ranking, the rate-limit ranking, the JS error lists,
// the failed cookie writes -- because each has its own copy of the cell's
// opening tag, and one whose note cannot be resolved stops the page mid-way
// with a 200.
func TestStatsMarksOldBrowsersAndExplainsThem(t *testing.T) {
	pinBrowserBaselines(t)
	// The stats page reads the aggregate tables, which only the real
	// migrations create (newTestHandler's schema is the event table alone).
	conn, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: filepath.Join(t.TempDir(), "t.sqlite")})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := db.Migrate(conn); err != nil {
		t.Fatal(err)
	}
	h := &Handler{DB: conn}
	h.SetSettings(settings.Settings{})
	old, cur := chromeUA("109"), chromeUA("300")
	min := time.Now().Unix() / 60
	last := time.Now().UTC().Format("2006-01-02 15:04:05.000")
	for i, ua := range []string{old, cur} {
		if _, err := conn.Exec(`INSERT INTO unmask_cookie_ip_minute
			(bucket_min, site, ip, kind, ja4, ua, cnt, last_seen)
			VALUES (?, 'default', ?, 'pow', 't13d_uaold', ?, ?, ?)`,
			min-1, events.PackIP(fmt.Sprintf("198.51.100.%d", 30+i)), ua, 4000-i, last); err != nil {
			t.Fatal(err)
		}
	}
	// One event per table that is built from the event log, all from the old
	// browser: a rate-limited serve, a JS error of the challenge's own and a
	// foreign one, a cookie that could not be written, a failed CAPTCHA, a
	// reload loop, and a CAPTCHA pass under a verdict the presets call a bot
	// (the stealth table, and the CAPTCHA report's ranking and latest list).
	// Two minutes old, so they sit inside the page's window whatever second
	// the request lands in.
	evAt := time.Now().Add(-2 * time.Minute).UTC().Format("2006-01-02 15:04:05.000")
	botVerdict := dashboard.BotVerdictNames(settings.Settings{}.Nginx)[0]
	for i, ev := range []struct {
		phase, verdict, payload string
		reloads                 int
	}{
		{"serve", "", `{"rl":1,"orig_path":"/search"}`, 0},
		{"error", "", `{"msg":"boom","src":"challenge.js"}`, 0},
		{"error", "", `{"kind":"js_foreign","msg":"boom"}`, 0},
		{"bv_pow_only", "", `{"cookie_set_ok":false}`, 0},
		{"verify_ng", "", `{"method":"captcha","score":0.1}`, 0},
		{"load", "", `{}`, 3},
		{"bv_captcha_only", botVerdict, `{}`, 0},
	} {
		if _, err := conn.Exec(`INSERT INTO unmask_event
			(site,host,scheme,port,ip_address,user_agent,ja4,ja4_verdict,ja4_verdict_id,
			 phase,flags,reload_count,cookie_bv,cookie_br,payload_json,date_created)
			VALUES ('default','','https',443,?,?,'t13d_uaold',?,0,?,0,?,'','',?,?)`,
			events.PackIP(fmt.Sprintf("198.51.100.%d", 40+i)), old, ev.verdict, ev.phase, ev.reloads, ev.payload, evAt); err != nil {
			t.Fatal(err)
		}
	}
	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/stats/default/?range=24h", nil)
	req.SetPathValue("site", "default")
	rr := httptest.NewRecorder()
	h.AdminStats(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("stats page status %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.HasSuffix(strings.TrimSpace(body), "</html>") {
		t.Fatalf("the stats page stopped before its end (%d bytes): a template error", len(body))
	}
	const mark = `<span class="ua-old"><span class="ua-old-n">Chrome 109</span><span class="ua-lag">` + "\u2212" + `191</span></span>`
	// Every UA cell that wears the mark carries the sentence; walk them all.
	marked := 0
	for rest := body; ; {
		i := strings.Index(rest, mark)
		if i < 0 {
			break
		}
		td := rest[strings.LastIndex(rest[:i], "<td"):i]
		if !strings.Contains(td, `class="bcd-ua`) {
			t.Errorf("the mark sits outside a stats UA cell: %s", td)
		}
		if !strings.Contains(td, `data-note="191 releases behind`) && !strings.Contains(td, `data-note="現行の安定版より 191 版古い`) {
			t.Errorf("a marked stats cell carries no note for its popover: %s", td)
		}
		marked++
		rest = rest[i+len(mark):]
	}
	// One per copy of the cell in the template: the reuse ranking, the
	// rate-limit ranking, both JS error lists, the failed cookie writes, the
	// failed CAPTCHAs, the reload loops, the stealth table, and the CAPTCHA
	// report's ranking and latest list.
	raw, err := assets.Templates.ReadFile("templates/dashboard.html")
	if err != nil {
		t.Fatal(err)
	}
	if copies := strings.Count(string(raw), `{{ template "ua_cell" `); marked != copies {
		t.Errorf("%d stats cells wear the mark, but the template has %d UA columns: a table is not fed by this test, or one lost the mark", marked, copies)
	}
	if n := strings.Count(body, ` data-note="`); n != marked {
		t.Errorf("%d cells carry a note, %d wear the mark: a note goes with a mark and only with one", n, marked)
	}
	j := strings.Index(body, "Chrome 300")
	if j < 0 {
		t.Fatal("the current browser's row is missing")
	}
	if td := body[strings.LastIndex(body[:j], "<td"):j]; strings.Contains(td, "data-note") || strings.Contains(td, "ua-old") {
		t.Errorf("a current browser's stats cell is marked or noted: %s", td)
	}
}

// The hunt ranking and the advisor's UA lines keep their own copy of the
// cell's opening tag; each hands the note to the popover the same way.  (What
// they render is checked where the pages are: TestHuntMarksOldBrowsers and
// TestAdvisorStoredContainedPickIsHidden.)
func TestRankingAndAdvisorCellsCarryTheNote(t *testing.T) {
	for file, want := range map[string]string{
		"templates/advisor.html": `{{ with uaOldNote $.Lang .UA }} data-note="{{ . }}"{{ end }}>{{ template "ua_cell" .UA }}`,
		"templates/hunt.html":    `{{ with uaOldNote $.Lang .Key }} data-note="{{ . }}"{{ end }}>{{ if .Key }}<span class="ua-sum">`,
	} {
		raw, err := assets.Templates.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(raw), want) {
			t.Errorf("%s: the UA cell no longer carries the old-version note", file)
		}
	}
}
