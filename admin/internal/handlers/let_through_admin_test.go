package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/ban"
	"github.com/unmask-sh/unmask/admin/internal/events"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestLetThroughPage drives the "Let through" tab against a migrated
// database: the grounds requests passed on, the addresses behind them with
// the BAN form, the mark on an address nothing shows to have met the
// challenge, and the pass cookie counted without a list.
func TestLetThroughPage(t *testing.T) {
	conn := migratedDB(t)
	now := time.Now().Unix()
	hour := now / 3600
	at := time.Unix(now-120, 0).UTC().Format("2006-01-02 15:04:05.000")
	total := func(reason, detail string, cnt int) {
		t.Helper()
		if _, err := conn.Exec(`INSERT INTO unmask_let_hourly (bucket_hour, site, reason, detail, cnt, ips) VALUES (?, 'a.example', ?, ?, ?, NULL)`,
			hour, reason, detail, cnt); err != nil {
			t.Fatal(err)
		}
	}
	addr := func(reason, detail, ip string, cnt int, path string) {
		t.Helper()
		if _, err := conn.Exec(`INSERT INTO unmask_let_ip_hourly (bucket_hour, site, reason, detail, ip, cnt, first_seen, last_seen, ja4, ua, path)
			VALUES (?, 'a.example', ?, ?, ?, ?, ?, ?, 't13d_x', ?, ?)`,
			hour, reason, detail, events.PackIP(ip), cnt, at, at, "ProbeUA/1.0 "+ip, path); err != nil {
			t.Fatal(err)
		}
	}
	total("cookie", "captcha", 4000)
	total("name", "ExampleBot", 61)
	addr("name", "ExampleBot", "203.0.113.41", 60, "/news/latest")
	addr("name", "ExampleBot", "203.0.113.42", 1, "/news/older")
	total("path", "list:partner API", 7)
	addr("path", "list:partner API", "203.0.113.43", 7, "/api/v1/items")
	total("path", "static-assets", 3)
	addr("path", "static-assets", "203.0.113.45", 3, "/robots.txt")
	total("ip", "list:office", 5)
	addr("ip", "list:office", "203.0.113.46", 5, "/status")
	total("none", "", 2)
	addr("none", "", "203.0.113.44", 2, "/admin/")
	total("future", "", 3) // a ground a newer configuration logs
	// 203.0.113.42 was shown a challenge in the window.
	if _, err := conn.Exec(`INSERT INTO unmask_event (site, host, ip_address, user_agent, phase, payload_json, date_created)
		VALUES ('a.example', 'h', ?, 'UA', 'serve', '{}', ?)`, events.PackIP("203.0.113.42"), at); err != nil {
		t.Fatal(err)
	}

	h := &Handler{DB: conn}
	var s settings.Settings
	s.Server.BasePath = "/unmask"
	s.Nginx.StatsExcludeIPs = []string{"192.0.2.0/24"}
	h.SetSettings(s)

	get := func(target string) string {
		t.Helper()
		req := asRole(httptest.NewRequest(http.MethodGet, target, nil), "admin")
		req.Header.Set("Accept-Language", "en")
		rr := httptest.NewRecorder()
		h.AdminLetThroughIndex(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("GET %s: %d %s", target, rr.Code, rr.Body.String())
		}
		return rr.Body.String()
	}
	body := get("/unmask/admin/let-through/")

	section := func(reason string) string {
		t.Helper()
		i := strings.Index(body, `data-reason="`+reason+`"`)
		if i < 0 {
			t.Fatalf("no section for the ground %q", reason)
		}
		rest := body[i:]
		if j := strings.Index(rest, "</details>"); j >= 0 {
			rest = rest[:j]
		}
		return rest
	}
	// Every ground the page knows has its block, the empty ones too.
	for _, reason := range letReasonOrder {
		section(reason)
	}

	name := section("name")
	for _, want := range []string{"203.0.113.41", "203.0.113.42", "ExampleBot", "/news/latest", "ProbeUA/1.0 203.0.113.41"} {
		if !strings.Contains(name, want) {
			t.Errorf("the name section lacks %q", want)
		}
	}
	if !strings.Contains(name, `name="return_to" value="let-through"`) || !strings.Contains(name, `name="ip" value="203.0.113.41"`) ||
		!strings.Contains(name, `name="scope" value="ip_only"`) {
		t.Error("the name section's rows have no BAN form that comes back to this page")
	}
	// The busier address never met the challenge, and is listed first; the
	// other was shown one.
	if i, j := strings.Index(name, "203.0.113.41"), strings.Index(name, "203.0.113.42"); i < 0 || j < 0 || i > j {
		t.Error("the address that never met the challenge is not listed first")
	}
	if n := strings.Count(name, `class="let-mark never"`); n != 1 {
		t.Errorf("%d addresses marked never checked in the name section, want 1", n)
	}
	if !strings.Contains(name, "let-unchecked") {
		t.Error("the name section's summary does not say an address was never checked")
	}

	// "No ground found" stands out when it has anything in it.
	if none := section("none"); !strings.Contains(none, "203.0.113.44") {
		t.Error("the address that got through on no ground is missing")
	}
	if !strings.Contains(body, `class="let-sec fault has" id="let-none" data-reason="none" open`) {
		t.Error("the fault section is not marked and open while it has requests")
	}

	// The operator's own row reads as theirs, without the prefix.
	if path := section("path"); !strings.Contains(path, "partner API") || strings.Contains(path, "list:partner API") {
		t.Error("the bypass path's own row is not named by its title alone")
	}
	// A preset is named by its label, not by its id.
	if path := section("path"); !strings.Contains(path, "Static assets") || strings.Contains(path, ">static-assets<") {
		t.Error("the bypass path preset is shown by its id, not its label")
	}
	// A bypass address is the operator's own exemption from every check:
	// that it never met the challenge is not news, and is not marked.
	if ip := section("ip"); !strings.Contains(ip, "203.0.113.46") || strings.Contains(ip, "let-mark never") || strings.Contains(ip, "let-unchecked") {
		t.Error("a bypass address is marked as never checked")
	}
	// A pass cookie is counted, never listed.
	if cookie := section("cookie"); strings.Contains(cookie, "<table") || !strings.Contains(cookie, "4,000") {
		t.Error("the pass cookie section is not a count without a list")
	}
	// A ground this version has no words for is shown under its token.
	if other := section("future"); !strings.Contains(other, "Other (future)") {
		t.Error("an unknown ground is not shown under its token")
	}
	// The one blind spot is named.
	if !strings.Contains(body, `id="let-not-recorded"`) || !strings.Contains(body, "192.0.2.0/24") {
		t.Error("the addresses excluded from statistics are not named as not recorded")
	}
	// The tab strip knows the page.
	if !strings.Contains(body, `/unmask/admin/let-through/" class="active"`) {
		t.Error("the BAN tab strip does not mark this tab")
	}

	// An hour ago and before: outside a window of one hour there is nothing.
	if _, err := conn.Exec(`UPDATE unmask_let_hourly SET bucket_hour = ?`, hour-5); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(`UPDATE unmask_let_ip_hourly SET bucket_hour = ?`, hour-5); err != nil {
		t.Fatal(err)
	}
	body = get("/unmask/admin/let-through/?window=1")
	if strings.Contains(body, "203.0.113.41") {
		t.Error("an address of five hours ago is listed in a window of one hour")
	}
	if body = get("/unmask/admin/let-through/?window=24"); !strings.Contains(body, "203.0.113.41") {
		t.Error("the address is missing from the window of a day")
	}
}

// TestLetThroughBanComesBackToTheTab: the BAN button posts through bot hunt's
// handler, as the candidates tab's does.  The operator lands back on this
// tab, in the window they were reading, and the address reads "banned"
// there instead of offering the button again.
func TestLetThroughBanComesBackToTheTab(t *testing.T) {
	conn := migratedDB(t)
	now := time.Now().Unix()
	at := time.Unix(now-120, 0).UTC().Format("2006-01-02 15:04:05.000")
	if _, err := conn.Exec(`INSERT INTO unmask_let_hourly (bucket_hour, site, reason, detail, cnt, ips) VALUES (?, 'a.example', 'name', 'ExampleBot', 9, NULL)`,
		now/3600); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(`INSERT INTO unmask_let_ip_hourly (bucket_hour, site, reason, detail, ip, cnt, first_seen, last_seen, ja4, ua, path)
		VALUES (?, 'a.example', 'name', 'ExampleBot', ?, 9, ?, ?, 't13d_x', 'ProbeUA/1.0', '/news/latest')`,
		now/3600, events.PackIP("203.0.113.41"), at, at); err != nil {
		t.Fatal(err)
	}
	h := &Handler{DB: conn}
	var s settings.Settings
	s.Server.BasePath = "/unmask"
	h.SetSettings(s)
	h.BanMgr = ban.New(conn, filepath.Join(t.TempDir(), "ban.list"), 0)

	page := func() string {
		t.Helper()
		req := asRole(httptest.NewRequest(http.MethodGet, "/unmask/admin/let-through/?window=168", nil), "admin")
		req.Header.Set("Accept-Language", "en")
		rr := httptest.NewRecorder()
		h.AdminLetThroughIndex(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("the page: %d", rr.Code)
		}
		return rr.Body.String()
	}
	before := page()
	if !strings.Contains(before, `name="ip" value="203.0.113.41"`) {
		t.Fatal("the address has no BAN form before the ban")
	}
	// What the row's form posts, with the window in the range field.
	form := url.Values{
		"op": {"ban"}, "return_to": {"let-through"}, "range": {"168"},
		"ip": {"203.0.113.41"}, "ja4": {"t13d_x"}, "scope": {"ip_only"}, "duration_sec": {"0"},
		"reason": {"let through: name (ExampleBot), never checked"},
		"share":  {""}, "comment": {""}, "accept_terms": {""},
	}
	req := asRole(httptest.NewRequest(http.MethodPost, "/unmask/admin/hunt/action", strings.NewReader(form.Encode())), "admin")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.AdminHuntAction(rr, req)
	if loc := rr.Header().Get("Location"); rr.Code != http.StatusFound || loc != "/unmask/admin/let-through/?window=168&saved=1" {
		t.Fatalf("the BAN answered %d, Location %q; want a redirect back to the tab in its window, saved", rr.Code, loc)
	}
	after := page()
	if strings.Contains(after, `name="ip" value="203.0.113.41"`) {
		t.Error("the banned address still offers the BAN button")
	}
	i := strings.Index(after, `<tr data-ip="203.0.113.41">`)
	if i < 0 || !strings.Contains(after[i:], ">banned<") {
		t.Error("the banned address does not read \"banned\" on the tab")
	}
}
