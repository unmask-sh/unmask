package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
	_ "time/tzdata" // the zones below, wherever the test runs

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The answer's times are the operator's: the TZ picker's zone when one is
// set, else the browser's, sent with the question; a name that is not a zone
// is UTC.
func TestAskLocation(t *testing.T) {
	post := func(form url.Values, cookie string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/admin/ask/send", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if cookie != "" {
			r.AddCookie(&http.Cookie{Name: tzCookieName, Value: cookie})
		}
		return r
	}
	for _, c := range []struct {
		name, cookie, tz, want string
	}{
		{"picker", "Europe/London", "Asia/Tokyo", "Europe/London"},
		{"browser", "", "Asia/Tokyo", "Asia/Tokyo"},
		{"picker on browser", "browser", "America/New_York", "America/New_York"},
		{"not a zone", "", "../../etc/passwd", "UTC"},
		{"none", "", "", "UTC"},
	} {
		if got := askLocation(post(url.Values{"q": {"x"}, "tz": {c.tz}}, c.cookie)).String(); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
}

// The note set after the question carries the operator's clock and today's
// browser versions.
func TestAskContext(t *testing.T) {
	loc, err := time.LoadLocation("Asia/Tokyo")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 13, 17, 5, 0, 0, time.UTC)
	note := askContext(now, loc, settings.GlobalConfig{})
	for _, want := range []string{"Now: 2026-10-14 02:05 +09:00", "time zone Asia/Tokyo", "Chrome ", "Firefox "} {
		if !strings.Contains(note, want) {
			t.Errorf("note missing %q: %s", want, note)
		}
	}
}

// The crawlers tool hands the model the dashboard's crawler card: each
// category with its crawlers, their requests, challenged and passed, and
// whether a crawler passes only from its published ranges.
func TestAskCrawlers(t *testing.T) {
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: t.TempDir() + "/s.sqlite"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	if err := db.Migrate(d); err != nil {
		t.Fatal(err)
	}
	h := &Handler{DB: d}
	now := time.Now().Unix()
	if _, err := d.Exec(`INSERT INTO unmask_crawler_minute (bucket_min, category, total, served) VALUES (?, 'search-engine', 150, 15)`, now/60-5); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`INSERT INTO unmask_crawler_detail_hourly (bucket_hour, category, crawler, total, served) VALUES (?, 'search-engine', 'Googlebot', 150, 15)`, now/3600); err != nil {
		t.Fatal(err)
	}
	out, err := h.askCrawlers(context.Background(), 24)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(out)
	js := string(b)
	for _, want := range []string{`"category":"search-engine"`, `"requests":150`, `"challenged":15`, `"passed":135`, `"crawler":"Googlebot"`, `"range_verified":`, "impostors"} {
		if !strings.Contains(js, want) {
			t.Errorf("crawlers missing %s: %s", want, js)
		}
	}
	if strings.Count(js, `"category":`) != 1 {
		t.Errorf("only categories with traffic are listed: %s", js)
	}
}

// Bold and inline code are not drawn: the asterisks and backticks go, the
// words stay, a path inside backticks is still a link, and a fenced block
// is left as it is.
func TestPlainProse(t *testing.T) {
	parts := splitFences("**見直すべき設定はありません。** BAN は `/admin/bans/` で。\n```\na **b** `c`\n```\n")
	var prose, code strings.Builder
	link := false
	for _, p := range parts {
		if p.Code {
			code.WriteString(p.Text)
			continue
		}
		prose.WriteString(p.Text)
		if p.Link == "/admin/bans/" {
			link = true
		}
	}
	if s := prose.String(); strings.ContainsAny(s, "*`") || !strings.Contains(s, "見直すべき設定はありません。") {
		t.Errorf("prose: %q", s)
	}
	if !link {
		t.Errorf("the path inside backticks must still be a link: %+v", parts)
	}
	if code.String() != "a **b** `c`" {
		t.Errorf("a fenced block is left as written: %q", code.String())
	}
}
