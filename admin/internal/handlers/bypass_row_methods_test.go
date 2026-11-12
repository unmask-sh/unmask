package handlers

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/i18n"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The bypass-paths rows carry a methods picker: "safe" stores the row as GET /
// HEAD / OPTIONS only, nothing stores it as every method, and anything else
// is refused -- read as "every method" it would drop a restriction the
// operator asked for.  A blank row between two rows must not shift the
// column.
func TestBypassPathRowMethodsForm(t *testing.T) {
	post := func(form url.Values) (settings.Nginx, error) {
		t.Helper()
		r := httptest.NewRequest("POST", "/", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		var n settings.Nginx
		err := applyBypassPathsForm(&n, r, i18n.LangEN)
		return n, err
	}

	n, err := post(url.Values{
		"bp_path":    {"^/feed/", "", "^/hooks/", "^/rss\\.xml$"},
		"bp_enabled": {"1", "1", "1", "1"},
		"bp_site":    {"", "", "", "shop.example.com"},
		"bp_methods": {"safe", "safe", "", "safe"},
	})
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	type row struct {
		path, site string
		safe       bool
	}
	want := []row{{"^/feed/", "", true}, {"^/hooks/", "", false}, {"^/rss\\.xml$", "shop.example.com", true}}
	if len(n.BypassPaths.Paths) != len(want) {
		t.Fatalf("rows = %+v, want %d", n.BypassPaths.Paths, len(want))
	}
	for i, w := range want {
		g := n.BypassPaths.Paths[i]
		if g.Path != w.path || g.Site != w.site || g.SafeMethodsOnly != w.safe {
			t.Errorf("row %d = {%q %q safe=%v}, want {%q %q safe=%v}", i, g.Path, g.Site, g.SafeMethodsOnly, w.path, w.site, w.safe)
		}
	}

	// A page from before the picker posts no bp_methods: every method.
	n, err = post(url.Values{"bp_path": {"^/feed/"}, "bp_enabled": {"1"}})
	if err != nil || len(n.BypassPaths.Paths) != 1 || n.BypassPaths.Paths[0].SafeMethodsOnly {
		t.Errorf("no picker posted: rows %+v, err %v; want one every-method row", n.BypassPaths.Paths, err)
	}

	_, err = post(url.Values{"bp_path": {"^/feed/"}, "bp_enabled": {"1"}, "bp_methods": {"get"}})
	var lf *listFieldError
	if !errors.As(err, &lf) || lf.Field != "bp_path" || lf.Value != "^/feed/" {
		t.Errorf("an unknown methods value must be refused on its row, got %v", err)
	}
}

// A rejected save re-renders what was typed: the row's methods ride the
// draft, so the error page does not hand back a restricted row as an
// every-method one.  The exempt-path lists share the overlay and have no such
// column.
func TestBypassPathRowMethodsDraft(t *testing.T) {
	rows := listRows{
		Values:  []string{"^/feed/", "^/hooks/"},
		Actions: []string{"safe", ""},
		Sites:   []string{"", "shop.example.com"},
	}
	got := overlayBypassPaths(rows)
	if len(got) != 2 || !got[0].SafeMethodsOnly || got[1].SafeMethodsOnly || got[1].Site != "shop.example.com" {
		t.Errorf("overlay = %+v, want the first row restricted, the second not", got)
	}
	if got := overlayBypassPaths(listRows{Values: []string{"^/rss"}}); len(got) != 1 || got[0].SafeMethodsOnly {
		t.Errorf("a list without the column = %+v, want an every-method row", got)
	}
	var spec *ruleListSpec
	for i, sp := range ruleListRegistry["bypass-paths"] {
		if sp.Name == "bp_path" {
			spec = &ruleListRegistry["bypass-paths"][i]
		}
	}
	if spec == nil || spec.Action != "bp_methods" {
		t.Errorf("the bypass-paths draft must carry bp_methods: %+v", spec)
	}
}

// Saved through the page and read back: config.yml holds the restriction, and
// the tab shows it -- the picker on the stored value, the folded row naming
// the methods -- while an every-method row shows neither.
func TestBypassPathRowMethodsSaveAndRender(t *testing.T) {
	h := ruleTestHandler(t)
	form := url.Values{
		"bp_path":    {"^/feed/", "^/hooks/"},
		"bp_title":   {"feed", "hooks"},
		"bp_enabled": {"1", "1"},
		"bp_site":    {"", ""},
		"bp_methods": {"safe", ""},
	}
	req := httptest.NewRequest(http.MethodPost, "/unmask/admin/settings/save?section=bypass-paths", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.AdminSettingsSave(rr, req)
	if rr.Code >= 400 {
		t.Fatalf("save: HTTP %d", rr.Code)
	}
	cur, err := settings.Load(h.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	p := cur.Nginx.BypassPaths.Paths
	if len(p) != 2 || !p[0].SafeMethodsOnly || p[1].SafeMethodsOnly {
		t.Fatalf("config.yml rows = %+v, want /feed/ restricted and /hooks/ not", p)
	}

	body := renderSettingsTab(t, h, "bypass-paths")
	rowOf := func(pat string) string {
		t.Helper()
		i := strings.Index(body, `name="bp_path"  value="`+pat+`"`)
		if i < 0 {
			t.Fatalf("no row for %s on the tab", pat)
		}
		start := strings.LastIndex(body[:i], `<div class="rule-row`)
		end := strings.Index(body[i:], `class="rule-row`)
		if end < 0 {
			end = len(body) - i
		}
		return body[start : i+end]
	}
	selected := regexp.MustCompile(`<option value="(safe)?"\s+selected>`)
	feed, hooks := rowOf("^/feed/"), rowOf("^/hooks/")
	if m := selected.FindStringSubmatch(feed); m == nil || m[1] != "safe" {
		t.Errorf("the restricted row's picker is not on \"safe\":\n%s", feed)
	}
	if !strings.Contains(feed, `data-pill="methods"`) {
		t.Errorf("the restricted row's folded view does not name the methods:\n%s", feed)
	}
	if m := selected.FindStringSubmatch(hooks); m == nil || m[1] != "" {
		t.Errorf("the every-method row's picker is not on the first option:\n%s", hooks)
	}
	if strings.Contains(hooks, `data-pill="methods"`) {
		t.Errorf("the every-method row carries a methods pill:\n%s", hooks)
	}
}

// Forward-auth reads the row as native renders it: GET / HEAD / OPTIONS pass,
// a POST is judged (here the protected rule on the same path challenges it),
// for a row naming every site and for a row naming one.  An every-method row
// passes its POSTs, and a row for another site does not reach this one.
func TestAuthCheckBypassRowSafeMethods(t *testing.T) {
	cfg := settings.Settings{Nginx: settings.Nginx{
		BypassPaths: settings.BypassPathsConfig{
			Paths: []settings.BypassPath{
				{Path: `^/feed/`, SafeMethodsOnly: true},
				{Path: `^/rss\.xml$`, Site: "shop.example.com", SafeMethodsOnly: true},
				{Path: `^/other\.xml$`, Site: "blog.example.com", SafeMethodsOnly: true},
				{Path: `^/hooks/`},
				{Path: `^/off/`, SafeMethodsOnly: true, Disabled: true},
			},
		},
		ProtectedPaths: settings.ProtectedPathsConfig{
			Paths: []settings.ProtectedPath{{Path: `^/feed/`}, {Path: `^/rss\.xml$`}, {Path: `^/other\.xml$`}, {Path: `^/hooks/`}, {Path: `^/off/`}},
		},
	}}
	check := func(uri, method string) *http.Response {
		t.Helper()
		h := &Handler{}
		h.SetSettings(cfg)
		r := httptest.NewRequest(http.MethodGet, "/unmask/api/check", nil)
		r.Header.Set("X-Original-URI", uri)
		r.Header.Set("X-Original-IP", "203.0.113.50")
		r.Header.Set("X-Original-Host", "shop.example.com")
		if method != "" {
			r.Header.Set("X-Original-Method", method)
		}
		r.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36")
		w := httptest.NewRecorder()
		h.AuthCheck(w, r)
		return w.Result()
	}
	cases := []struct {
		name, uri, method string
		pass              bool
	}{
		{"every-site row GET", "/feed/atom", "GET", true},
		{"every-site row HEAD", "/feed/atom", "HEAD", true},
		{"every-site row OPTIONS", "/feed/atom", "OPTIONS", true},
		{"every-site row POST", "/feed/atom", "POST", false},
		{"every-site row DELETE", "/feed/atom", "DELETE", false},
		{"one-site row GET", "/rss.xml", "GET", true},
		{"one-site row POST", "/rss.xml", "POST", false},
		{"another site's row GET", "/other.xml", "GET", false},
		{"every-method row POST", "/hooks/deploy", "POST", true},
		{"row switched off GET", "/off/x", "GET", false},
		// A snippet from before the method header: the restricted row passes
		// whatever was sent, as the presets do there.
		{"no method header", "/feed/atom", "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := check(c.uri, c.method)
			reason := res.Header.Get("X-Unmask-Reason")
			bypassed := reason == "bypass:path" && res.StatusCode == http.StatusOK
			if bypassed != c.pass {
				t.Errorf("status %d reason %q: bypassed = %v, want %v", res.StatusCode, reason, bypassed, c.pass)
			}
		})
	}
}
