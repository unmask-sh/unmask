package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The reuse cap's per-pass budget is two fields on the rate-limit tab -- so
// many requests every so many minutes -- and the card has to post what it
// shows.  Read the rendered form back the way a browser submits it:
//
//   - a tuned window (and the rest of the card off its seeds) survives a save
//     of the tab as displayed, byte for byte in config.yml;
//   - the fields carry the stored figures, the seeds as placeholders, and the
//     limits the server enforces;
//   - a figure below its window's minutes is refused, with the config left as
//     it was;
//   - the hour-only field the pair replaced is gone from the form.
func TestReusePassWindowFormRoundTrip(t *testing.T) {
	h := newTestHandler(t)
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yml")

	// A real fresh install (TestSettingsTabsNoOpSave explains the seed), with
	// every field of the card off its built-in value.
	emptyPath := filepath.Join(dir, "empty-seed.yml")
	if err := os.WriteFile(emptyPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := settings.Load(emptyPath)
	if err != nil {
		t.Fatal(err)
	}
	s.Server.Bind = "127.0.0.1"
	s.Server.Port = 9477
	s.Server.BasePath = "/unmask"
	h.Version = "9.9.9"
	s.Nginx.SeenVersion = "v9.9.9"
	s.Nginx.OutputDir = dir
	s.CommunityBans.MapDir = dir
	s.RateLimit.Reuse = settings.ReuseLimitConfig{PassRequests: 300, PassMinutes: 5, PerDay: 20000, Burst: 3000, Action: "deny"}
	if err := settings.Save(s, cfgPath); err != nil {
		t.Fatal(err)
	}
	h.ConfigPath = cfgPath
	loaded, err := settings.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	h.SetSettings(loaded)

	page := func() string {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/unmask/admin/settings/?tab=rate-limit", nil)
		req.SetPathValue("tab", "rate-limit")
		rr := httptest.NewRecorder()
		h.AdminSettingsIndex(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("settings GET tab=rate-limit: want 200, got %d", rr.Code)
		}
		return rr.Body.String()
	}
	rateForm := func(doc string) htmlForm {
		t.Helper()
		for _, f := range parseForms(doc) {
			if sectionOf(f.action) == "rate_limit" {
				return f
			}
		}
		t.Fatal("the rate-limit tab rendered no rate_limit form")
		return htmlForm{}
	}
	// post saves the tab and returns where the save landed and, for a
	// refused one, the message the page shows (the err flash).
	post := func(v url.Values) (loc, refusal string) {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/unmask/admin/settings/save?section=rate_limit", strings.NewReader(v.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		h.AdminSettingsSave(rr, req)
		if rr.Code != http.StatusFound && rr.Code != http.StatusSeeOther {
			t.Fatalf("save: want a redirect, got %d body=%s", rr.Code, rr.Body.String())
		}
		for _, c := range rr.Result().Cookies() {
			if c.Name == flashCookiePrefix+"err" {
				refusal, _ = url.QueryUnescape(c.Value)
			}
		}
		return rr.Header().Get("Location"), refusal
	}
	// field returns the attributes of the page's <input name=...>.
	field := func(doc, name string) map[string]string {
		t.Helper()
		for pos := 0; ; {
			body, start, end := scanTag(doc, "input", pos)
			if start < 0 {
				t.Fatalf("the page has no <input name=%q>", name)
			}
			if a := parseAttrs(body); a["name"] == name {
				return a
			}
			pos = end
		}
	}
	// pair checks the two fields: what they show, and that the limits and
	// the seeds they announce are the ones the server holds -- a browser
	// stops a figure out of range before the save does.
	pair := func(doc, wantRequests, wantMinutes string) {
		t.Helper()
		for _, c := range []struct {
			name, value string
			seed, max   int
		}{
			{"reuse_pass_requests", wantRequests, settings.ReusePassSeedRequests, settings.ReusePassMaxRequests},
			{"reuse_pass_minutes", wantMinutes, settings.ReusePassSeedMinutes, settings.ReusePassMaxMinutes},
		} {
			a := field(doc, c.name)
			if a["type"] != "number" || a["min"] != "1" || a["max"] != strconv.Itoa(c.max) || a["step"] != "1" {
				t.Errorf("%s: type %q min %q max %q step %q, want a whole number in 1-%d", c.name, a["type"], a["min"], a["max"], a["step"], c.max)
			}
			if a["placeholder"] != strconv.Itoa(c.seed) {
				t.Errorf("%s: placeholder %q, want the seed %d", c.name, a["placeholder"], c.seed)
			}
			if a["value"] != c.value {
				t.Errorf("%s shows %q, want %q", c.name, a["value"], c.value)
			}
			if a["aria-label"] == "" || strings.HasPrefix(a["aria-label"], "settings.") {
				t.Errorf("%s has no name of its own for a screen reader: %q", c.name, a["aria-label"])
			}
		}
	}
	stored := func() (settings.ReuseLimitConfig, string) {
		t.Helper()
		got, err := settings.Load(cfgPath)
		if err != nil {
			t.Fatal(err)
		}
		y, err := settings.MarshalYAML(got)
		if err != nil {
			t.Fatal(err)
		}
		return got.RateLimit.Reuse, y
	}

	doc := page()
	form := rateForm(doc)
	v := form.values()
	if got := v.Get("reuse_pass_requests"); got != "300" {
		t.Errorf("the figure field shows %q, want the stored 300", got)
	}
	if got := v.Get("reuse_pass_minutes"); got != "5" {
		t.Errorf("the minutes field shows %q, want the stored 5", got)
	}
	if _, ok := v["reuse_pass_per_hour"]; ok {
		t.Error("the hour-only field is still in the form")
	}
	pair(doc, "300", "5")
	// The note the card's own check fills in, and the words it fills it with.
	for _, want := range []string{`id="rl-reuse-pass-err"`, "must be at least its minutes"} {
		if !strings.Contains(doc, want) {
			t.Errorf("the card lacks %q", want)
		}
	}

	// Saved as displayed: nothing in config.yml moves.
	_, before := stored()
	if loc, refusal := post(v); !strings.Contains(loc, "saved=1") {
		t.Fatalf("saving the tab as displayed was refused: %q (Location=%q)", refusal, loc)
	}
	ru, after := stored()
	if before != after {
		t.Errorf("a no-op save of a tuned card changed the config:\n%s", yamlDiff(before, after))
	}
	if ru != (settings.ReuseLimitConfig{PassRequests: 300, PassMinutes: 5, PerDay: 20000, Burst: 3000, Action: "deny"}) {
		t.Errorf("stored %+v", ru)
	}

	// A figure below its window's minutes: refused, and nothing is written.
	for _, bad := range [][2]string{{"4", "5"}, {"", "501"}, {"59", ""}} {
		v := rateForm(page()).values()
		v.Set("reuse_pass_requests", bad[0])
		v.Set("reuse_pass_minutes", bad[1])
		loc, refusal := post(v)
		if strings.Contains(loc, "saved=1") {
			t.Errorf("%q every %q minutes was saved, want it refused (Location=%q)", bad[0], bad[1], loc)
		}
		if !strings.Contains(refusal, "reuse_pass_requests") || !strings.Contains(refusal, "at least its window's minutes") {
			t.Errorf("%q every %q minutes: the refusal does not say which fields and why: %q", bad[0], bad[1], refusal)
		}
		if _, now := stored(); now != after {
			t.Errorf("%q every %q minutes: a refused save changed the config:\n%s", bad[0], bad[1], yamlDiff(after, now))
		}
	}

	// Both fields cleared: the budget is back at its seeds, and the keys leave
	// config.yml.
	v = rateForm(page()).values()
	v.Set("reuse_pass_requests", "")
	v.Set("reuse_pass_minutes", "")
	if loc, refusal := post(v); !strings.Contains(loc, "saved=1") {
		t.Fatalf("clearing the pair was refused: %q (Location=%q)", refusal, loc)
	}
	ru, y := stored()
	if ru.PassRequests != 0 || ru.PassMinutes != 0 || ru.ResolvedPassRequests() != 500 || ru.ResolvedPassMinutes() != 60 {
		t.Errorf("cleared pair stored %+v", ru)
	}
	if strings.Contains(y, "pass_requests") || strings.Contains(y, "pass_minutes") {
		t.Errorf("cleared fields must write no key:\n%s", y)
	}
	if ru.PerDay != 20000 || ru.Burst != 3000 || ru.Action != "deny" {
		t.Errorf("clearing the pair changed the rest of the card: %+v", ru)
	}
	// And the cleared card shows the seeds as placeholders, with no value.
	pair(page(), "", "")
}
