package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// Adding a second timestamp touched every custom-rule save path, and a save
// path that mis-zips its parallel arrays loses rules rather than dates.  This
// posts a section back the way the form does and checks the rules survive with
// both dates intact.
func TestSavingCustomRulesKeepsRulesAndDates(t *testing.T) {
	h := newTestHandler(t)
	s := h.snapshotSettings()
	s.Server.BasePath = "/unmask"
	cfgPath := filepath.Join(t.TempDir(), "config.yml")
	if err := settings.Save(s, cfgPath); err != nil {
		t.Fatal(err)
	}
	h.ConfigPath = cfgPath
	h.SetSettings(s)

	form := url.Values{}
	// Two protected paths: one untouched since it was added, one edited later.
	form["protected_path"] = []string{"^/wp-admin", "^/login"}
	form["protected_title"] = []string{"WP", "login"}
	form["protected_enabled"] = []string{"1", "1"}
	form["protected_mode"] = []string{"strict", "captcha"}
	form["protected_site"] = []string{"a.example", ""}
	form["protected_action"] = []string{"deny", "inherit"}
	form["protected_created_at"] = []string{"1740000000", "1740000000"}
	form["protected_updated_at"] = []string{"0", "1753000000"}

	req := httptest.NewRequest(http.MethodPost,
		"/unmask/admin/settings/save?section=protected", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.AdminSettingsSave(rr, req)
	if rr.Code != http.StatusSeeOther && rr.Code != http.StatusOK && rr.Code != http.StatusFound {
		t.Fatalf("save: %d %s", rr.Code, rr.Body.String())
	}

	if loc := rr.Header().Get("Location"); strings.Contains(loc, "err") {
		t.Fatalf("save redirected with an error: %s", loc)
	}
	saved, err := settings.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	got := saved.Nginx.ProtectedPaths.Paths
	if len(got) != 2 {
		t.Fatalf("saved %d rules, want 2: the save path lost rows", len(got))
	}
	want := []settings.ProtectedPath{
		{Path: "^/wp-admin", Title: "WP", Mode: "strict", Action: "deny", Site: "a.example",
			CreatedAt: 1740000000, UpdatedAt: 0},
		{Path: "^/login", Title: "login", Mode: "captcha",
			CreatedAt: 1740000000, UpdatedAt: 1753000000},
	}
	for i, w := range want {
		g := got[i]
		if g.Path != w.Path || g.Title != w.Title || g.Mode != w.Mode ||
			g.Action != w.Action || g.Site != w.Site {
			t.Errorf("rule %d: %+v, want %+v", i, g, w)
		}
		if g.CreatedAt != w.CreatedAt {
			t.Errorf("rule %d: add date %d, want %d (it must not move on save)", i, g.CreatedAt, w.CreatedAt)
		}
		if g.UpdatedAt != w.UpdatedAt {
			t.Errorf("rule %d: edit date %d, want %d", i, g.UpdatedAt, w.UpdatedAt)
		}
	}

	// A row with no add date gets one; the edit date stays absent, because
	// being saved for the first time is not an edit.
	form["protected_created_at"] = []string{"", ""}
	form["protected_updated_at"] = []string{"", ""}
	req = httptest.NewRequest(http.MethodPost,
		"/unmask/admin/settings/save?section=protected", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.AdminSettingsSave(httptest.NewRecorder(), req)
	saved2, err := settings.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	for i, g := range saved2.Nginx.ProtectedPaths.Paths {
		if g.CreatedAt <= 0 {
			t.Errorf("rule %d: a row with no add date did not get one", i)
		}
		if g.UpdatedAt != 0 {
			t.Errorf("rule %d: edit date %d, want 0 -- first save is not an edit", i, g.UpdatedAt)
		}
	}
}

// The value-rule lists -- defined sites, admin allowed IPs and hosts, the
// metrics allowlist -- go through their own shared partial and their own save
// helper, and were left without dates when the rule lists got them.  An
// allowlist entry is exactly the kind of row that outlives the reason it was
// added, so it needs the dates most.
func TestValueListsCarryDatesToo(t *testing.T) {
	h := newTestHandler(t)
	s := h.snapshotSettings()
	s.Server.BasePath = "/unmask"
	cfgPath := filepath.Join(t.TempDir(), "config.yml")
	if err := settings.Save(s, cfgPath); err != nil {
		t.Fatal(err)
	}
	h.ConfigPath = cfgPath
	h.SetSettings(s)

	form := url.Values{}
	form["site_mode"] = []string{"defined"}
	form["site_defined"] = []string{"shop.example.com", "blog.example.com"}
	form["site_defined_title"] = []string{"EC", "blog"}
	form["site_defined_enabled"] = []string{"1", "1"}
	form["site_defined_created_at"] = []string{"1740000000", ""}
	form["site_defined_updated_at"] = []string{"1753000000", ""}

	req := httptest.NewRequest(http.MethodPost,
		"/unmask/admin/settings/save?section=sites", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.AdminSettingsSave(rr, req)
	if loc := rr.Header().Get("Location"); strings.Contains(loc, "err") {
		t.Fatalf("save redirected with an error: %s", loc)
	}
	saved, err := settings.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	c := saved.Sites
	if len(c.Defined) != 2 {
		t.Fatalf("saved %d sites, want 2", len(c.Defined))
	}
	if len(c.DefinedCreatedAt) != 2 {
		t.Fatalf("defined sites carry %d add dates, want 2", len(c.DefinedCreatedAt))
	}
	if c.DefinedCreatedAt[0] != 1740000000 {
		t.Errorf("add date %d, want 1740000000: it must survive a save unchanged", c.DefinedCreatedAt[0])
	}
	if c.DefinedCreatedAt[1] <= 0 {
		t.Error("a row saved without an add date did not get one")
	}
	if len(c.DefinedUpdatedAt) != 2 || c.DefinedUpdatedAt[0] != 1753000000 {
		t.Errorf("edit date %v, want the posted 1753000000 to round-trip", c.DefinedUpdatedAt)
	}
	if len(c.DefinedUpdatedAt) == 2 && c.DefinedUpdatedAt[1] != 0 {
		t.Errorf("a row saved for the first time reads as edited: %d", c.DefinedUpdatedAt[1])
	}
}
