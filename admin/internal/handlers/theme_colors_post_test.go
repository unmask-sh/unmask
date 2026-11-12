package handlers

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// tickedValue: what a browser posts for the checkbox of that name once it is
// ticked -- its value attribute, or "on" where it has none.
func tickedValue(t *testing.T, f htmlForm, name string) string {
	t.Helper()
	for _, fld := range f.fields {
		if fld.name == name && fld.typ == "checkbox" {
			if fld.value == "" {
				return "on"
			}
			return fld.value
		}
	}
	t.Fatalf("the form has no checkbox named %q", name)
	return ""
}

// A theme's "customize" box, ticked on the page, has to reach the server as
// the value the server reads.  The boxes carried no value attribute, so a
// browser posted "on"; the handler takes "1" and read every box as unticked.
// The save was answered as taken and no colour was ever stored from the page.
// The handler's other tests post the "1" themselves, which is why this one
// takes the value from the rendered form.
func TestThemeColoursTickedOnThePageAreStored(t *testing.T) {
	h := newTestHandler(t)
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty-seed.yml")
	if err := os.WriteFile(empty, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := settings.Load(empty)
	if err != nil {
		t.Fatal(err)
	}
	s.Server.BasePath = "/unmask"
	h.Version = "9.9.9"
	s.Nginx.SeenVersion = "v9.9.9"
	s.Nginx.OutputDir = filepath.Join(dir, "nginx")
	s.CommunityBans.MapDir = dir
	h.ConfigPath = filepath.Join(dir, "config.yml")
	if err := settings.Save(s, h.ConfigPath); err != nil {
		t.Fatal(err)
	}
	loaded, err := settings.Load(h.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	h.SetSettings(loaded)

	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/settings/theme/", nil)
	req.SetPathValue("tab", "theme")
	rr := httptest.NewRecorder()
	h.AdminSettingsIndex(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET theme tab: %d", rr.Code)
	}
	var form *htmlForm
	for _, f := range parseForms(rr.Body.String()) {
		if sectionOf(f.action) == "appearance" {
			form = &f
			break
		}
	}
	if form == nil {
		t.Fatal("the theme tab has no appearance form")
	}

	vals := form.values()
	for _, box := range []string{"custom_on_dark", "deny_custom_on_light", "ban_custom_on_dark"} {
		vals.Set(box, tickedValue(t, *form, box))
	}
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for k, vs := range vals {
		for _, v := range vs {
			if err := mw.WriteField(k, v); err != nil {
				t.Fatal(err)
			}
		}
	}
	_ = mw.Close()
	post := httptest.NewRequest(http.MethodPost, "/unmask/admin/settings/save?section="+url.QueryEscape("appearance"), &buf)
	post.Header.Set("Content-Type", mw.FormDataContentType())
	rr = httptest.NewRecorder()
	h.AdminSettingsSave(rr, post)
	if rr.Code != http.StatusFound || !strings.Contains(rr.Header().Get("Location"), "saved=1") {
		t.Fatalf("save: %d %s", rr.Code, rr.Header().Get("Location"))
	}

	cur, err := settings.Load(h.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	b := cur.Branding.Default
	if bg, text := b.CustomColorsFor("dark"); bg == "" || text == "" {
		t.Errorf("the dark theme's box was ticked on the page and no colours were stored for it: %v", b.CustomColors)
	}
	if bg, _ := b.DenyRateColorsFor("light"); bg == "" {
		t.Errorf("the deny page's light box was ticked on the page and no colours were stored for it: %v", b.DenyRateColors)
	}
	if bg, _ := b.DenyBanColorsFor("dark"); bg == "" {
		t.Errorf("the ban page's dark box was ticked on the page and no colours were stored for it: %v", b.DenyBanColors)
	}
}
