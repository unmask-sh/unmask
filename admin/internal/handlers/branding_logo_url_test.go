package handlers

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestBrandingLogoURLIsScopeScoped pins the thumbnail URL the settings page
// emits for a per-site scope.  The plain /branding/logo route resolves the
// REQUEST host, so while editing site X from an admin served on host Y it
// returned Y's logo (usually 404).  A correctly saved per-site logo then
// rendered as a broken thumbnail, which reads as "the save failed" -- the
// operator re-saves, often into whichever scope the picker happened to hold.
// The site-scoped route (admin-session gated) shows the right image.
func TestBrandingLogoURLScoped(t *testing.T) {
	dir := withTempLogoDir(t)
	logo := filepath.Join(dir, "logo.example.com.png")
	if err := os.WriteFile(logo, []byte("PNG"), 0o644); err != nil {
		t.Fatal(err)
	}
	defLogo := filepath.Join(dir, "logo.png")
	if err := os.WriteFile(defLogo, []byte("PNG"), 0o644); err != nil {
		t.Fatal(err)
	}

	h := newTestHandler(t)
	cfgPath := filepath.Join(t.TempDir(), "config.yml")
	var s settings.Settings
	s.Server.BasePath = "/unmask"
	s.Branding.Default = settings.BrandingValues{LogoPath: defLogo}
	s.Branding.Sites = map[string]settings.BrandingValues{
		"example.com":   {LogoPath: logo},
		"*.example.com": {LogoPath: logo},
	}
	if err := settings.Save(s, cfgPath); err != nil {
		t.Fatal(err)
	}
	h.ConfigPath = cfgPath
	h.SetSettings(s)

	render := func(scope string) string {
		t.Helper()
		u := "/unmask/admin/settings/?tab=theme"
		if scope != "" {
			u += "&scope=" + scope
		}
		r := httptest.NewRequest(http.MethodGet, u, nil)
		rr := httptest.NewRecorder()
		h.AdminSettingsIndex(rr, r)
		if rr.Code != http.StatusOK {
			t.Fatalf("scope=%q: status %d", scope, rr.Code)
		}
		return rr.Body.String()
	}

	// per-site scope -> site-scoped route
	if body := render("example.com"); !strings.Contains(body, "/unmask/branding/example.com/logo") {
		t.Error("per-site scope must point the thumbnail at /branding/<site>/logo")
	}
	// Default scope -> the host-resolved route (correct: Default IS the host's)
	body := render("")
	if strings.Contains(body, "/unmask/branding/example.com/logo") {
		t.Error("default scope must not use a site-scoped logo URL")
	}
	if !strings.Contains(body, "/unmask/branding/logo") {
		t.Error("default scope should use the plain /branding/logo route")
	}
	// A wildcard scope is not addressable on the site route (its path segment
	// fails the host regex), so it must fall back rather than emit a 404 URL.
	if b := render("*.example.com"); strings.Contains(b, "/branding/*.example.com/logo") {
		t.Error("wildcard scope must not emit an unroutable site-scoped URL")
	}
}

// TestBrandingSiteSaveOverrideOffDoesNotLie: a per-site save whose override
// toggle is off used to discard everything the form carried -- logo upload
// included -- and still redirect with "saved".  The page normally disables
// those fields when the toggle is off, so a deliberate "uncheck + save" (=
// drop the override) still arrives empty and must keep working; a POST that
// DOES carry values must not be reported as saved.
func TestBrandingSiteSaveOverrideOffDoesNotLie(t *testing.T) {
	newHandler := func(t *testing.T) (*Handler, string) {
		t.Helper()
		h := newTestHandler(t)
		cfgPath := filepath.Join(t.TempDir(), "config.yml")
		s := settings.Settings{}
		s.Branding.Sites = map[string]settings.BrandingValues{
			"example.com": {SiteName: "kept"},
		}
		if err := settings.Save(s, cfgPath); err != nil {
			t.Fatal(err)
		}
		h.ConfigPath = cfgPath
		return h, cfgPath
	}

	post := func(t *testing.T, h *Handler, withEdits bool) *httptest.ResponseRecorder {
		t.Helper()
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		_ = mw.WriteField("site", "example.com")
		// no use_site_override -> toggle off
		if withEdits {
			_ = mw.WriteField("branding_site_name", "Typed by the operator")
			fw, _ := mw.CreateFormFile("branding_logo_file", "logo.png")
			_, _ = fw.Write([]byte("PNG"))
		}
		_ = mw.Close()
		r := httptest.NewRequest(http.MethodPost, "/admin/settings/branding/site/save?site=example.com", &buf)
		r.Header.Set("Content-Type", mw.FormDataContentType())
		rr := httptest.NewRecorder()
		h.AdminBrandingSiteSave(rr, r)
		return rr
	}

	// (a) fields present + toggle off -> must NOT claim success, must not save
	h, cfgPath := newHandler(t)
	rr := post(t, h, true)
	if loc := rr.Header().Get("Location"); strings.Contains(loc, "saved=1") {
		t.Errorf("discarded edits reported as saved: %s", loc)
	}
	got, _ := settings.Load(cfgPath)
	if bv := got.Branding.Sites["example.com"]; bv.Disabled {
		t.Error("aborted save must not flip Disabled")
	} else if bv.SiteName != "kept" {
		t.Errorf("stored record changed: %q", bv.SiteName)
	}

	// (b) empty form + toggle off -> the legitimate "drop the override" path
	h2, cfgPath2 := newHandler(t)
	rr2 := post(t, h2, false)
	if loc := rr2.Header().Get("Location"); !strings.Contains(loc, "saved=1") {
		t.Errorf("dropping an override should still succeed: %s", loc)
	}
	got2, _ := settings.Load(cfgPath2)
	if !got2.Branding.Sites["example.com"].Disabled {
		t.Error("dropping an override must set Disabled")
	}
}
