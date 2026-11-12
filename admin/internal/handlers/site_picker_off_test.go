package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The public test pages' site picker is on unless it is turned off, and it
// could not be turned off: the save took the unticked box, and the writer of
// config.yml -- which drops an explicit "off" from the Default record, off
// being what the other flags come to when nothing is said -- dropped this
// one too, where nothing said means on.  The page the save landed on showed
// the box ticked again, and the public test pages went on listing the sites
// that have settings of their own.
func TestThePublicTestPagesSitePickerCanBeTurnedOff(t *testing.T) {
	e := newSiteEnv(t, func(s *settings.Settings) {
		s.Challenge.Default.PublicTestPages = settings.BoolPtr(true)
	})
	defaultForm := func() htmlForm {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/unmask/admin/settings/challenge/", nil)
		req.SetPathValue("tab", "challenge")
		rr := httptest.NewRecorder()
		e.h.AdminSettingsIndex(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("GET challenge tab: %d", rr.Code)
		}
		for _, f := range parseForms(rr.Body.String()) {
			if sectionOf(f.action) == "challenge" {
				return f
			}
		}
		t.Fatal("the challenge tab has no form for the Default record")
		return htmlForm{}
	}
	save := func(vals url.Values) {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/unmask/admin/settings/save?section=challenge", strings.NewReader(vals.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		e.h.AdminSettingsSave(rr, req)
		if rr.Code != http.StatusFound || !strings.Contains(rr.Header().Get("Location"), "saved=1") {
			t.Fatalf("save: %d %s", rr.Code, rr.Header().Get("Location"))
		}
	}
	picker := func(f htmlForm) bool {
		for _, fld := range f.fields {
			if fld.name == "public_test_pages_site_picker" && fld.typ == "checkbox" {
				return fld.checked
			}
		}
		t.Fatal("the form has no site picker box")
		return false
	}

	f := defaultForm()
	if !picker(f) {
		t.Fatal("the site picker is not on where nothing was set")
	}
	vals := f.values()
	vals.Del("public_test_pages_site_picker")
	save(vals)
	if e.load().Challenge.Default.IsPublicTestPagesSitePicker() {
		t.Error("the site picker, unticked and saved, is on in the config that was written")
	}
	if e.h.snapshotSettings().Challenge.Default.IsPublicTestPagesSitePicker() {
		t.Error("the site picker, unticked and saved, is on in the running settings")
	}
	if picker(defaultForm()) {
		t.Error("the page the save lands on shows the site picker ticked again")
	}
	// Saved as shown, it stays off; ticked again, it is on, and the file says
	// nothing about it (on is what nothing said comes to).
	before := e.yaml()
	f = defaultForm()
	save(f.values())
	if after := e.yaml(); after != before {
		t.Errorf("a save of the form as shown changed the config:\n%s", yamlDiff(before, after))
	}
	f = defaultForm()
	vals = f.values()
	vals.Set("public_test_pages_site_picker", tickedValue(t, f, "public_test_pages_site_picker"))
	save(vals)
	cur := e.load()
	if !cur.Challenge.Default.IsPublicTestPagesSitePicker() || cur.Challenge.Default.PublicTestPagesSitePicker != nil {
		t.Errorf("the site picker ticked again: on=%v, written explicitly=%v (want on, and nothing written)",
			cur.Challenge.Default.IsPublicTestPagesSitePicker(), cur.Challenge.Default.PublicTestPagesSitePicker != nil)
	}
}
