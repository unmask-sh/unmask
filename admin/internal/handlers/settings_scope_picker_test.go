package handlers

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// scopeSelected extracts the value of the <option> carrying `selected` from
// the first scope picker in the page.
func scopeSelected(t *testing.T, body string) string {
	t.Helper()
	sel := regexp.MustCompile(`(?s)<select id="scope-select-[a-z]+".*?</select>`).FindString(body)
	if sel == "" {
		t.Fatal("scope picker <select> not rendered")
	}
	m := regexp.MustCompile(`<option value="([^"]*)"[^>]*\bselected\b`).FindStringSubmatch(sel)
	if m == nil {
		return "" // nothing selected -> browsers show the first option (Default)
	}
	return m[1]
}

func scopeTestHandler(t *testing.T) *Handler {
	t.Helper()
	h := newTestHandler(t)
	cfgPath := filepath.Join(t.TempDir(), "config.yml")
	var s settings.Settings
	s.Server.BasePath = "/unmask"
	// One already-configured site, so the picker has a populated list that a
	// brand-new host must not be confused with.
	s.Branding.Sites = map[string]settings.BrandingValues{"old.example.com": {SiteName: "old"}}
	if err := settings.Save(s, cfgPath); err != nil {
		t.Fatal(err)
	}
	h.ConfigPath = cfgPath
	h.SetSettings(s)
	return h
}

func renderSettings(t *testing.T, h *Handler, query string) string {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/unmask/admin/settings/"+query, nil)
	// The tab now rides in the path (the router fills PathValue); these
	// call-sites still pass the legacy ?tab= form, so lift it across here.
	// Any ?scope= stays in the query where the handler reads it.
	if tab := r.URL.Query().Get("tab"); tab != "" {
		r.SetPathValue("tab", tab)
	}
	rr := httptest.NewRecorder()
	h.AdminSettingsIndex(rr, r)
	if rr.Code != http.StatusOK {
		t.Fatalf("%s: status %d", query, rr.Code)
	}
	return rr.Body.String()
}

// TestScopePickerShowsNewlyAddedHost: the picker's "add a host" prompt jumps to
// ?scope=<typed>, but that host is in none of the sources the option list is
// built from until something is saved for it.  The <select> then had no
// matching option and displayed "Default" while the banner next to it named
// the new host and the form edited that host -- so the pulldown actively lied
// about what was being edited.
func TestScopePickerShowsNewlyAddedHost(t *testing.T) {
	h := scopeTestHandler(t)
	body := renderSettings(t, h, "?tab=theme&scope=new.example.com")

	if got := scopeSelected(t, body); got != "new.example.com" {
		t.Errorf("scope picker selected %q, want the newly added host", got)
	}
	if !strings.Contains(body, `<option value="old.example.com"`) {
		t.Error("existing hosts must stay in the list")
	}
}

// TestScopePickerNormalizesTypedHost: the prompt takes free text, so the typed
// value can differ in case / port / trailing dot from the key the save handler
// writes (it normalizes).  Both must resolve to the same row, otherwise the
// form comes back empty and a second save lands somewhere else.
func TestScopePickerNormalizesTypedHost(t *testing.T) {
	h := scopeTestHandler(t)
	for _, typed := range []string{"OLD.example.com", "old.example.com:443", "old.example.com."} {
		body := renderSettings(t, h, "?tab=theme&scope="+typed)
		if got := scopeSelected(t, body); got != "old.example.com" {
			t.Errorf("typed %q -> selected %q, want old.example.com", typed, got)
		}
		// and it must resolve to the SAVED record, not a blank one
		if !strings.Contains(body, `value="old"`) {
			t.Errorf("typed %q: form did not load the saved record for that host", typed)
		}
	}
}

// TestScopePickerDefaultUnchanged: the Default scope still selects the empty
// option and does not gain a phantom host entry.
func TestScopePickerDefaultUnchanged(t *testing.T) {
	h := scopeTestHandler(t)
	body := renderSettings(t, h, "?tab=theme")
	if got := scopeSelected(t, body); got != "" {
		t.Errorf("default scope selected %q, want the empty (Default) option", got)
	}
}
