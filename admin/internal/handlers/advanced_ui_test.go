package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The Advanced master switch is a reveal-gate that lives on the About tab (next
// to the version-check toggle).  With it off, the Web Bot Auth / Privacy Pass
// tabs are hidden from the nav and a direct URL hit redirects to About; with it
// on, the two tabs appear.
func TestAdvancedTabRevealGate(t *testing.T) {
	get := func(h *Handler, tab string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/unmask/admin/settings/?tab="+tab, nil)
		rr := httptest.NewRecorder()
		h.AdminSettingsIndex(rr, req)
		return rr
	}

	t.Run("off_hides_and_redirects", func(t *testing.T) {
		h := newTestHandler(t) // AdvancedEnabled defaults to false
		// About carries the master toggle, unchecked; feature links absent.
		rr := get(h, "about")
		if rr.Code != http.StatusOK {
			t.Fatalf("about tab: want 200, got %d", rr.Code)
		}
		body := rr.Body.String()
		if !strings.Contains(body, `name="advanced_enabled" value="1"`) {
			t.Error("About tab must render the advanced master toggle")
		}
		if strings.Contains(body, `name="advanced_enabled" value="1" checked`) {
			t.Error("toggle must be unchecked when advanced is off")
		}
		if strings.Contains(body, `href="?tab=web-bot-auth"`) || strings.Contains(body, `href="?tab=privacy-pass"`) {
			t.Error("feature tabs must be hidden from nav while advanced is off")
		}
		// Direct hit on a gated tab redirects to About (where the toggle lives).
		for _, tab := range []string{"web-bot-auth", "privacy-pass"} {
			rr := get(h, tab)
			if rr.Code != http.StatusSeeOther {
				t.Errorf("%s while off: want 303 redirect, got %d", tab, rr.Code)
			}
			if loc := rr.Header().Get("Location"); !strings.HasSuffix(loc, "?tab=about") {
				t.Errorf("%s redirect Location = %q, want ...?tab=about", tab, loc)
			}
		}
	})

	t.Run("on_reveals_tabs", func(t *testing.T) {
		h := newTestHandler(t)
		h.updateSettingsInMemory(func(s *settings.Settings) { s.Nginx.AdvancedEnabled = true })
		rr := get(h, "about")
		if rr.Code != http.StatusOK {
			t.Fatalf("about tab: want 200, got %d", rr.Code)
		}
		body := rr.Body.String()
		if !strings.Contains(body, `name="advanced_enabled" value="1" checked`) {
			t.Error("toggle must be checked when advanced is on")
		}
		if !strings.Contains(body, `href="?tab=web-bot-auth"`) || !strings.Contains(body, `href="?tab=privacy-pass"`) {
			t.Error("feature tabs must appear in nav once advanced is on")
		}
		// And the gated tabs now render instead of redirecting.
		if rr := get(h, "privacy-pass"); rr.Code != http.StatusOK {
			t.Errorf("privacy-pass while on: want 200, got %d", rr.Code)
		}
	})
}
