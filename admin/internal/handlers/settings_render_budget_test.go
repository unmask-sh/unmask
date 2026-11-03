package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/i18n"
	"github.com/unmask-sh/unmask/admin/internal/user"
)

// The settings page is written whole or not at all: a build that outruns
// the budget gets an error page that says so, in the operator's language,
// not the top half of the form without its save button.
func TestSettingsPageSaysWhenItsBuildTookTooLong(t *testing.T) {
	h := installedHandler(t)
	st := *h.cfg()
	st.Server.BasePath = "/unmask"
	h.SetSettings(st)

	get := func(lang string) *httptest.ResponseRecorder {
		t.Helper()
		req := asRole(httptest.NewRequest(http.MethodGet, "/unmask/admin/settings/network/", nil), user.RoleAdmin)
		req.SetPathValue("tab", "network")
		req.AddCookie(&http.Cookie{Name: i18n.CookieName, Value: lang})
		rr := httptest.NewRecorder()
		h.AdminSettingsIndex(rr, req)
		return rr
	}

	oldBudget := settingsRenderBudget
	settingsRenderBudget = 20 * time.Millisecond
	settingsRenderHook = func() { time.Sleep(300 * time.Millisecond) }
	t.Cleanup(func() {
		settingsRenderBudget = oldBudget
		settingsRenderHook = nil
	})
	rr := get("en")
	if rr.Code != http.StatusServiceUnavailable || rr.Header().Get("Retry-After") == "" {
		t.Fatalf("slow build: %d %v", rr.Code, rr.Header())
	}
	if body := rr.Body.String(); !strings.Contains(body, "took too long") || strings.Contains(body, "<form") {
		t.Errorf("slow build body: %s", body)
	}
	if body := get("ja").Body.String(); !strings.Contains(body, "時間がかかりすぎた") {
		t.Errorf("slow build body in Japanese: %s", body)
	}

	// Within the budget the page is whole, with its form.
	settingsRenderBudget = oldBudget
	settingsRenderHook = nil
	rr = get("en")
	if rr.Code != http.StatusOK {
		t.Fatalf("page: %d %s", rr.Code, rr.Body.String())
	}
	if body := rr.Body.String(); !strings.Contains(body, "<form") || !strings.Contains(body, "</html>") {
		t.Error("the page lacks its form or its end")
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("content type %q", ct)
	}
}
