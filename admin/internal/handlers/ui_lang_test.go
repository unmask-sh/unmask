package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/i18n"
	"github.com/unmask-sh/unmask/admin/internal/settings"
	"github.com/unmask-sh/unmask/admin/internal/user"
)

// The language an account sees the admin in is recorded as it uses it --
// the one picked at the top right, or the browser's when none was -- and its
// alert mail is written in it.  Nothing is written while the language stays
// the same.
func TestAccountLanguageIsRemembered(t *testing.T) {
	h, _ := newInviteTestHandler(t)
	ctx := context.Background()
	h.updateSettingsInMemory(func(s *settings.Settings) {
		s.Secret.BVSecret = "test-bv-secret-0123456789abcdef"
	})
	origPath, origLegacy := SetupTokenPath, legacySetupTokenPath
	SetupTokenPath, legacySetupTokenPath = filepath.Join(t.TempDir(), ".setup-token"), ""
	t.Cleanup(func() { SetupTokenPath, legacySetupTokenPath = origPath, origLegacy })
	eve, err := h.UserRepo.CreateWithProfile(ctx, "eve", "test-password-eve1", "superadmin", "eve@example.com", false)
	if err != nil {
		t.Fatal(err)
	}
	cookie := issueSessionCookie(h.cfg().Secret.BVSecret, eve.ID, eve.Role, false, false)
	visit := func(locale, acceptLang string) {
		t.Helper()
		mw := h.AuthMiddleware(func(w http.ResponseWriter, r *http.Request) {})
		req := httptest.NewRequest(http.MethodGet, "/unmask/admin/", nil)
		req.AddCookie(cookie)
		if locale != "" {
			req.AddCookie(&http.Cookie{Name: i18n.CookieName, Value: locale})
		}
		if acceptLang != "" {
			req.Header.Set("Accept-Language", acceptLang)
		}
		mw(httptest.NewRecorder(), req)
	}
	langOf := func(want string) string {
		t.Helper()
		deadline := time.Now().Add(2 * time.Second)
		for {
			u, err := h.UserRepo.GetByID(ctx, eve.ID)
			if err != nil {
				t.Fatal(err)
			}
			if u.UILang == want || time.Now().After(deadline) {
				return u.UILang
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	if u, _ := h.UserRepo.GetByID(ctx, eve.ID); u.UILang != "" {
		t.Fatalf("a new account has a language before its first visit: %q", u.UILang)
	}
	visit("", "en-US,en;q=0.9") // the browser's
	if got := langOf("en"); got != "en" {
		t.Errorf("after a visit from an English browser: %q, want en", got)
	}
	visit("ja", "en-US") // picked at the top right
	if got := langOf("ja"); got != "ja" {
		t.Errorf("after picking Japanese: %q, want ja", got)
	}
	recips, err := h.UserRepo.AlertRecipients(ctx)
	if err != nil || len(recips) != 1 || recips[0] != (user.AlertRecipient{Email: "eve@example.com", Lang: "ja"}) {
		t.Errorf("alert recipients = %+v (%v), want eve in ja", recips, err)
	}
	if got := h.UserRepo.UILangByEmail(ctx, "EVE@example.com"); got != "ja" {
		t.Errorf("language by address = %q, want ja (addresses compare without case)", got)
	}
	if got := h.UserRepo.UILangByEmail(ctx, "nobody@example.com"); got != "" {
		t.Errorf("language of an address that is no account's = %q", got)
	}
}

// The default mail language, for the addresses that are no account's: picked
// on the notifications tab; English is stored as no value, so a save that
// changes nothing writes nothing (TestSettingsTabsNoOpSave).
func TestNotificationsMailLanguage(t *testing.T) {
	for _, c := range []struct{ in, want string }{{"ja", "ja"}, {"", ""}, {"en", ""}, {"fr", ""}} {
		form := url.Values{"mail_lang": {c.in}}
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if err := req.ParseForm(); err != nil {
			t.Fatal(err)
		}
		var n settings.Notifications
		applyNotificationsForm(&n, req)
		if n.Lang != c.want {
			t.Errorf("mail_lang=%q saved as %q, want %q", c.in, n.Lang, c.want)
		}
	}
	if (settings.Notifications{}).LangResolved() != "en" || (settings.Notifications{Lang: "ja"}).LangResolved() != "ja" {
		t.Error("LangResolved")
	}
	if got := NotifierConfigFrom(settings.Notifications{Lang: "ja"}, "h").Lang; got != "ja" {
		t.Errorf("notifier config Lang = %q", got)
	}
}
