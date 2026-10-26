package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
	"github.com/unmask-sh/unmask/admin/internal/user"
)

// sessionGenHandler is a handler on a migrated user store, with the setup
// token kept away from the host's (a real one would send AuthMiddleware into
// the wizard).  root exists so the account under test is never the last
// superadmin.
func sessionGenHandler(t *testing.T) *Handler {
	t.Helper()
	h, _ := newInviteTestHandler(t)
	h.updateSettingsInMemory(func(s *settings.Settings) {
		s.Secret.BVSecret = "test-bv-secret-0123456789abcdef"
		s.Server.BasePath = "/unmask"
	})
	origPath, origLegacy := SetupTokenPath, legacySetupTokenPath
	SetupTokenPath, legacySetupTokenPath = filepath.Join(t.TempDir(), ".setup-token"), ""
	t.Cleanup(func() { SetupTokenPath, legacySetupTokenPath = origPath, origLegacy })
	if _, err := h.UserRepo.CreateWithProfile(context.Background(), "root", "test-password-root", "superadmin", "", false); err != nil {
		t.Fatal(err)
	}
	return h
}

// serveWithSession runs one request through AuthMiddleware and reports
// whether it reached the handler.
func serveWithSession(h *Handler, c *http.Cookie) (*httptest.ResponseRecorder, bool) {
	called := false
	mw := h.AuthMiddleware(func(w http.ResponseWriter, r *http.Request) { called = true })
	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/", nil)
	req.AddCookie(c)
	rr := httptest.NewRecorder()
	mw(rr, req)
	return rr, called
}

func sessionCookieOf(rr *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range rr.Result().Cookies() {
		if c.Name == sessionCookieName {
			return c
		}
	}
	return nil
}

// The session cookie carries nothing the server could revoke, so it used to
// stay good for the rest of its life -- 30 days with "remember me" -- after
// the password it was signed in with was changed or reset.  It now carries
// the account's session generation, which SetPassword advances.
func TestPasswordChangeEndsExistingSessions(t *testing.T) {
	h := sessionGenHandler(t)
	ctx := context.Background()
	eve, err := h.UserRepo.CreateWithProfile(ctx, "eve", "test-password-eve1", "admin", "", false)
	if err != nil {
		t.Fatal(err)
	}
	secret := h.cfg().Secret.BVSecret
	old := issueSessionCookie(secret, "/unmask/admin", eve.ID, eve.Role, false, true, eve.SessionGen)
	if rr, called := serveWithSession(h, old); !called {
		t.Fatalf("a current session must pass (code=%d loc=%q)", rr.Code, rr.Header().Get("Location"))
	}

	if err := h.UserRepo.SetPassword(ctx, eve.ID, "test-password-eve2"); err != nil {
		t.Fatal(err)
	}
	rr, called := serveWithSession(h, old)
	if called {
		t.Fatal("a session from before the password change still reached the handler")
	}
	if rr.Code != http.StatusFound || !strings.Contains(rr.Header().Get("Location"), "/admin/login") {
		t.Fatalf("want a login redirect, got %d %q", rr.Code, rr.Header().Get("Location"))
	}
	if c := sessionCookieOf(rr); c == nil || c.MaxAge >= 0 {
		t.Error("the revoked cookie was not cleared on the response")
	}
	// The signature itself is still fine: the revocation is the generation
	// the account's row holds, not the cookie.
	if verifySessionCookie(secret, old.Value) == nil {
		t.Error("the old cookie should still verify as signed; the generation is what refuses it")
	}

	// Signing in with the new password issues a cookie under the new
	// generation, and that one passes.
	form := url.Values{"username": {"eve"}, "password": {"test-password-eve2"}}
	req := httptest.NewRequest(http.MethodPost, "/unmask/admin/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	lrr := httptest.NewRecorder()
	h.AdminLoginPost(lrr, req)
	fresh := sessionCookieOf(lrr)
	if fresh == nil || fresh.Value == "" {
		t.Fatalf("login with the new password issued no session (code=%d loc=%q)", lrr.Code, lrr.Header().Get("Location"))
	}
	if pay := verifySessionCookie(secret, fresh.Value); pay == nil || pay.Gen != 1 {
		t.Fatalf("the new session should carry generation 1, got %+v", pay)
	}
	if rr, called := serveWithSession(h, fresh); !called {
		t.Fatalf("the new session must pass (code=%d loc=%q)", rr.Code, rr.Header().Get("Location"))
	}
	// Signing in again (which may rehash) leaves that session alone.
	if rr, called := serveWithSession(h, fresh); !called {
		t.Fatalf("the new session must still pass after another sign-in (code=%d)", rr.Code)
	}
}

// Suspending ends the sessions for good: the middleware already turns a
// suspended account away, and re-enabling must not bring its old cookies
// back.
func TestSuspensionEndsSessionsForGood(t *testing.T) {
	h := sessionGenHandler(t)
	ctx := context.Background()
	eve, err := h.UserRepo.CreateWithProfile(ctx, "eve", "test-password-eve1", "admin", "", false)
	if err != nil {
		t.Fatal(err)
	}
	c := issueSessionCookie(h.cfg().Secret.BVSecret, "/unmask/admin", eve.ID, eve.Role, false, false, eve.SessionGen)
	if err := h.UserRepo.SetDisabled(ctx, eve.ID, true); err != nil {
		t.Fatal(err)
	}
	if err := h.UserRepo.SetDisabled(ctx, eve.ID, false); err != nil {
		t.Fatal(err)
	}
	if _, called := serveWithSession(h, c); called {
		t.Fatal("a cookie from before the suspension came back to life on re-enabling")
	}
}

// The operator who changes their own password on the profile page keeps the
// session they did it from: the response carries a cookie under the new
// generation, while a cookie from another device of theirs is ended.
func TestOwnPasswordChangeKeepsTheChangersSession(t *testing.T) {
	h := sessionGenHandler(t)
	ctx := context.Background()
	eve, err := h.UserRepo.CreateWithProfile(ctx, "eve", "test-password-eve1", "admin", "", false)
	if err != nil {
		t.Fatal(err)
	}
	secret := h.cfg().Secret.BVSecret
	otherDevice := issueSessionCookie(secret, "/unmask/admin", eve.ID, eve.Role, false, true, eve.SessionGen)

	form := url.Values{
		"op":               {"password"},
		"current_password": {"test-password-eve1"},
		"new_password":     {"test-password-eve2"},
		"confirm_password": {"test-password-eve2"},
	}
	req := httptest.NewRequest(http.MethodPost, "/unmask/admin/profile/save", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = req.WithContext(context.WithValue(req.Context(), sessionCtxKey{},
		&SessionPayload{UserID: eve.ID, Role: eve.Role, Remember: true, Gen: eve.SessionGen}))
	rr := httptest.NewRecorder()
	h.AdminProfileSave(rr, req)
	if rr.Code != http.StatusFound || !strings.Contains(rr.Header().Get("Location"), "saved=1") {
		t.Fatalf("password change: %d %q", rr.Code, rr.Header().Get("Location"))
	}
	mine := sessionCookieOf(rr)
	if mine == nil || mine.Value == "" {
		t.Fatal("the response carried no fresh session cookie for the session that made the change")
	}
	pay := verifySessionCookie(secret, mine.Value)
	if pay == nil || pay.Gen != 1 || !pay.Remember {
		t.Fatalf("fresh cookie payload = %+v, want generation 1 with remember kept", pay)
	}
	if rr, called := serveWithSession(h, mine); !called {
		t.Fatalf("the changer's fresh session must pass (code=%d loc=%q)", rr.Code, rr.Header().Get("Location"))
	}
	if _, called := serveWithSession(h, otherDevice); called {
		t.Fatal("the account's session on another device survived the password change")
	}
}

// A superadmin's wizard re-run is gated by the same session as the rest of
// the admin, generation included.
func TestSetupReconfigureRefusesARevokedSession(t *testing.T) {
	h, uid := reconfHandler(t, true)
	req := httptest.NewRequest(http.MethodGet, "/admin/setup/", nil)
	req.AddCookie(superadminCookie(uid))
	if h.setupSuperadmin(req) == nil {
		t.Fatal("a current superadmin session must be accepted")
	}
	if err := h.UserRepo.SetPassword(context.Background(), uid, "another-password-1"); err != nil {
		t.Fatal(err)
	}
	if h.setupSuperadmin(req) != nil {
		t.Fatal("a session from before the password change was accepted for the wizard")
	}
}

// A cookie in the pre-generation shape (one field fewer) fails verification:
// the upgrade signs every operator out once, by design.
func TestPreGenerationCookieIsRefused(t *testing.T) {
	const secret = "s"
	body := "1." + user.RoleAdmin + ".4102444800.0"
	if verifySessionCookie(secret, body+"."+sessionSign(secret, body)) != nil {
		t.Error("a cookie without the generation field verified")
	}
	if verifySessionCookie(secret, issueSessionCookie(secret, "/unmask/admin", 1, user.RoleAdmin, false, false, 7).Value).Gen != 7 {
		t.Error("the generation did not round-trip through the cookie")
	}
}
