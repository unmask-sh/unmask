package handlers

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
	"github.com/unmask-sh/unmask/admin/internal/user"
)

// TestSetDisabledGuards pins the lock-out guards: the last ENABLED superadmin
// can be neither suspended nor demoted, and a suspended superadmin does not
// keep the guard satisfied -- being unable to sign in, it administers
// nothing, so counting it would allow suspending the only working superadmin.
func TestSetDisabledGuards(t *testing.T) {
	h, _ := newInviteTestHandler(t)
	ctx := context.Background()
	sa1, err := h.UserRepo.CreateWithProfile(ctx, "sa1", "test-password-sa1", "superadmin", "", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.UserRepo.SetDisabled(ctx, sa1.ID, true); err != user.ErrLastSuperadmin {
		t.Fatalf("suspending the only superadmin: err=%v, want ErrLastSuperadmin", err)
	}

	sa2, err := h.UserRepo.CreateWithProfile(ctx, "sa2", "test-password-sa2", "superadmin", "", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.UserRepo.SetDisabled(ctx, sa1.ID, true); err != nil {
		t.Fatalf("suspending sa1 with sa2 enabled: %v", err)
	}
	// sa1 is suspended: sa2 is now the last WORKING superadmin.
	if err := h.UserRepo.SetDisabled(ctx, sa2.ID, true); err != user.ErrLastSuperadmin {
		t.Fatalf("suspending the last enabled superadmin: err=%v, want ErrLastSuperadmin", err)
	}
	if err := h.UserRepo.SetRole(ctx, sa2.ID, "admin"); err != user.ErrLastSuperadmin {
		t.Fatalf("demoting the last enabled superadmin: err=%v, want ErrLastSuperadmin", err)
	}
	if err := h.UserRepo.Delete(ctx, sa2.ID); err != user.ErrLastSuperadmin {
		t.Fatalf("deleting the last enabled superadmin: err=%v, want ErrLastSuperadmin", err)
	}
	// Re-enabling sa1 restores the headcount; sa2 can then be suspended.
	if err := h.UserRepo.SetDisabled(ctx, sa1.ID, false); err != nil {
		t.Fatal(err)
	}
	if err := h.UserRepo.SetDisabled(ctx, sa2.ID, true); err != nil {
		t.Fatalf("suspending sa2 after re-enabling sa1: %v", err)
	}
}

// TestDisabledExcludedFromAlerts: a suspended admin stops receiving alert
// mail -- an ex-operator must not keep getting over-block pages.
func TestDisabledExcludedFromAlerts(t *testing.T) {
	h, _ := newInviteTestHandler(t)
	ctx := context.Background()
	a1, err := h.UserRepo.CreateWithProfile(ctx, "a1", "test-password-a1x", "superadmin", "a1@example.com", false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.UserRepo.CreateWithProfile(ctx, "a2", "test-password-a2x", "admin", "a2@example.com", false); err != nil {
		t.Fatal(err)
	}
	if got, _ := h.UserRepo.AlertRecipients(ctx); len(got) != 2 {
		t.Fatalf("recipients before = %v, want 2", got)
	}
	// a2 keeps the superadmin guard irrelevant here (a1 is superadmin; suspend a2).
	u2, _ := h.UserRepo.GetByUsername(ctx, "a2")
	if err := h.UserRepo.SetDisabled(ctx, u2.ID, true); err != nil {
		t.Fatal(err)
	}
	got, _ := h.UserRepo.AlertRecipients(ctx)
	if len(got) != 1 || got[0] != a1.Email.String {
		t.Fatalf("recipients after suspend = %v, want only a1", got)
	}
}

// TestDisabledAccountLosesSessionImmediately: the point of suspension is
// immediacy -- an existing session cookie dies on the very next request, the
// same way a deleted account's does.
func TestDisabledAccountLosesSessionImmediately(t *testing.T) {
	h, _ := newInviteTestHandler(t)
	ctx := context.Background()
	h.updateSettingsInMemory(func(s *settings.Settings) {
		s.Secret.BVSecret = "test-bv-secret-0123456789abcdef"
	})
	// Isolate the setup-token globals: on a dev box a real
	// /var/lib/unmask/.setup-token would flip AuthMiddleware into the wizard
	// redirect and fail this test for reasons that have nothing to do with it.
	origPath, origLegacy := SetupTokenPath, legacySetupTokenPath
	SetupTokenPath, legacySetupTokenPath = filepath.Join(t.TempDir(), ".setup-token"), ""
	t.Cleanup(func() { SetupTokenPath, legacySetupTokenPath = origPath, origLegacy })
	// A superadmin besides eve, so suspending eve is allowed.
	if _, err := h.UserRepo.CreateWithProfile(ctx, "root", "test-password-root", "superadmin", "", false); err != nil {
		t.Fatal(err)
	}
	eve, err := h.UserRepo.CreateWithProfile(ctx, "eve", "test-password-eve1", "admin", "", false)
	if err != nil {
		t.Fatal(err)
	}
	cookie := issueSessionCookie(h.cfg().Secret.BVSecret, eve.ID, eve.Role, false, false)

	serve := func() (*httptest.ResponseRecorder, bool) {
		called := false
		mw := h.AuthMiddleware(func(w http.ResponseWriter, r *http.Request) { called = true })
		req := httptest.NewRequest(http.MethodGet, "/unmask/admin/", nil)
		req.AddCookie(cookie)
		rr := httptest.NewRecorder()
		mw(rr, req)
		return rr, called
	}

	if rr, called := serve(); !called {
		t.Fatalf("an enabled account's session must pass the middleware (code=%d loc=%q)",
			rr.Code, rr.Header().Get("Location"))
	}
	if err := h.UserRepo.SetDisabled(ctx, eve.ID, true); err != nil {
		t.Fatal(err)
	}
	rr, called := serve()
	if called {
		t.Fatal("a suspended account's session still reached the handler")
	}
	if rr.Code != http.StatusFound || !strings.Contains(rr.Header().Get("Location"), "/admin/login") {
		t.Fatalf("want a login redirect, got %d %q", rr.Code, rr.Header().Get("Location"))
	}
}

// TestDisabledLoginRefused: a correct password no longer signs in, and the
// response is byte-identical in kind to a wrong password (no session cookie,
// same redirect shape) -- a distinct answer would confirm the account.
func TestDisabledLoginRefused(t *testing.T) {
	h, _ := newInviteTestHandler(t)
	ctx := context.Background()
	u, err := h.UserRepo.CreateWithProfile(ctx, "frank", "test-password-frank", "admin", "", false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.UserRepo.CreateWithProfile(ctx, "root", "test-password-root", "superadmin", "", false); err != nil {
		t.Fatal(err)
	}
	login := func() *httptest.ResponseRecorder {
		form := url.Values{"username": {"frank"}, "password": {"test-password-frank"}}
		req := httptest.NewRequest(http.MethodPost, "/unmask/admin/login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		h.AdminLoginPost(rr, req)
		return rr
	}
	hasSession := func(rr *httptest.ResponseRecorder) bool {
		for _, c := range rr.Result().Cookies() {
			if c.Name == sessionCookieName && c.Value != "" {
				return true
			}
		}
		return false
	}

	if rr := login(); !hasSession(rr) {
		t.Fatalf("enabled account must sign in (code=%d loc=%q)", rr.Code, rr.Header().Get("Location"))
	}
	if err := h.UserRepo.SetDisabled(ctx, u.ID, true); err != nil {
		t.Fatal(err)
	}
	if rr := login(); hasSession(rr) {
		t.Fatal("suspended account signed in with a correct password")
	}
}

// TestSetDisabledHandlerGuards: the users/save op refuses self-suspension
// (the operator would cut their own session mid-click) and flips others.
func TestSetDisabledHandlerGuards(t *testing.T) {
	h, _ := newInviteTestHandler(t)
	ctx := context.Background()
	me, err := h.UserRepo.CreateWithProfile(ctx, "me", "test-password-me00", "superadmin", "", false)
	if err != nil {
		t.Fatal(err)
	}
	other, err := h.UserRepo.CreateWithProfile(ctx, "other", "test-password-oth0", "superadmin", "", false)
	if err != nil {
		t.Fatal(err)
	}
	post := func(id int64, disabled string) *httptest.ResponseRecorder {
		form := url.Values{"op": {"set_disabled"}, "id": {fmt.Sprint(id)}, "disabled": {disabled}}
		req := httptest.NewRequest(http.MethodPost, "/unmask/admin/users/save", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req = req.WithContext(context.WithValue(req.Context(), sessionCtxKey{},
			&SessionPayload{UserID: me.ID, Role: "superadmin"}))
		rr := httptest.NewRecorder()
		h.AdminUsersSave(rr, req)
		return rr
	}

	if rr := post(me.ID, "1"); strings.Contains(rr.Header().Get("Location"), "saved=1") {
		t.Fatal("self-suspension must be refused")
	}
	if u, _ := h.UserRepo.GetByID(ctx, me.ID); u.Disabled {
		t.Fatal("self-suspension went through")
	}
	if rr := post(other.ID, "1"); !strings.Contains(rr.Header().Get("Location"), "saved=1") {
		t.Fatalf("suspending another user failed: %q", rr.Header().Get("Location"))
	}
	if u, _ := h.UserRepo.GetByID(ctx, other.ID); !u.Disabled {
		t.Fatal("suspension not persisted")
	}
}
