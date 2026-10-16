package handlers

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/user"
)

// A viewer login shared by a team breaks the day one of its users changes
// the password.  An administrator can keep an account from changing its own
// password: the users page sets the flag, and with it the profile page's
// password form gives way to a note, its save op refuses, and the
// forgot-password link issues nothing -- while the users page itself still
// sets the password.

func lockTestUser(t *testing.T, h *Handler, name string) *user.User {
	t.Helper()
	u, err := h.UserRepo.CreateWithProfile(context.Background(), name, "test-password-"+name, "viewer", name+"@example.com", false)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestPasswordLockIsSetFromTheUsersPage(t *testing.T) {
	h, _ := newInviteTestHandler(t)
	ctx := context.Background()
	shared := lockTestUser(t, h, "shared")
	if shared.PasswordLocked {
		t.Fatal("a new account starts unlocked")
	}
	update := func(locked bool) {
		form := url.Values{"op": {"update"}, "id": {fmt.Sprint(shared.ID)}, "role": {"viewer"}, "email": {"shared@example.com"}}
		if locked {
			form.Set("password_locked", "1")
		}
		if rr := postUsersSave(t, h, form); !strings.Contains(rr.Header().Get("Location"), "saved=1") {
			t.Fatalf("update: %q", rr.Header().Get("Location"))
		}
	}
	update(true)
	if u, _ := h.UserRepo.GetByID(ctx, shared.ID); !u.PasswordLocked {
		t.Fatal("the lock did not persist")
	}
	// The users page still sets the password of a locked account.
	form := url.Values{"op": {"update"}, "id": {fmt.Sprint(shared.ID)}, "role": {"viewer"}, "email": {"shared@example.com"}, "password_locked": {"1"}, "password": {"test-password-by-admin"}}
	if rr := postUsersSave(t, h, form); !strings.Contains(rr.Header().Get("Location"), "saved=1") {
		t.Fatalf("update with a password: %q", rr.Header().Get("Location"))
	}
	u, _ := h.UserRepo.GetByID(ctx, shared.ID)
	if err := user.CheckPassword(u.PasswordHash, "test-password-by-admin"); err != nil || !u.PasswordLocked {
		t.Fatalf("the administrator's password did not take (err %v, locked %v)", err, u.PasswordLocked)
	}
	update(false)
	if u, _ := h.UserRepo.GetByID(ctx, shared.ID); u.PasswordLocked {
		t.Fatal("the unlock did not persist")
	}
	// op=create carries the flag too.
	form = url.Values{"op": {"create"}, "username": {"shared2"}, "password": {"test-password-shared2"}, "role": {"viewer"}, "password_locked": {"1"}}
	if rr := postUsersSave(t, h, form); !strings.Contains(rr.Header().Get("Location"), "saved=1") {
		t.Fatalf("create: %q", rr.Header().Get("Location"))
	}
	if u, err := h.UserRepo.GetByUsername(ctx, "shared2"); err != nil || !u.PasswordLocked {
		t.Fatalf("create with the flag: err %v, locked %v", err, u != nil && u.PasswordLocked)
	}
}

func TestPasswordLockKeepsTheProfileFromChangingIt(t *testing.T) {
	h, _ := newInviteTestHandler(t)
	ctx := context.Background()
	shared := lockTestUser(t, h, "shared")
	profile := func() string {
		rr := httptest.NewRecorder()
		h.AdminProfileIndex(rr, asUser(httptest.NewRequest(http.MethodGet, "/unmask/admin/profile/", nil), shared.ID, shared.Role))
		if rr.Code != http.StatusOK {
			t.Fatalf("profile: %d", rr.Code)
		}
		return rr.Body.String()
	}
	change := func(newPass string) string {
		form := url.Values{"op": {"password"}, "current_password": {"test-password-shared"}, "new_password": {newPass}, "confirm_password": {newPass}}
		req := httptest.NewRequest(http.MethodPost, "/unmask/admin/profile/save", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		h.AdminProfileSave(rr, asUser(req, shared.ID, shared.Role))
		return rr.Header().Get("Location")
	}
	// Unlocked: the form is there and the change goes through.
	if body := profile(); !strings.Contains(body, `name="current_password"`) || strings.Contains(body, `id="password-locked-note"`) {
		t.Fatal("unlocked: the profile should offer the password form, without the note")
	}
	if loc := change("test-password-mine-1"); !strings.Contains(loc, "saved=1") {
		t.Fatalf("unlocked: the change was refused: %q", loc)
	}
	if u, _ := h.UserRepo.GetByID(ctx, shared.ID); user.CheckPassword(u.PasswordHash, "test-password-mine-1") != nil {
		t.Fatal("unlocked: the change did not take")
	}
	if err := h.UserRepo.SetPassword(ctx, shared.ID, "test-password-shared"); err != nil {
		t.Fatal(err)
	}
	// Locked: a note in place of the form, and the op refuses.
	if err := h.UserRepo.SetPasswordLocked(ctx, shared.ID, true); err != nil {
		t.Fatal(err)
	}
	if body := profile(); strings.Contains(body, `name="current_password"`) || !strings.Contains(body, `id="password-locked-note"`) {
		t.Fatal("locked: the profile should show the note and no password form")
	}
	if loc := change("test-password-mine-2"); strings.Contains(loc, "saved=1") {
		t.Fatalf("locked: the change went through: %q", loc)
	}
	if u, _ := h.UserRepo.GetByID(ctx, shared.ID); user.CheckPassword(u.PasswordHash, "test-password-shared") != nil {
		t.Fatal("locked: the password changed")
	}
}

func TestPasswordLockIssuesNoResetLink(t *testing.T) {
	h, _ := newInviteTestHandler(t)
	ctx := context.Background()
	shared := lockTestUser(t, h, "shared")
	forgot := func() {
		form := url.Values{"identifier": {"shared@example.com"}}
		req := httptest.NewRequest(http.MethodPost, "/unmask/admin/forgot-password", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		h.AdminForgotPasswordPost(rr, req)
		if rr.Code != http.StatusFound {
			t.Fatalf("forgot: %d %s", rr.Code, rr.Body.String())
		}
	}
	forgot()
	if u, _ := h.UserRepo.GetByID(ctx, shared.ID); !u.ResetToken.Valid {
		t.Fatal("unlocked: no reset token was issued")
	}
	if err := h.UserRepo.IssueResetToken(ctx, shared.ID, "", 0); err != nil {
		t.Fatal(err)
	}
	if err := h.UserRepo.SetPasswordLocked(ctx, shared.ID, true); err != nil {
		t.Fatal(err)
	}
	forgot()
	if u, _ := h.UserRepo.GetByID(ctx, shared.ID); u.ResetToken.Valid && u.ResetToken.String != "" {
		t.Fatalf("locked: a reset token was issued: %q", u.ResetToken.String)
	}
}
