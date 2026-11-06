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

// The setup wizard and the CLI refuse a password shorter than
// user.MinPasswordLen.  The pages that set one afterwards -- the account's
// own profile, the users page, the mailed reset link -- took whatever they
// were given, one character included; the reset page even says "at least 8".
// Every path now holds the same floor, and refuses before it writes anything.

const shortPassword = "seven77" // one under user.MinPasswordLen

func TestProfilePasswordChangeRefusesAShortPassword(t *testing.T) {
	h := sessionGenHandler(t)
	ctx := context.Background()
	eve, err := h.UserRepo.CreateWithProfile(ctx, "eve", "test-password-eve1", "admin", "", false)
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{
		"op":               {"password"},
		"current_password": {"test-password-eve1"},
		"new_password":     {shortPassword},
		"confirm_password": {shortPassword},
	}
	req := httptest.NewRequest(http.MethodPost, "/unmask/admin/profile/save", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = req.WithContext(context.WithValue(req.Context(), sessionCtxKey{},
		&SessionPayload{UserID: eve.ID, Role: eve.Role, Gen: eve.SessionGen}))
	rr := httptest.NewRecorder()
	h.AdminProfileSave(rr, req)
	if rr.Code != http.StatusFound || strings.Contains(rr.Header().Get("Location"), "saved=1") {
		t.Fatalf("a %d-character password was accepted: %d %q", len(shortPassword), rr.Code, rr.Header().Get("Location"))
	}
	after, _ := h.UserRepo.GetByID(ctx, eve.ID)
	if err := user.CheckPassword(after.PasswordHash, "test-password-eve1"); err != nil {
		t.Fatalf("the old password no longer signs in after a refused change: %v", err)
	}
	if after.SessionGen != eve.SessionGen {
		t.Fatal("a refused change ended the account's sessions")
	}
}

func TestUsersPageRefusesAShortPassword(t *testing.T) {
	h, _ := newInviteTestHandler(t)
	ctx := context.Background()
	bob, err := h.UserRepo.CreateWithProfile(ctx, "bob", "test-password-bob1", "viewer", "bob@example.com", false)
	if err != nil {
		t.Fatal(err)
	}
	refused := func(what string, form url.Values) {
		t.Helper()
		rr := postUsersSave(t, h, form)
		if strings.Contains(rr.Header().Get("Location"), "saved=1") {
			t.Fatalf("%s: a %d-character password was accepted (%q)", what, len(shortPassword), rr.Header().Get("Location"))
		}
	}

	// update: nothing of the request is applied, the role included.
	refused("update", url.Values{"op": {"update"}, "id": {fmt.Sprint(bob.ID)}, "role": {"admin"},
		"email": {"changed@example.com"}, "password": {shortPassword}})
	after, _ := h.UserRepo.GetByID(ctx, bob.ID)
	if after.Role != "viewer" || after.Email.String != "bob@example.com" {
		t.Fatalf("a refused update still wrote role %q / email %q", after.Role, after.Email.String)
	}

	refused("reset_password", url.Values{"op": {"reset_password"}, "id": {fmt.Sprint(bob.ID)}, "password": {shortPassword}})
	after, _ = h.UserRepo.GetByID(ctx, bob.ID)
	if err := user.CheckPassword(after.PasswordHash, "test-password-bob1"); err != nil {
		t.Fatalf("the password changed after two refusals: %v", err)
	}

	refused("create", url.Values{"op": {"create"}, "username": {"carol"}, "password": {shortPassword}, "role": {"viewer"}})
	if u, err := h.UserRepo.GetByUsername(ctx, "carol"); err == nil && u != nil {
		t.Fatal("a refused create still made the account")
	}

	// The floor itself is accepted, on each of the three.
	floor := strings.Repeat("x", user.MinPasswordLen)
	for what, form := range map[string]url.Values{
		"update":         {"op": {"update"}, "id": {fmt.Sprint(bob.ID)}, "role": {"viewer"}, "email": {"bob@example.com"}, "password": {floor}},
		"reset_password": {"op": {"reset_password"}, "id": {fmt.Sprint(bob.ID)}, "password": {floor}},
		"create":         {"op": {"create"}, "username": {"dave"}, "password": {floor}, "role": {"viewer"}},
	} {
		if rr := postUsersSave(t, h, form); !strings.Contains(rr.Header().Get("Location"), "saved=1") {
			t.Fatalf("%s: a %d-character password was refused (%q)", what, len(floor), rr.Header().Get("Location"))
		}
	}
}

func TestResetLinkRefusesAShortPasswordAndKeepsTheToken(t *testing.T) {
	h, _ := newInviteTestHandler(t)
	ctx := context.Background()
	bob, err := h.UserRepo.CreateWithProfile(ctx, "bob", "test-password-bob1", "viewer", "bob@example.com", false)
	if err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("ab", 32)
	if err := h.UserRepo.IssueResetToken(ctx, bob.ID, token, 3600); err != nil {
		t.Fatal(err)
	}
	post := func(pw string) string {
		form := url.Values{"token": {token}, "password": {pw}, "password2": {pw}}
		req := httptest.NewRequest(http.MethodPost, "/unmask/admin/reset-password", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		h.AdminResetPasswordPost(rr, req)
		return rr.Header().Get("Location")
	}

	for what, pw := range map[string]string{
		"short": shortPassword,
		"long":  strings.Repeat("x", user.MaxPasswordLen+1),
	} {
		loc := post(pw)
		if !strings.Contains(loc, "err=length") || !strings.Contains(loc, "token="+token) {
			t.Fatalf("%s password: redirected to %q, want the form again with err=length and the token kept", what, loc)
		}
	}
	after, _ := h.UserRepo.GetByID(ctx, bob.ID)
	if err := user.CheckPassword(after.PasswordHash, "test-password-bob1"); err != nil {
		t.Fatalf("the password changed after refusals: %v", err)
	}
	// The link is still good: the refusals did not spend it.
	if loc := post("test-password-bob2"); !strings.Contains(loc, "/admin/login") {
		t.Fatalf("a valid password after the refusals: redirected to %q, want the login page", loc)
	}
	after, _ = h.UserRepo.GetByID(ctx, bob.ID)
	if err := user.CheckPassword(after.PasswordHash, "test-password-bob2"); err != nil {
		t.Fatalf("the reset did not take: %v", err)
	}
}
