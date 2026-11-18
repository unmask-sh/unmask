package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// The profile page's "current password" is asked of whoever holds a session,
// and the login's lockout -- by address, at the login form -- never saw the
// answers: a session was enough to guess the password without end, and the
// password is what outlasts the session.  The wrong answers are counted by
// account, on both forms that ask.
func TestOwnPasswordChecksAreCounted(t *testing.T) {
	h, _ := newInviteTestHandler(t)
	// Three wrong answers lock, so the test does not wait on ten hashes.
	h.loginThrottle = newLoginThrottle()
	h.loginThrottle.failLimit = 3
	ctx := context.Background()
	me := lockTestUser(t, h, "owner")   // test-password-owner, owner@example.com
	other := lockTestUser(t, h, "mate") // test-password-mate
	save := func(id int64, role, addr string, form url.Values) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/unmask/admin/profile/save", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = addr
		rr := httptest.NewRecorder()
		h.AdminProfileSave(rr, asUser(req, id, role))
		return rr
	}
	pw := func(cur string) url.Values {
		return url.Values{"op": {"password"}, "current_password": {cur}, "new_password": {"a-new-password-2026"}, "confirm_password": {"a-new-password-2026"}}
	}
	mail := func(cur string) url.Values {
		return url.Values{"op": {"profile"}, "email": {"taker@example.net"}, "email_current_password": {cur}}
	}
	hash := func() string {
		u, err := h.UserRepo.GetByID(ctx, me.ID)
		if err != nil {
			t.Fatal(err)
		}
		return u.PasswordHash
	}
	before := hash()

	// Two wrong answers, one on each form and each from another address:
	// the page's own message, as before.
	for i, rr := range []*httptest.ResponseRecorder{
		save(me.ID, me.Role, "198.51.100.1:1000", pw("guess-1")),
		save(me.ID, me.Role, "198.51.100.2:1000", mail("guess-2")),
	} {
		if rr.Code != http.StatusFound || strings.Contains(rr.Header().Get("Location"), "saved=1") {
			t.Fatalf("wrong answer %d: %d %q", i+1, rr.Code, rr.Header().Get("Location"))
		}
	}
	// The third trips the count: 429 with Retry-After, whatever the address.
	rr := save(me.ID, me.Role, "198.51.100.3:1000", pw("guess-3"))
	if rr.Code != http.StatusTooManyRequests || rr.Header().Get("Retry-After") == "" {
		t.Fatalf("the third wrong answer: %d (Retry-After %q), want 429", rr.Code, rr.Header().Get("Retry-After"))
	}
	// Locked: the right password is not looked at either, on either form,
	// so the lock cannot be used to tell a right guess from a wrong one.
	if rr := save(me.ID, me.Role, "198.51.100.4:1000", pw("test-password-owner")); rr.Code != http.StatusTooManyRequests {
		t.Errorf("the right password while locked: %d %q, want 429", rr.Code, rr.Header().Get("Location"))
	}
	if rr := save(me.ID, me.Role, "198.51.100.5:1000", mail("test-password-owner")); rr.Code != http.StatusTooManyRequests {
		t.Errorf("the address form while locked: %d %q, want 429", rr.Code, rr.Header().Get("Location"))
	}
	if hash() != before {
		t.Error("the password changed while the checks were locked")
	}
	if u, _ := h.UserRepo.GetByID(ctx, me.ID); u.Email.String != "owner@example.com" {
		t.Errorf("the address changed while the checks were locked: %q", u.Email.String)
	}
	// The lock is the account's: another account, from the address that
	// tripped it, changes its password as usual.
	if rr := save(other.ID, other.Role, "198.51.100.3:1000", url.Values{"op": {"password"}, "current_password": {"test-password-mate"},
		"new_password": {"a-new-password-2026"}, "confirm_password": {"a-new-password-2026"}}); rr.Code != http.StatusFound || !strings.Contains(rr.Header().Get("Location"), "saved=1") {
		t.Errorf("another account, same address: %d %q", rr.Code, rr.Header().Get("Location"))
	}
	// What needs no password is not held up: the alert switch alone.
	if rr := save(me.ID, me.Role, "198.51.100.6:1000", url.Values{"op": {"profile"}, "email": {"owner@example.com"}, "alert_opt_out": {"1"}}); rr.Code != http.StatusFound || !strings.Contains(rr.Header().Get("Location"), "saved=1") {
		t.Errorf("the alert switch while the checks are locked: %d %q", rr.Code, rr.Header().Get("Location"))
	}
	// And it is in the audit log.
	var n int
	if err := h.DB.QueryRow(`SELECT COUNT(*) FROM unmask_user_audit WHERE action = 'own_password_check_locked' AND username = 'owner'`).Scan(&n); err != nil || n != 1 {
		t.Errorf("audit rows for the lock: %d (err %v), want 1", n, err)
	}
}
