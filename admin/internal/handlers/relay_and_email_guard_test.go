package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The mail relay carries every account's password-reset link, a
// superadmin's among them.  An admin could point it at a server of their
// own, ask for a superadmin's reset and read the link.  Only a superadmin
// changes where the mail goes; an admin still saves the sender and the
// channels, with the relay fields as saved.
func TestOnlyASuperadminChangesTheMailRelay(t *testing.T) {
	h := ruleTestHandler(t)
	save := func(role string, form url.Values) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/unmask/admin/settings/save?section=notifications", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		h.AdminSettingsSave(rr, asRole(req, role))
		return rr
	}
	relay := func() settings.SMTP {
		t.Helper()
		cur, err := settings.Load(h.ConfigPath)
		if err != nil {
			t.Fatal(err)
		}
		return cur.SMTP
	}
	card := url.Values{"host": {"smtp.example.com"}, "port": {"587"}, "username": {"mailer"}, "password": {"relay-secret"}, "starttls": {"1"}, "format": {"slack"}}
	if rr := save("superadmin", card); !strings.Contains(rr.Header().Get("Location"), "saved=1") {
		t.Fatalf("a superadmin's save: %q", rr.Header().Get("Location"))
	}

	// An admin pointing the relay elsewhere is refused, and nothing changes.
	moved := url.Values{"host": {"mail.attacker.example"}, "port": {"587"}, "username": {"mailer"}, "starttls": {"1"}, "format": {"slack"}}
	if rr := save("admin", moved); strings.Contains(rr.Header().Get("Location"), "saved=1") {
		t.Fatalf("an admin moved the relay: %q", rr.Header().Get("Location"))
	}
	if got := relay(); got.Host != "smtp.example.com" || got.Password != "relay-secret" {
		t.Fatalf("the relay after an admin's refused save: %+v", got)
	}
	// So is a TLS check turned off, or a password of their own.
	for _, f := range []url.Values{
		{"host": {"smtp.example.com"}, "port": {"587"}, "username": {"mailer"}, "starttls": {"1"}, "insecure_skip_verify": {"1"}, "format": {"slack"}},
		{"host": {"smtp.example.com"}, "port": {"587"}, "username": {"mailer"}, "password": {"other"}, "starttls": {"1"}, "format": {"slack"}},
	} {
		if rr := save("admin", f); strings.Contains(rr.Header().Get("Location"), "saved=1") {
			t.Errorf("an admin changed the relay's checks or credentials: %v", f)
		}
	}

	// The sender and the channels stay an admin's to change.
	sender := url.Values{"host": {"smtp.example.com"}, "port": {"587"}, "username": {"mailer"}, "starttls": {"1"}, "from_name": {"Site alerts"}, "format": {"slack"}}
	if rr := save("admin", sender); !strings.Contains(rr.Header().Get("Location"), "saved=1") {
		t.Fatalf("an admin's sender change was refused: %q", rr.Header().Get("Location"))
	}
	if got := relay(); got.FromName != "Site alerts" || got.Host != "smtp.example.com" || got.Password != "relay-secret" {
		t.Errorf("after an admin's sender change: %+v", got)
	}
}

// The profile's address is where a password reset goes: changing it takes
// the current password, so a session alone cannot move the reset to an
// address of the holder's choosing.  The alert switch does not.
func TestProfileEmailChangeTakesThePassword(t *testing.T) {
	h, _ := newInviteTestHandler(t)
	ctx := context.Background()
	me := lockTestUser(t, h, "owner") // test-password-owner, owner@example.com
	save := func(form url.Values) string {
		t.Helper()
		form.Set("op", "profile")
		req := httptest.NewRequest(http.MethodPost, "/unmask/admin/profile/save", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		h.AdminProfileSave(rr, asUser(req, me.ID, me.Role))
		return rr.Header().Get("Location")
	}
	email := func() string {
		u, err := h.UserRepo.GetByID(ctx, me.ID)
		if err != nil {
			t.Fatal(err)
		}
		return u.Email.String
	}
	if loc := save(url.Values{"email": {"taker@example.net"}}); strings.Contains(loc, "saved=1") || email() != "owner@example.com" {
		t.Fatalf("the address changed without the password: %q, now %q", loc, email())
	}
	if loc := save(url.Values{"email": {"taker@example.net"}, "email_current_password": {"wrong"}}); strings.Contains(loc, "saved=1") || email() != "owner@example.com" {
		t.Fatalf("the address changed with a wrong password: %q", loc)
	}
	if loc := save(url.Values{"email": {"owner@example.com"}, "alert_opt_out": {"1"}}); !strings.Contains(loc, "saved=1") {
		t.Fatalf("the alert switch alone asked for the password: %q", loc)
	}
	if loc := save(url.Values{"email": {"new@example.com"}, "email_current_password": {"test-password-owner"}}); !strings.Contains(loc, "saved=1") || email() != "new@example.com" {
		t.Fatalf("the address did not change with the password: %q, now %q", loc, email())
	}
}
