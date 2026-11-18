package handlers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/i18n"
	"github.com/unmask-sh/unmask/admin/internal/settings"
	"github.com/unmask-sh/unmask/admin/internal/user"
)

// forgotFrom posts the forgot-password form from the given address.
func forgotFrom(t *testing.T, h *Handler, addr, identifier string) {
	t.Helper()
	form := url.Values{"identifier": {identifier}}
	req := httptest.NewRequest(http.MethodPost, "/unmask/admin/forgot-password", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = addr
	rr := httptest.NewRecorder()
	h.AdminForgotPasswordPost(rr, req)
	if rr.Code != http.StatusFound || !strings.HasSuffix(rr.Header().Get("Location"), "/admin/forgot-password?sent=1") {
		t.Fatalf("forgot from %s: %d %q, want the page every request gets", addr, rr.Code, rr.Header().Get("Location"))
	}
}

// An account holds one reset link at a time, and every request for one used
// to replace it: whoever knew a user name or an address could keep the
// owner's link dead by asking again as each mail went out, from as many
// addresses as the per-address cap took, and fill the owner's mailbox on the
// way.  An account is now sent one link in resetLinkEvery, whoever asks.
func TestForgotPasswordLeavesARecentLinkAlone(t *testing.T) {
	h, stub := newInviteTestHandler(t)
	h.updateSettingsInMemory(func(s *settings.Settings) { s.Server.BasePath = "/unmask" })
	ctx := context.Background()
	u, err := h.UserRepo.CreateWithProfile(ctx, "erin", "test-password-erin", "admin", "erin@example.com", false)
	if err != nil {
		t.Fatal(err)
	}
	stored := func() string {
		t.Helper()
		again, err := h.UserRepo.GetByID(ctx, u.ID)
		if err != nil {
			t.Fatal(err)
		}
		return again.ResetToken.String
	}
	hashOf := func(tok string) string { sum := sha256.Sum256([]byte(tok)); return hex.EncodeToString(sum[:]) }
	noMail := func(what string) {
		t.Helper()
		select {
		case m := <-stub.messages:
			t.Errorf("%s: a mail went out:\n%s", what, m)
		case <-time.After(400 * time.Millisecond):
		}
	}
	// windowOver moves the account's last link out of the window, as the
	// clock would.
	windowOver := func() {
		t.Helper()
		res, err := h.DB.Exec(`UPDATE unmask_login_throttle SET locked_until = ? WHERE k = ?`, time.Now().Unix()-1, resetLinkKey(u.ID))
		if err != nil {
			t.Fatal(err)
		}
		if n, _ := res.RowsAffected(); n != 1 {
			t.Fatalf("%d rows hold the account's last link, want 1", n)
		}
	}

	// The owner asks, and is mailed a link.
	forgotFrom(t, h, "198.51.100.1:1000", "erin")
	m := resetPathRE.FindStringSubmatch(stub.waitMessage(t))
	if m == nil {
		t.Fatal("the first mail carries no reset path")
	}
	first := m[1]
	if stored() != hashOf(first) {
		t.Fatal("the account does not hold the mailed link")
	}

	// Somebody else asks for the same account, by its name and by its
	// address, from other addresses: the same page, no other link, no other
	// mail -- and the owner's link is still the account's.
	forgotFrom(t, h, "203.0.113.7:1000", "erin")
	forgotFrom(t, h, "203.0.113.8:1000", "erin@example.com")
	noMail("a second request inside the window")
	if stored() != hashOf(first) {
		t.Fatal("a second request replaced the link the owner was mailed")
	}

	// The window over, a request is answered again, and the new link takes
	// the old one's place (the account still holds one).
	windowOver()
	forgotFrom(t, h, "203.0.113.9:1000", "erin")
	m = resetPathRE.FindStringSubmatch(stub.waitMessage(t))
	if m == nil || m[1] == first {
		t.Fatalf("after the window: no new link in the mail (%v)", m)
	}
	second := m[1]
	if stored() != hashOf(second) {
		t.Fatal("after the window the account does not hold the new link")
	}
	if _, err := h.UserRepo.ConsumeResetToken(ctx, first); err == nil {
		t.Error("the replaced link still redeems")
	}

	// An administrator's setup link is the account's link too: sent, it is
	// left alone by the forgot page for the same time -- and the
	// administrator's own resend is not held up.
	windowOver()
	superadmin, err := h.UserRepo.Create(ctx, "root", "test-password-root", user.RoleSuperadmin)
	if err != nil {
		t.Fatal(err)
	}
	resend := func() string {
		t.Helper()
		form := url.Values{"op": {"send_setup_link"}, "id": {strconv.FormatInt(u.ID, 10)}}
		req := httptest.NewRequest(http.MethodPost, "/unmask/admin/users/save", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		h.AdminUsersSave(rr, asUser(req, superadmin.ID, superadmin.Role))
		if rr.Code != http.StatusFound {
			t.Fatalf("resend: %d %s", rr.Code, rr.Body.String())
		}
		mm := resetPathRE.FindStringSubmatch(stub.waitMessage(t))
		if mm == nil {
			t.Fatal("the setup mail carries no path")
		}
		return mm[1]
	}
	invite := resend()
	forgotFrom(t, h, "203.0.113.10:1000", "erin")
	noMail("a forgot request right after an administrator's setup link")
	if stored() != hashOf(invite) {
		t.Fatal("a forgot request replaced the setup link an administrator had just sent")
	}
	if again := resend(); again == invite || stored() != hashOf(again) {
		t.Error("the administrator's own resend was held up")
	}

	// Another account is not held by this one's window.
	if _, err := h.UserRepo.CreateWithProfile(ctx, "frank", "test-password-frank", "admin", "frank@example.com", false); err != nil {
		t.Fatal(err)
	}
	forgotFrom(t, h, "203.0.113.11:1000", "frank")
	if mm := resetPathRE.FindStringSubmatch(stub.waitMessage(t)); mm == nil {
		t.Error("another account's request was not answered")
	}
}

// The page says how often a link is sent; the number is the code's.
func TestForgotPageNamesTheWindow(t *testing.T) {
	want := strconv.Itoa(int(resetLinkEvery / time.Minute))
	if newLoginThrottle().resetEvery != resetLinkEvery || resetLinkEvery < time.Minute {
		t.Fatalf("resetEvery = %s, resetLinkEvery = %s", newLoginThrottle().resetEvery, resetLinkEvery)
	}
	for _, lang := range []i18n.Lang{"en", "ja"} {
		text := i18n.T(lang, "forgot.sent")
		if !strings.Contains(text, want+" minutes") && !strings.Contains(text, want+" 分") {
			t.Errorf("forgot.sent (%s) does not name the %s minutes a link is sent once in: %q", lang, want, text)
		}
	}
}
