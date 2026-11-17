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

// The link in a password-reset or invitation mail is built on
// admin_public_url, or failing that on a host admin_allowed_hosts admits.
// An admin who wrote a host of their own there had a superadmin's link point
// at it, and the token arrive with the first click.  Only a superadmin
// changes either; the rest of the Network tab, and a row's note, stay an
// admin's.
func TestOnlyASuperadminMovesTheLinksInMail(t *testing.T) {
	h := ruleTestHandler(t)
	save := func(role string, form url.Values) bool {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/unmask/admin/settings/save?section=network", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Host = "admin.example.com"
		rr := httptest.NewRecorder()
		h.AdminSettingsSave(rr, asRole(req, role))
		return strings.Contains(rr.Header().Get("Location"), "saved=1")
	}
	stored := func() settings.Nginx {
		t.Helper()
		cur, err := settings.Load(h.ConfigPath)
		if err != nil {
			t.Fatal(err)
		}
		return cur.Nginx
	}
	tab := func(over url.Values) url.Values {
		f := url.Values{
			"admin_public_url":            {"https://admin.example.com/unmask"},
			"admin_allowed_hosts":         {"exact:admin.example.com"},
			"admin_allowed_hosts_enabled": {"1"},
		}
		for k, v := range over {
			f[k] = v
		}
		return f
	}
	if !save("superadmin", tab(nil)) {
		t.Fatal("a superadmin's save was refused")
	}
	want := adminLinkBase(stored())
	if !strings.Contains(want, "https://admin.example.com/unmask") || !strings.Contains(want, "admin.example.com") {
		t.Fatalf("the saved link base: %q", want)
	}

	for name, f := range map[string]url.Values{
		"a public address of their own":    tab(url.Values{"admin_public_url": {"https://attacker.example"}}),
		"the public address cleared":       tab(url.Values{"admin_public_url": {""}}),
		"a host of their own, first":       tab(url.Values{"admin_allowed_hosts": {"exact:attacker.example", "exact:admin.example.com"}, "admin_allowed_hosts_enabled": {"1", "1"}}),
		"a pattern that admits their host": tab(url.Values{"admin_allowed_hosts": {"exact:admin.example.com", "subdomain:attacker.example"}, "admin_allowed_hosts_enabled": {"1", "1"}}),
		"the operator's row switched off":  tab(url.Values{"admin_allowed_hosts_enabled": {"0"}}),
	} {
		if save("admin", f) {
			t.Errorf("an admin's save went through with %s", name)
		}
		if got := adminLinkBase(stored()); got != want {
			t.Fatalf("after an admin's save with %s the links are built on %q, want %q", name, got, want)
		}
	}

	// What moves no link is an admin's to save: another list on the tab, and
	// the note on the host's row.
	if !save("admin", tab(url.Values{"metrics_allow_from": {"192.0.2.0/24"}, "admin_allowed_hosts_title": {"the office"}})) {
		t.Fatal("an admin's save of the metrics list and a row's note was refused")
	}
	got := stored()
	if adminLinkBase(got) != want {
		t.Errorf("the links moved with an admin's own save: %q", adminLinkBase(got))
	}
	if len(got.MetricsAllowFrom) != 1 || got.MetricsAllowFrom[0] != "192.0.2.0/24" {
		t.Errorf("the metrics list after an admin's save: %q", got.MetricsAllowFrom)
	}
	if len(got.AdminAllowedHostsTitle) != 1 || got.AdminAllowedHostsTitle[0] != "the office" {
		t.Errorf("the row's note after an admin's save: %q", got.AdminAllowedHostsTitle)
	}
}

// The check is on what the save leaves, not on what the form carries.  An
// admin's Network page opened before a superadmin set the public address
// still shows the old one; saved with another field changed, the merge keeps
// the superadmin's address, so nothing the admin may not change has changed
// and the save goes through.
func TestAdminsEarlierPageKeepsTheSuperadminsAddress(t *testing.T) {
	f := newStaleSaveFixture(t)
	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/settings/network/", nil)
	req.SetPathValue("tab", "network")
	rr := httptest.NewRecorder()
	f.h.AdminSettingsIndex(rr, req)
	m := baseFieldRE.FindStringSubmatch(rr.Body.String())
	if m == nil {
		t.Fatalf("the network form carries no _base (status %d)", rr.Code)
	}
	save := func(role string, form url.Values) bool {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/unmask/admin/settings/save?section=network", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		f.h.AdminSettingsSave(rr, asRole(req, role))
		return strings.Contains(rr.Header().Get("Location"), "saved=1")
	}
	if !save("superadmin", url.Values{"admin_public_url": {"https://admin.example.com/unmask"}}) {
		t.Fatal("the superadmin's save was refused")
	}
	if !save("admin", url.Values{"_base": {m[1]}, "admin_public_url": {""}, "metrics_allow_from": {"192.0.2.0/24"}}) {
		t.Fatal("an admin's save from the earlier page was refused; it changed the metrics list alone")
	}
	got := f.stored().Nginx
	if got.AdminPublicURL != "https://admin.example.com/unmask" {
		t.Errorf("the public address after the admin's save: %q, want the superadmin's", got.AdminPublicURL)
	}
	if len(got.MetricsAllowFrom) != 1 || got.MetricsAllowFrom[0] != "192.0.2.0/24" {
		t.Errorf("the metrics list after the admin's save: %q", got.MetricsAllowFrom)
	}
}
