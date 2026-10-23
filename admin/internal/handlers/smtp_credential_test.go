package handlers

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// closingRelay listens on a loopback port and closes every connection at
// once, so a test send toward it fails on the greeting without leaving the
// host -- the point being only whether the handler attempted the send.
func closingRelay(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func postSMTPTest(t *testing.T, h *Handler, form url.Values) (int, map[string]any) {
	t.Helper()
	form.Set("to", "someone@example.com")
	req := httptest.NewRequest(http.MethodPost, "/unmask/admin/api/smtp/test", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.AdminSMTPTest(rr, req)
	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("smtp test answer is not JSON: %s", rr.Body.String())
	}
	return rr.Code, body
}

func TestSMTPSameServer(t *testing.T) {
	saved := settings.SMTP{Host: "smtp.example.com", Port: 587, Username: "mailer"}
	cases := []struct {
		name     string
		host     string
		port     int
		username string
		want     bool
	}{
		{"as saved", "smtp.example.com", 587, "mailer", true},
		{"host case", "SMTP.Example.COM", 587, "mailer", true},
		{"other host", "smtp.evil.example", 587, "mailer", false},
		{"other port", "smtp.example.com", 2525, "mailer", false},
		{"other user", "smtp.example.com", 587, "someone", false},
		{"no user", "smtp.example.com", 587, "", false},
	}
	for _, c := range cases {
		if got := smtpSameServer(saved, c.host, c.port, c.username); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
	// A hand-written config may leave the port out; the mailer sends to 587
	// then, and so is the form's default.
	if !smtpSameServer(settings.SMTP{Host: "smtp.example.com"}, "smtp.example.com", 587, "") {
		t.Error("a saved port of 0 should match the form's 587")
	}
}

// The saved password goes only to the saved relay.  With the host, port or
// username changed and no password typed, the test send is refused with
// password_required -- an admin-role user pointing the form at a relay of
// their own would otherwise read the saved password off it.  A typed
// password, or no saved one, is sent wherever the form says.
func TestAdminSMTPTestSavedPasswordOnlyForSavedRelay(t *testing.T) {
	h := newTestHandler(t)
	port := closingRelay(t)
	var s settings.Settings
	s.SMTP = settings.SMTP{Host: "127.0.0.1", Port: port, Username: "mailer", Password: "LEAK-saved"}
	h.SetSettings(s)
	asSaved := url.Values{"host": {"127.0.0.1"}, "port": {strconv.Itoa(port)}, "username": {"mailer"}}

	refused := func(name string, form url.Values) {
		t.Helper()
		code, body := postSMTPTest(t, h, form)
		if code != http.StatusBadRequest || body["error"] != "password_required" {
			t.Errorf("%s: want 400 password_required, got %d %v", name, code, body)
		}
	}
	attempted := func(name string, form url.Values) {
		t.Helper()
		code, body := postSMTPTest(t, h, form)
		if code == http.StatusBadRequest || body["error"] == "password_required" {
			t.Errorf("%s: the send was refused: %d %v", name, code, body)
		}
	}

	other := url.Values{"host": {"127.0.0.1"}, "port": {strconv.Itoa(port)}, "username": {"someone-else"}}
	refused("other username", other)
	refused("other port", url.Values{"host": {"127.0.0.1"}, "port": {strconv.Itoa(port + 1)}, "username": {"mailer"}})
	refused("other host", url.Values{"host": {"relay.evil.example"}, "port": {strconv.Itoa(port)}, "username": {"mailer"}})

	attempted("as saved, password empty", asSaved)
	typed := url.Values{"host": {"127.0.0.1"}, "port": {strconv.Itoa(port)}, "username": {"someone-else"}, "password": {"typed"}}
	attempted("other username, password typed", typed)

	s.SMTP.Password = ""
	h.SetSettings(s)
	attempted("no saved password, other username", other)
}

// A changed host drops the stored password unless a new one is typed: the
// stored one was given for the old relay.  The port, the username and the
// host's case are not a change of relay.
func TestApplySMTPFormDropsPasswordWhenHostChanges(t *testing.T) {
	apply := func(c settings.SMTP, form url.Values) (settings.SMTP, bool) {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		cleared := applySMTPForm(&c, req)
		return c, cleared
	}
	saved := settings.SMTP{Host: "smtp.example.com", Port: 587, Username: "mailer", Password: "pw"}

	if c, cleared := apply(saved, url.Values{"host": {"SMTP.example.com"}, "port": {"2525"}, "username": {"other"}}); cleared || c.Password != "pw" {
		t.Errorf("same host (case, port, user differ): cleared=%v password=%q", cleared, c.Password)
	}
	if c, cleared := apply(saved, url.Values{"host": {"relay.example.net"}, "port": {"587"}, "username": {"mailer"}}); !cleared || c.Password != "" {
		t.Errorf("new host, no password: cleared=%v password=%q", cleared, c.Password)
	}
	if c, cleared := apply(saved, url.Values{"host": {"relay.example.net"}, "password": {"new-pw"}}); cleared || c.Password != "new-pw" {
		t.Errorf("new host with a password: cleared=%v password=%q", cleared, c.Password)
	}
	if c, cleared := apply(saved, url.Values{"host": {""}}); !cleared || c.Password != "" {
		t.Errorf("host blanked: cleared=%v password=%q", cleared, c.Password)
	}
	none := settings.SMTP{Host: "smtp.example.com"}
	if _, cleared := apply(none, url.Values{"host": {"relay.example.net"}}); cleared {
		t.Error("nothing stored, yet reported as cleared")
	}
}

// The whole save: the password is gone from the file, and the redirect
// carries the flag the tab's banner reads, which then says so.
func TestNotificationsSaveFlagsDroppedPassword(t *testing.T) {
	h := newTestHandler(t)
	dir := t.TempDir()
	emptyPath := filepath.Join(dir, "empty.yml")
	if err := os.WriteFile(emptyPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := settings.Load(emptyPath)
	if err != nil {
		t.Fatal(err)
	}
	s.Server.BasePath = "/unmask"
	s.Nginx.OutputDir = dir
	s.CommunityBans.MapDir = dir
	s.SMTP = settings.SMTP{Host: "smtp.example.com", Port: 587, Username: "mailer", Password: "pw"}
	cfgPath := filepath.Join(dir, "config.yml")
	if err := settings.Save(s, cfgPath); err != nil {
		t.Fatal(err)
	}
	h.ConfigPath = cfgPath
	loaded, err := settings.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	h.SetSettings(loaded)

	form := url.Values{"host": {"relay.example.net"}, "port": {"587"}, "username": {"mailer"}, "format": {"slack"}}
	req := httptest.NewRequest(http.MethodPost, "/unmask/admin/settings/save?section=notifications", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.AdminSettingsSave(rr, req)
	loc := rr.Header().Get("Location")
	if rr.Code != http.StatusFound || !strings.Contains(loc, "credential_cleared=smtp_password") {
		t.Fatalf("save: want a 302 flagged credential_cleared=smtp_password, got %d -> %s", rr.Code, loc)
	}
	if got, _ := settings.Load(cfgPath); got.SMTP.Password != "" || got.SMTP.Host != "relay.example.net" {
		t.Errorf("file after the save: %+v", got.SMTP)
	}

	req = httptest.NewRequest(http.MethodGet, "/unmask/admin/settings/notifications/?saved=1&section=notifications&credential_cleared=smtp_password", nil)
	req.SetPathValue("tab", "notifications")
	req.Header.Set("Accept-Language", "en")
	rr = httptest.NewRecorder()
	h.AdminSettingsIndex(rr, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "the saved password was dropped") {
		t.Errorf("the notifications tab does not say the password was dropped (HTTP %d)", rr.Code)
	}

	// The same host again (a port change) keeps what is stored.
	h.SetSettings(s)
	if err := settings.Save(s, cfgPath); err != nil {
		t.Fatal(err)
	}
	form = url.Values{"host": {"smtp.example.com"}, "port": {"2525"}, "username": {"mailer"}, "format": {"slack"}}
	req = httptest.NewRequest(http.MethodPost, "/unmask/admin/settings/save?section=notifications", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = httptest.NewRecorder()
	h.AdminSettingsSave(rr, req)
	if loc := rr.Header().Get("Location"); strings.Contains(loc, "credential_cleared") {
		t.Errorf("a port change flagged the password as dropped: %s", loc)
	}
	if got, _ := settings.Load(cfgPath); got.SMTP.Password != "pw" || got.SMTP.Port != 2525 {
		t.Errorf("file after the port change: %+v", got.SMTP)
	}
}
