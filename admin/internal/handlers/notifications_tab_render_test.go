package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// renderSettingsTab renders one settings tab and returns the body.
func renderSettingsTab(t *testing.T, h *Handler, tab string) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/settings/?tab="+tab, nil)
	req.SetPathValue("tab", tab)
	rr := httptest.NewRecorder()
	h.AdminSettingsIndex(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("tab %s: want 200, got %d", tab, rr.Code)
	}
	return rr.Body.String()
}

// TestNotificationsTabWired pins the final shape of the notifications tab:
// ONE tab, ONE form, with the channels and the SMTP server as separate cards
// inside it.  The event checkboxes gate webhook and mail equally, the mail
// pause lives on the mail card (not buried in the server card), and setting
// mail up is one screen with one save.  The tab shipped fully functional but
// nav-hidden ("until post-v0.1"); opened 2026-08-19.  This test keeps a
// template restore from re-hiding the tab, re-splitting it into a standalone
// smtp tab, or re-merging the pause into the server card (all shapes this
// page has cycled through).
func TestNotificationsTabWired(t *testing.T) {
	h := newTestHandler(t)

	top := renderSettingsTab(t, h, "top")
	href := `href="/admin/settings/notifications/"` // BasePath is empty under newTestHandler
	if !strings.Contains(top, `<li><a `+href) {
		t.Error("settings side-nav has no notifications link")
	}
	if !strings.Contains(top, `class="sti" `+href) {
		t.Error("settings TOP has no notifications card")
	}
	if strings.Contains(top, `/admin/settings/smtp/`) {
		t.Error("settings TOP still links a standalone smtp tab")
	}

	body := renderSettingsTab(t, h, "notifications")
	for _, want := range []string{
		`id="notify-form"`,
		`section=notifications`,
		`name="url"`,           // webhook channel
		`name="mail_disabled"`, // mail channel pause, on the mail card
		`name="mail_to"`,       // explicit alert recipients (empty = admin users)
		`name="host"`,          // SMTP server card, same form
		// The over-block breaker note: the alert has no per-event toggle, and
		// the tab says so ("fail-safe" appears in both locales' wording).
		`fail-safe`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("notifications tab body lacks %q", want)
		}
	}
	// One form, one save section: a second form or section would resurrect
	// the split-save shape.
	for _, gone := range []string{`id="smtp-form"`, `section=smtp`} {
		if strings.Contains(body, gone) {
			t.Errorf("notifications tab still carries %q -- the save split again", gone)
		}
	}
	// The pause precedes the server card: it belongs to the CHANNEL.  (Both
	// names are unique in the body, so index order is meaningful.)
	if strings.Index(body, `name="mail_disabled"`) > strings.Index(body, `name="host"`) {
		t.Error("the mail pause sits below the server fields -- it drifted back into the server card")
	}

	// A direct hit on the retired tab path falls back to TOP (the shared
	// unknown-tab behavior), not to a half-rendered smtp page.
	old := renderSettingsTab(t, h, "smtp")
	if strings.Contains(old, `name="host"`) {
		t.Error("tab=smtp still renders an smtp page")
	}
	if !strings.Contains(old, `class="sti" `+href) {
		t.Error("tab=smtp did not fall back to the settings TOP")
	}
}

// TestNotificationsSaveCarriesBothCards: one POST to section=notifications
// must persist the channel fields AND the SMTP-server card.  The no-op save
// test cannot catch a dropped applySMTPForm -- fields the handler ignores
// still round-trip unchanged -- so this pins the change actually landing.
func TestNotificationsSaveCarriesBothCards(t *testing.T) {
	h := newTestHandler(t)
	dir := t.TempDir()
	// Defaults come from loading an empty yaml (the same trick the no-op save
	// test uses): a hand-built partial struct would persist zero values no
	// real install produces.
	emptyPath := filepath.Join(dir, "empty-seed.yml")
	if err := os.WriteFile(emptyPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := settings.Load(emptyPath)
	if err != nil {
		t.Fatal(err)
	}
	s.Server.BasePath = "/unmask"
	s.Nginx.OutputDir = dir
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

	form := url.Values{
		"site_label":    {"jp-node"},
		"url":           {"https://hooks.example/x"},
		"format":        {"slack"},
		"mail_disabled": {"1"},
		"mail_to":       {"alerts@example.com"},
		"host":          {"smtp.example.com"},
		"port":          {"25"},
		"starttls":      {"1"},
		"from_address":  {"notify@example.com"},
	}
	req := httptest.NewRequest(http.MethodPost,
		"/unmask/admin/settings/save?section=notifications",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.AdminSettingsSave(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("save: want 302, got %d body=%s", rr.Code, rr.Body.String())
	}
	if loc := rr.Header().Get("Location"); !strings.Contains(loc, "/admin/settings/notifications/") {
		t.Errorf("save redirected to %q, want the notifications tab", loc)
	}

	after, err := settings.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if after.Notifications.SiteLabel != "jp-node" || after.Notifications.URL != "https://hooks.example/x" || !after.Notifications.MailDisabled || after.Notifications.MailTo != "alerts@example.com" {
		t.Errorf("channel fields not persisted: %+v", after.Notifications)
	}
	if after.SMTP.Host != "smtp.example.com" || after.SMTP.Port != 25 || !after.SMTP.StartTLS || after.SMTP.FromAddress != "notify@example.com" {
		t.Errorf("SMTP card not persisted by section=notifications: %+v", after.SMTP)
	}
}
