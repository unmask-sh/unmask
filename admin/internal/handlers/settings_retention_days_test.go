package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/i18n"
	"github.com/unmask-sh/unmask/admin/internal/settings"
	"github.com/unmask-sh/unmask/admin/internal/user"
)

// The audit log's and the notification list's retention are set on the
// retention tab, each its own number, 0 keeping the rows (the default for
// both), capped like the events window; a save writes them to config.yml
// under their own keys, and the tab shows them back.
func TestRetentionTabSavesTheAuditAndNoticeDays(t *testing.T) {
	h := installedHandler(t)
	st := *h.cfg()
	st.Server.BasePath = "/unmask"
	st.Nginx.OutputDir = t.TempDir() // a save renders nginx's configuration
	h.SetSettings(st)
	// The save reads the file back before writing it, like a real install's.
	h.ConfigPath = filepath.Join(t.TempDir(), "config.yml")
	if err := settings.Save(st, h.ConfigPath); err != nil {
		t.Fatal(err)
	}

	if c := h.cfg(); c.AuditLogRetentionDays != 0 || c.NoticeRetentionDays != 0 {
		t.Fatalf("defaults: audit %d notice %d, want 0 and 0 (kept)", c.AuditLogRetentionDays, c.NoticeRetentionDays)
	}
	form := url.Values{
		"events_retention_days":      {"7"},
		"audit_log_retention_days":   {"30"},
		"notice_retention_days":      {"4000"}, // over the cap
		"ask_history_retention_days": {"60"},
	}
	req := asRole(httptest.NewRequest(http.MethodPost, "/unmask/admin/settings/save?section=retention", strings.NewReader(form.Encode())), user.RoleSuperadmin)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.AdminSettingsSave(rr, req)
	if rr.Code != http.StatusFound && rr.Code != http.StatusSeeOther {
		t.Fatalf("save: %d %s", rr.Code, rr.Body.String())
	}
	if c := h.cfg(); c.AuditLogRetentionDays != 30 || c.NoticeRetentionDays != 3650 || c.EventsRetentionDays != 7 || c.AskHistoryRetentionDays != 60 {
		t.Errorf("after the save: audit %d notice %d events %d (location %q, cookies %q)",
			c.AuditLogRetentionDays, c.NoticeRetentionDays, c.EventsRetentionDays, rr.Header().Get("Location"), rr.Header()["Set-Cookie"])
	}
	raw, err := os.ReadFile(h.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"audit_log_retention_days: 30", "notice_retention_days: 3650", "ask_history_retention_days: 60"} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("config.yml lacks %q", want)
		}
	}
	if strings.Contains(string(raw), "audit_retention_days:") {
		t.Error("config.yml still carries the removed key")
	}

	get := asRole(httptest.NewRequest(http.MethodGet, "/unmask/admin/settings/retention/", nil), user.RoleSuperadmin)
	get.SetPathValue("tab", "retention")
	get.AddCookie(&http.Cookie{Name: i18n.CookieName, Value: "ja"})
	rr = httptest.NewRecorder()
	h.AdminSettingsIndex(rr, get)
	if rr.Code != http.StatusOK {
		t.Fatalf("the retention tab: %d", rr.Code)
	}
	tab := rr.Body.String()
	for _, want := range []string{
		`name="audit_log_retention_days" value="30"`,
		`name="notice_retention_days" value="3650"`,
		"監査ログの保持日数", "通知の保持日数",
	} {
		if !strings.Contains(tab, want) {
			t.Errorf("the retention tab lacks %q", want)
		}
	}
}
