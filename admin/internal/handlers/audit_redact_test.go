package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
	"github.com/unmask-sh/unmask/admin/internal/user"
)

// auditHandler: a Handler with a migrated DB (the audit table lives there),
// one admin user, and a config file whose credentials each carry the LEAK
// marker -- nothing else in the file produces it, so one substring search
// over an audit row tells whether any of them got through.
func auditHandler(t *testing.T) (h *Handler, cfgPath string, userID int64) {
	t.Helper()
	dir := t.TempDir()
	conn, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: filepath.Join(dir, "a.sqlite")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	if err := db.Migrate(conn); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(`INSERT INTO unmask_user (username, password_hash, role) VALUES ('auditor', 'x', 'admin')`); err != nil {
		t.Fatal(err)
	}
	if err := conn.QueryRow(`SELECT id FROM unmask_user WHERE username = 'auditor'`).Scan(&userID); err != nil {
		t.Fatal(err)
	}
	h = &Handler{DB: conn, UserRepo: &user.Repository{DB: conn}}

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
	s.Secret.BVSecret = "LEAK-bv-session-key"
	s.SMTP = settings.SMTP{Host: "smtp.example.com", Port: 587, Username: "mailer", Password: "LEAK-smtp-old"}
	s.AIAdvisor.APIKey = "LEAK-ai-key"
	s.Notifications.URL = "https://hooks.example/services/LEAK-hook-old"
	cfgPath = filepath.Join(dir, "config.yml")
	if err := settings.Save(s, cfgPath); err != nil {
		t.Fatal(err)
	}
	h.ConfigPath = cfgPath
	loaded, err := settings.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	h.SetSettings(loaded)
	return h, cfgPath, userID
}

func asAdmin(r *http.Request, id int64) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), sessionCtxKey{},
		&SessionPayload{UserID: id, Role: "admin", Exp: time.Now().Add(time.Hour).Unix()}))
}

// latestAudit returns the newest audit row with the action, parsed.
func latestAudit(t *testing.T, h *Handler, action string) (*user.AuditEntry, AuditSettingsDetail) {
	t.Helper()
	rows, err := h.UserRepo.ListAudit(context.Background(), 20, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range rows {
		if e.Action != action || !e.Detail.Valid {
			continue
		}
		var d AuditSettingsDetail
		if err := json.Unmarshal([]byte(e.Detail.String), &d); err != nil {
			t.Fatalf("audit detail of %s: %v", action, err)
		}
		return e, d
	}
	t.Fatalf("no %s audit row", action)
	return nil, AuditSettingsDetail{}
}

func mustHaveNoSecret(t *testing.T, what, body string) {
	t.Helper()
	for _, line := range strings.Split(body, "\n") {
		if strings.Contains(line, "LEAK-") {
			t.Errorf("%s carries a secret: %s", what, strings.TrimSpace(line))
		}
	}
}

// A settings save writes its before / after snapshots and the diff with
// every credential redacted -- the row is retained and shown to the admin
// role, and bv_secret alone would let a reader of it forge a superadmin
// session.  The save itself still lands the new password in the file.
func TestSettingsSaveAuditRowCarriesNoSecrets(t *testing.T) {
	h, cfgPath, uid := auditHandler(t)
	form := url.Values{
		"host": {"smtp.example.com"}, "port": {"587"}, "username": {"mailer"},
		"password": {"LEAK-smtp-new"}, "starttls": {"1"},
		"url": {"https://hooks.example/services/LEAK-hook-new"}, "format": {"slack"},
	}
	req := asAdmin(httptest.NewRequest(http.MethodPost, "/unmask/admin/settings/save?section=notifications",
		strings.NewReader(form.Encode())), uid)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.AdminSettingsSave(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("save: want 302, got %d body=%s", rr.Code, rr.Body.String())
	}

	e, d := latestAudit(t, h, "settings_save")
	if e.Target.String != "notifications" {
		t.Errorf("audit target %q, want the section", e.Target.String)
	}
	mustHaveNoSecret(t, "before", d.Before)
	mustHaveNoSecret(t, "after", d.After)
	mustHaveNoSecret(t, "diff", d.Diff)
	if !strings.Contains(d.Before, "***REDACTED***") || !strings.Contains(d.After, "***REDACTED***") {
		t.Error("the snapshots do not carry the redaction marker where the secrets were")
	}
	if !strings.Contains(d.Diff, "starttls") {
		t.Errorf("the diff lost the non-secret change:\n%s", d.Diff)
	}
	got, err := settings.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if got.SMTP.Password != "LEAK-smtp-new" || got.Notifications.URL != "https://hooks.example/services/LEAK-hook-new" {
		t.Errorf("the save did not land the new credentials: %+v / %q", got.SMTP, got.Notifications.URL)
	}
}

// Restoring a redacted row puts the live secrets back where the marker is:
// the file and the in-memory settings keep bv_secret and the rest, and the
// restore's own audit row is redacted like any other.  A snapshot taken
// before a rotation does not know the old secret, so the current one stays.
func TestAuditRestorePutsLiveSecretsBack(t *testing.T) {
	h, cfgPath, uid := auditHandler(t)

	// A manual snapshot: the same redaction, and the row restore reads.
	req := asAdmin(httptest.NewRequest(http.MethodPost, "/unmask/admin/settings/snapshot",
		strings.NewReader(url.Values{"name": {"before-rotation"}}.Encode())), uid)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.AdminSettingsSnapshot(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("snapshot: want 302, got %d body=%s", rr.Code, rr.Body.String())
	}
	snap, d := latestAudit(t, h, "settings_snapshot")
	mustHaveNoSecret(t, "snapshot", d.Before)

	// Rotate the SMTP password and change a plain setting after the snapshot.
	live := h.snapshotSettings()
	live.SMTP.Password = "LEAK-smtp-rotated"
	live.SMTP.StartTLS = true
	if err := settings.Save(live, cfgPath); err != nil {
		t.Fatal(err)
	}
	h.SetSettings(live)

	req = asAdmin(httptest.NewRequest(http.MethodPost, "/unmask/admin/audit/restore?id="+strconv.FormatInt(snap.ID, 10), nil), uid)
	rr = httptest.NewRecorder()
	h.AdminAuditRestore(rr, req)
	if rr.Code != http.StatusFound || !strings.Contains(rr.Header().Get("Location"), "saved=1") {
		t.Fatalf("restore: want a 302 to saved=1, got %d -> %s", rr.Code, rr.Header().Get("Location"))
	}
	got, err := settings.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if got.Secret.BVSecret != "LEAK-bv-session-key" {
		t.Errorf("bv_secret after restore: %q", got.Secret.BVSecret)
	}
	if got.SMTP.Password != "LEAK-smtp-rotated" {
		t.Errorf("smtp password after restore: %q, want the live one", got.SMTP.Password)
	}
	if got.AIAdvisor.APIKey != "LEAK-ai-key" || got.Notifications.URL != "https://hooks.example/services/LEAK-hook-old" {
		t.Errorf("other credentials after restore: %q / %q", got.AIAdvisor.APIKey, got.Notifications.URL)
	}
	if got.SMTP.StartTLS {
		t.Error("the plain setting was not restored to the snapshot's value")
	}
	if strings.Contains(h.cfg().Secret.BVSecret, "REDACTED") {
		t.Error("the marker reached the in-memory settings")
	}
	_, rd := latestAudit(t, h, "settings_save")
	mustHaveNoSecret(t, "restore row before", rd.Before)
	mustHaveNoSecret(t, "restore row after", rd.After)
}

// A row written before the redaction holds the secrets in the clear, and
// restoring it applies them as written -- the refill only touches the marker.
func TestAuditRestoreAppliesLegacyClearRow(t *testing.T) {
	h, cfgPath, uid := auditHandler(t)
	legacy := h.snapshotSettings()
	legacy.SMTP.Password = "LEAK-smtp-legacy"
	body, err := settings.MarshalYAML(legacy)
	if err != nil {
		t.Fatal(err)
	}
	det, _ := json.Marshal(AuditSettingsDetail{Section: "notifications", Before: body, After: body, Diff: "(no changes)"})
	h.UserRepo.Record(context.Background(), uid, "auditor", "settings_save", "notifications", string(det))
	row, _ := latestAudit(t, h, "settings_save")

	req := asAdmin(httptest.NewRequest(http.MethodPost, "/unmask/admin/audit/restore?id="+strconv.FormatInt(row.ID, 10), nil), uid)
	rr := httptest.NewRecorder()
	h.AdminAuditRestore(rr, req)
	if rr.Code != http.StatusFound || !strings.Contains(rr.Header().Get("Location"), "saved=1") {
		t.Fatalf("restore: want a 302 to saved=1, got %d -> %s", rr.Code, rr.Header().Get("Location"))
	}
	got, err := settings.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if got.SMTP.Password != "LEAK-smtp-legacy" {
		t.Errorf("a clear-text snapshot value was not applied: %q", got.SMTP.Password)
	}
}
