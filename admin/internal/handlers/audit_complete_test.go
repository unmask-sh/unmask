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
	"github.com/unmask-sh/unmask/admin/internal/user"
)

// auditedHandler: an installed admin with a config.yml to save to and an
// output directory of its own to render into.
func auditedHandler(t *testing.T) *Handler {
	t.Helper()
	h := installedHandler(t)
	dir := t.TempDir()
	s := *h.cfg()
	s.Server.BasePath = "/unmask"
	s.Nginx.OutputDir = filepath.Join(dir, "nginx")
	h.ConfigPath = filepath.Join(dir, "config.yml")
	if err := settings.Save(s, h.ConfigPath); err != nil {
		t.Fatal(err)
	}
	h.SetSettings(s)
	return h
}

func settingsSaveRows(t *testing.T, h *Handler) (targets []string, lastDetail string) {
	t.Helper()
	rows, err := h.DB.Query(`SELECT COALESCE(target, ''), COALESCE(detail, '') FROM unmask_user_audit WHERE action = 'settings_save' ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var target string
		if err := rows.Scan(&target, &lastDetail); err != nil {
			t.Fatal(err)
		}
		targets = append(targets, target)
	}
	return targets, lastDetail
}

// A save whose render fails is still a save: config.yml is written and the
// settings are live.  The render came first and returned on its failure, so
// such a change -- a webhook pointed elsewhere, say -- left no row in the
// audit log.
func TestSettingsSaveIsAuditedWhenItsRenderFails(t *testing.T) {
	h := auditedHandler(t)
	save := func(hook, format string) *httptest.ResponseRecorder {
		form := url.Values{"url": {hook}, "format": {format}}
		req := asRole(httptest.NewRequest(http.MethodPost, "/unmask/admin/settings/save?section=notifications", strings.NewReader(form.Encode())), user.RoleSuperadmin)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		h.AdminSettingsSave(rr, req)
		return rr
	}
	save("https://hooks.example.com/a", "slack")
	if targets, _ := settingsSaveRows(t, h); len(targets) != 1 {
		t.Fatalf("a plain save wrote %d audit rows, want 1", len(targets))
	}

	// The output directory becomes a file: the next render fails.
	out := h.cfg().Nginx.OutputDir
	if err := os.RemoveAll(out); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	rr := save("https://hooks.example.com/changed", "discord")
	flash := ""
	for _, c := range rr.Result().Cookies() {
		if c.Name == flashCookiePrefix+"err" {
			flash, _ = url.QueryUnescape(c.Value)
		}
	}
	if !strings.Contains(flash, "render failed") {
		t.Fatalf("the render did not fail as arranged (flash %q)", flash)
	}
	cur, err := settings.Load(h.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if cur.Notifications.URL != "https://hooks.example.com/changed" || h.cfg().Notifications.URL != cur.Notifications.URL {
		t.Fatalf("precondition: the save itself was not made (file %q, live %q)", cur.Notifications.URL, h.cfg().Notifications.URL)
	}
	targets, detail := settingsSaveRows(t, h)
	if len(targets) != 2 {
		t.Fatalf("%d audit rows after a save whose render failed, want 2: the change is saved and live", len(targets))
	}
	// The hook's address is a credential and is redacted in the snapshots;
	// the format beside it is what the diff shows.
	if !strings.Contains(detail, "discord") {
		t.Errorf("the row does not carry the change: %.200s", detail)
	}
	if strings.Contains(detail, "hooks.example.com/changed") {
		t.Error("the row carries the webhook address in the clear")
	}
}

// A site's own record -- its CAPTCHA provider and keys, its proof-of-work
// difficulty -- is saved and deleted through endpoints of its own, which
// wrote nothing to the audit log.  They write a settings_save row naming the
// tab and the site, with the keys redacted like every other snapshot.
func TestPerSiteSavesAreAudited(t *testing.T) {
	h := auditedHandler(t)
	post := func(path string, form url.Values, fn func(http.ResponseWriter, *http.Request)) {
		req := asRole(httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode())), user.RoleSuperadmin)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		fn(httptest.NewRecorder(), req)
	}
	post("/unmask/admin/settings/challenge/site/save", url.Values{
		"site": {"shop.example.com"}, "use_site_override": {"1"}, "pow_difficulty": {"10"},
		"provider": {"turnstile"}, "turnstile_site_key": {"site-key"}, "turnstile_secret_key": {"s3cret-key-value"},
	}, h.AdminChallengeSiteSave)
	cur, err := settings.Load(h.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if cur.Challenge.Sites["shop.example.com"].PowDifficulty != 10 {
		t.Fatalf("precondition: the site's record was not saved: %+v", cur.Challenge.Sites)
	}
	targets, detail := settingsSaveRows(t, h)
	if len(targets) != 1 || targets[0] != "challenge@shop.example.com" {
		t.Fatalf("audit rows after a per-site save: %v, want one for challenge@shop.example.com", targets)
	}
	if !strings.Contains(detail, "shop.example.com") {
		t.Errorf("the row's diff does not name the site: %.200s", detail)
	}
	if strings.Contains(detail, "s3cret-key-value") {
		t.Error("the row carries the site's CAPTCHA secret key in the clear")
	}

	post("/unmask/admin/settings/challenge/site/delete", url.Values{"site": {"shop.example.com"}}, h.AdminChallengeSiteDelete)
	if targets, _ := settingsSaveRows(t, h); len(targets) != 2 {
		t.Fatalf("audit rows after the per-site delete: %v, want a second one", targets)
	}
}

// The setup wizard creates the first superadmin and decides the database,
// and wrote nothing to the audit log: a new install's log began with the
// first login.  It writes a row of its own, under the account it created.
func TestSetupWizardWritesItsAuditRow(t *testing.T) {
	h, token := optionsWizard(t)
	res := wizardPost(h.AdminSetupInstall, nil, token, "127.0.0.1:9477")
	if res.StatusCode != http.StatusFound || !strings.Contains(res.Header.Get("Location"), "/admin/setup/done") {
		t.Fatalf("install: %d %s", res.StatusCode, res.Header.Get("Location"))
	}
	var username, detail string
	var n int
	rows, err := h.DB.Query(`SELECT username, COALESCE(detail, '') FROM unmask_user_audit WHERE action = 'setup_wizard'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		if err := rows.Scan(&username, &detail); err != nil {
			t.Fatal(err)
		}
		n++
	}
	if n != 1 {
		t.Fatalf("%d setup_wizard rows after the install, want 1", n)
	}
	if username != "admin" {
		t.Errorf("the row is under %q, want the account the wizard created", username)
	}
	for _, want := range []string{`"reconfigure":false`, `"admin_created":true`, `"db":"sqlite"`} {
		if !strings.Contains(detail, want) {
			t.Errorf("the row's detail lacks %s: %s", want, detail)
		}
	}
}
