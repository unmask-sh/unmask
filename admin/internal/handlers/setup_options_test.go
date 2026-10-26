package handlers

import (
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/i18n"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// optionsWizard: a bootstrap wizard taken through the token, db and user
// steps on a fresh SQLite, with a config.yml the package install would have
// left (the DB block; everything else at its default).  Returns the handler
// and the token the cookie carries.
func optionsWizard(t *testing.T) (*Handler, string) {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "unmask.sqlite")
	cfgPath := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(cfgPath, []byte("db:\n  driver: sqlite\n  sqlite_path: "+dbPath+"\nsecret:\n  bv_secret: 0123456789abcdef0123456789abcdef\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	conn, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: dbPath})
	if err != nil {
		t.Fatalf("open boot db: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	h := &Handler{DB: conn, ConfigPath: cfgPath, Version: "0.0.0"}
	live, err := settings.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	live.Server.BasePath = "/unmask"
	h.SetSettings(live)

	token := "tok-options-" + filepath.Base(dir)
	oldPath, oldLegacy := SetupTokenPath, legacySetupTokenPath
	SetupTokenPath = filepath.Join(dir, ".setup-token")
	legacySetupTokenPath = ""
	t.Cleanup(func() { SetupTokenPath, legacySetupTokenPath = oldPath, oldLegacy; dropWizardState(token) })
	if err := os.WriteFile(SetupTokenPath, []byte(token), 0o600); err != nil {
		t.Fatal(err)
	}
	if res := wizardPost(h.AdminSetupSaveDB, url.Values{"driver": {"sqlite"}, "sqlite_path": {dbPath}}, token, ""); res.StatusCode != http.StatusFound {
		t.Fatalf("db step: %d", res.StatusCode)
	}
	if res := wizardPost(h.AdminSetupSaveUser, url.Values{"username": {"admin"}, "password": {"correct-horse-battery"}, "password_confirm": {"correct-horse-battery"}}, token, ""); res.StatusCode != http.StatusFound {
		t.Fatalf("user step: %d", res.StatusCode)
	}
	return h, token
}

// wizardPost posts form to a wizard handler with the token cookie, in
// English, from host (the Host header) when given.
func wizardPost(fn http.HandlerFunc, form url.Values, token, host string) *http.Response {
	r := httptest.NewRequest(http.MethodPost, "/unmask/admin/setup/x", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(setupTokenCookie(token))
	r.AddCookie(&http.Cookie{Name: i18n.CookieName, Value: "en"})
	if host != "" {
		r.Host = host
	}
	w := httptest.NewRecorder()
	fn(w, r)
	return w.Result()
}

// wizardPage renders the wizard's current step in English, from host.
func wizardPage(t *testing.T, h *Handler, token, host, query string) string {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/unmask/admin/setup/"+query, nil)
	r.AddCookie(setupTokenCookie(token))
	r.AddCookie(&http.Cookie{Name: i18n.CookieName, Value: "en"})
	r.Host = host
	w := httptest.NewRecorder()
	h.AdminSetupIndex(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /admin/setup/%s: %d %s", query, w.Code, w.Header().Get("Location"))
	}
	b, _ := io.ReadAll(w.Result().Body)
	return string(b)
}

// The options step follows the user step on a first run: every communication
// ticked, the hostname the wizard was reached on prefilled.  What the operator
// unticks is off in the saved config and in the live settings, the hostname
// is an exact entry, monitor mode is on; what was left ticked stays as it was.
func TestSetupWizardOptionsStep(t *testing.T) {
	h, token := optionsWizard(t)
	const host = "admin.example.test"

	page := wizardPage(t, h, token, host+":8443", "")
	if !strings.Contains(page, i18n.T(i18n.LangEN, "setup.options.h")) {
		t.Fatalf("after the user step the wizard is not on the options step:\n%s", page)
	}
	for _, name := range []string{"comm_feed", "comm_liveness", "comm_country", "comm_geoip", "comm_sync", "comm_version"} {
		if !strings.Contains(page, `name="`+name+`" value="1" checked`) {
			t.Errorf("%s is not ticked by default", name)
		}
	}
	if strings.Contains(page, `name="observe_only" value="1" checked`) {
		t.Error("monitor mode is ticked by default")
	}
	if !strings.Contains(page, `name="admin_host" value="`+host+`"`) {
		t.Errorf("the hostname field is not prefilled with the Host reached (port stripped):\n%s", page)
	}
	if !strings.Contains(page, "https://unmask.sh/feed/privacy/") {
		t.Error("the step does not link the privacy document")
	}

	res := wizardPost(h.AdminSetupSaveOptions, url.Values{
		"comm_liveness": {"1"}, "comm_geoip": {"1"}, "comm_sync": {"1"},
		"admin_host": {"Admin.Example.Test"}, "observe_only": {"1"},
	}, token, host)
	if res.StatusCode != http.StatusFound || strings.Contains(res.Header.Get("Location"), "err=") {
		t.Fatalf("options step: %d %s", res.StatusCode, res.Header.Get("Location"))
	}
	st := wizardStateForKey(token)
	if !st.OptionsSet {
		t.Fatal("the options step did not record OptionsSet")
	}
	if want := "exact:" + host; st.Options.AdminHost != want {
		t.Errorf("AdminHost = %q, want %q (lowercased, exact)", st.Options.AdminHost, want)
	}

	// The review names what was turned off, the host and the mode.  (The
	// labels are compared as the template writes them, apostrophes escaped.)
	page = wizardPage(t, h, token, host, "")
	for _, want := range []string{
		html.EscapeString(i18n.T(i18n.LangEN, "setup.review.h")),
		html.EscapeString(i18n.T(i18n.LangEN, "setup.options.comm_feed")),
		html.EscapeString(i18n.T(i18n.LangEN, "setup.options.comm_country")),
		html.EscapeString(i18n.T(i18n.LangEN, "setup.options.comm_version")),
		"<code>" + host + "</code>",
		html.EscapeString(i18n.T(i18n.LangEN, "setup.review.mode_observe")),
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the review lacks %q", want)
		}
	}
	if strings.Contains(page, html.EscapeString(i18n.T(i18n.LangEN, "setup.options.comm_liveness"))) {
		t.Error("the review lists a communication that was left on as turned off")
	}

	res = wizardPost(h.AdminSetupInstall, nil, token, host)
	if res.StatusCode != http.StatusFound || !strings.Contains(res.Header.Get("Location"), "/admin/setup/done") {
		t.Fatalf("install: %d %s", res.StatusCode, res.Header.Get("Location"))
	}
	saved, err := settings.Load(h.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []settings.Settings{saved, *h.cfg()} {
		if s.CommunityBans.ResolvedSubscribeMode() != settings.SubscribeOff {
			t.Errorf("subscribe_mode = %q, want off", s.CommunityBans.SubscribeMode)
		}
		if !s.CommunityBans.PublishLiveness || s.CommunityBans.PublishCountry {
			t.Errorf("publish_liveness=%v publish_country=%v, want true/false", s.CommunityBans.PublishLiveness, s.CommunityBans.PublishCountry)
		}
		if !s.IPGeo.AutoFetch || !s.IPGeo.AutoUpdate || !s.IPGeo.AutoUpdateASN {
			t.Errorf("the GeoIP switches were touched although left on: %+v", s.IPGeo)
		}
		if s.Nginx.SyncDisabled || !s.VersionCheckDisabled {
			t.Errorf("sync_disabled=%v version_check_disabled=%v, want false/true", s.Nginx.SyncDisabled, s.VersionCheckDisabled)
		}
		if len(s.Nginx.AdminAllowedHosts) != 1 || s.Nginx.AdminAllowedHosts[0] != "exact:"+host {
			t.Errorf("admin_allowed_hosts = %v, want [exact:%s]", s.Nginx.AdminAllowedHosts, host)
		}
		if s.Challenge.Default.ObserveOnly == nil || !*s.Challenge.Default.ObserveOnly {
			t.Error("observe_only is not on")
		}
	}
}

// A wizard driven by a script posts install right after the user step (the
// container smoke test does).  Install must go through, and leave every
// option as the config has it.
func TestSetupWizardInstallWithoutOptionsKeepsDefaults(t *testing.T) {
	h, token := optionsWizard(t)
	res := wizardPost(h.AdminSetupInstall, nil, token, "127.0.0.1:9477")
	if res.StatusCode != http.StatusFound || !strings.Contains(res.Header.Get("Location"), "/admin/setup/done") {
		t.Fatalf("install without the options step: %d %s", res.StatusCode, res.Header.Get("Location"))
	}
	saved, err := settings.Load(h.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if saved.CommunityBans.ResolvedSubscribeMode() != settings.SubscribeFetchApply || !saved.CommunityBans.PublishLiveness || !saved.CommunityBans.PublishCountry {
		t.Errorf("community bans changed without the options step: %+v", saved.CommunityBans)
	}
	if !saved.IPGeo.AutoFetch || saved.Nginx.SyncDisabled || saved.VersionCheckDisabled {
		t.Errorf("a communication was turned off without the options step: ipgeo=%+v sync_disabled=%v version_check_disabled=%v", saved.IPGeo, saved.Nginx.SyncDisabled, saved.VersionCheckDisabled)
	}
	if len(saved.Nginx.AdminAllowedHosts) != 0 || saved.Challenge.Default.ObserveOnly != nil {
		t.Errorf("admin_allowed_hosts=%v observe_only=%v, want none", saved.Nginx.AdminAllowedHosts, saved.Challenge.Default.ObserveOnly)
	}
}

// Reached by address, the hostname field is left empty with the reason
// shown; an address typed in is refused, so is a hostname other than the
// one the wizard is reached on (the Network tab's lockout guard), and one
// with a character no hostname has.
func TestSetupWizardOptionsHostRules(t *testing.T) {
	h, token := optionsWizard(t)
	page := wizardPage(t, h, token, "203.0.113.5:9477", "")
	if !strings.Contains(page, `name="admin_host" value=""`) {
		t.Error("reached by address, the hostname field is not empty")
	}
	if !strings.Contains(page, i18n.Tf(i18n.LangEN, "setup.options.host_ip", "203.0.113.5")) {
		t.Error("reached by address, the page does not say why the field is empty")
	}
	page = wizardPage(t, h, token, "[2001:db8::7]:9477", "")
	if !strings.Contains(page, i18n.Tf(i18n.LangEN, "setup.options.host_ip", "2001:db8::7")) {
		t.Error("an IPv6 address is not recognised as one")
	}

	for _, c := range []struct{ host, typed, want string }{
		{"admin.example.test", "203.0.113.5", i18n.Tf(i18n.LangEN, "setup.err.admin_host_ip", "203.0.113.5")},
		{"admin.example.test", "other.example.test", i18n.Tf(i18n.LangEN, "err.admin_lockout_host", "admin.example.test")},
		{"admin.example.test", "bad host", i18n.Tf(i18n.LangEN, "err.admin_host_invalid", "bad host")},
	} {
		res := wizardPost(h.AdminSetupSaveOptions, url.Values{"comm_feed": {"1"}, "admin_host": {c.typed}}, token, c.host)
		loc, _ := url.Parse(res.Header.Get("Location"))
		if res.StatusCode != http.StatusFound || loc == nil || loc.Query().Get("err") != c.want {
			t.Errorf("host %q typed %q: %d %s, want err=%q", c.host, c.typed, res.StatusCode, res.Header.Get("Location"), c.want)
		}
		if loc != nil && loc.Query().Get("admin_host") != c.typed {
			t.Errorf("the typed hostname does not survive the error round-trip: %s", res.Header.Get("Location"))
		}
		if st := wizardStateForKey(token); st.OptionsSet {
			t.Fatalf("a refused hostname recorded the step as done (%q)", c.typed)
		}
	}
	// Reached through a port, the entry matches without it.
	res := wizardPost(h.AdminSetupSaveOptions, url.Values{"admin_host": {"admin.example.test"}}, token, "admin.example.test:8443")
	if res.StatusCode != http.StatusFound || strings.Contains(res.Header.Get("Location"), "err=") {
		t.Fatalf("the Host's port counts against the hostname: %s", res.Header.Get("Location"))
	}
	if st := wizardStateForKey(token); !st.OptionsSet || st.Options.Feed {
		t.Errorf("an empty form turns every communication off; state = %+v", st.Options)
	}
}

// Reconfigure (a superadmin re-running the wizard) has no options step: the
// wizard goes from the user step to the review, a ?step=options is ignored,
// and a POST to the step changes nothing.
func TestSetupWizardReconfigureHasNoOptionsStep(t *testing.T) {
	h, uid := reconfHandler(t, true)
	h.updateSettingsInMemory(func(s *settings.Settings) { s.Server.BasePath = "/unmask" })
	key := "sess:" + strconv.FormatInt(uid, 10)
	st := wizardStateForKey(key)
	st.DBSet, st.DB = true, h.cfg().DB
	st.UserSkipped = true
	t.Cleanup(func() { dropWizardState(key) })

	get := func(query string) string {
		r := httptest.NewRequest(http.MethodGet, "/unmask/admin/setup/"+query, nil)
		r.AddCookie(superadminCookie(uid))
		r.AddCookie(&http.Cookie{Name: i18n.CookieName, Value: "en"})
		w := httptest.NewRecorder()
		h.AdminSetupIndex(w, r)
		b, _ := io.ReadAll(w.Result().Body)
		return string(b)
	}
	if page := get(""); !strings.Contains(page, i18n.T(i18n.LangEN, "setup.review.h")) || strings.Contains(page, i18n.T(i18n.LangEN, "setup.options.h")) {
		t.Errorf("reconfigure after the user step is not on the review, or shows the options step")
	}
	if page := get("?step=options"); strings.Contains(page, i18n.T(i18n.LangEN, "setup.options.h")) {
		t.Error("?step=options opened the options step on a reconfigure")
	}
	if page := get(""); strings.Contains(page, `4. `+i18n.T(i18n.LangEN, "setup.step.options")) {
		t.Error("the step bar lists an options step on a reconfigure")
	}
	r := httptest.NewRequest(http.MethodPost, "/unmask/admin/setup/options", strings.NewReader("observe_only=1"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(superadminCookie(uid))
	w := httptest.NewRecorder()
	h.AdminSetupSaveOptions(w, r)
	if w.Code != http.StatusFound || wizardStateForKey(key).OptionsSet {
		t.Errorf("a reconfigure POST to the options step: %d, OptionsSet=%v", w.Code, wizardStateForKey(key).OptionsSet)
	}
}

// The step reads the switches as the config has them, and turns a switch
// back on only when the config has it fully off.
func TestWizardOptionsRoundTrip(t *testing.T) {
	var s settings.Settings
	s.CommunityBans.SubscribeMode = settings.SubscribeFetch
	s.IPGeo.AutoUpdateASN = true
	o := wizardOptionsFromSettings(s)
	if !o.Feed || !o.GeoIP || o.Liveness || o.Country || !o.Sync || !o.VersionCheck || o.ObserveOnly {
		t.Errorf("read back: %+v", o)
	}
	applyWizardOptions(&s, o)
	if s.CommunityBans.SubscribeMode != settings.SubscribeFetch {
		t.Errorf("a feed left on changed the subscribe mode to %q", s.CommunityBans.SubscribeMode)
	}
	if s.IPGeo.AutoFetch || s.IPGeo.AutoUpdate || !s.IPGeo.AutoUpdateASN {
		t.Errorf("GeoIP left on changed the switches: %+v", s.IPGeo)
	}
	o.Feed, o.GeoIP = false, false
	applyWizardOptions(&s, o)
	if s.CommunityBans.SubscribeMode != settings.SubscribeOff || s.IPGeo.AutoUpdateASN {
		t.Errorf("turning off: subscribe_mode=%q ipgeo=%+v", s.CommunityBans.SubscribeMode, s.IPGeo)
	}
	o.Feed, o.GeoIP = true, true
	applyWizardOptions(&s, o)
	if s.CommunityBans.SubscribeMode != settings.SubscribeFetchApply || !s.IPGeo.AutoFetch || !s.IPGeo.AutoUpdate || !s.IPGeo.AutoUpdateASN {
		t.Errorf("turning back on from fully off: subscribe_mode=%q ipgeo=%+v", s.CommunityBans.SubscribeMode, s.IPGeo)
	}
}
