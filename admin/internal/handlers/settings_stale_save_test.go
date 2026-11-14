package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// staleSaveFixture: a handler on a config file of its own, with the
// retention tab's page and save -- a form of four numbers, which two tabs
// can each change.
type staleSaveFixture struct {
	t       *testing.T
	h       *Handler
	cfgPath string
}

func newStaleSaveFixture(t *testing.T) *staleSaveFixture {
	t.Helper()
	h := newTestHandler(t)
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yml")
	seed := filepath.Join(dir, "seed.yml")
	if err := os.WriteFile(seed, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := settings.Load(seed)
	if err != nil {
		t.Fatal(err)
	}
	s.Server.BasePath = "/unmask"
	s.Nginx.OutputDir = dir
	s.EventsRetentionDays = 7
	if err := settings.Save(s, cfgPath); err != nil {
		t.Fatal(err)
	}
	h.ConfigPath = cfgPath
	loaded, err := settings.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	h.SetSettings(loaded)
	return &staleSaveFixture{t: t, h: h, cfgPath: cfgPath}
}

var baseFieldRE = regexp.MustCompile(`name="_base" value="([0-9a-f]{16})"`)

// open renders the retention tab, as a browser tab opening it, and returns
// the version its form carries.
func (f *staleSaveFixture) open() string {
	f.t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/settings/retention/", nil)
	req.SetPathValue("tab", "retention")
	rr := httptest.NewRecorder()
	f.h.AdminSettingsIndex(rr, req)
	m := baseFieldRE.FindStringSubmatch(rr.Body.String())
	if m == nil {
		f.t.Fatalf("the retention form carries no _base (status %d)", rr.Code)
	}
	return m[1]
}

func (f *staleSaveFixture) stored() settings.Settings {
	f.t.Helper()
	s, err := settings.Load(f.cfgPath)
	if err != nil {
		f.t.Fatal(err)
	}
	return s
}

// save posts the retention form as a tab shows it -- every field, with the
// values given -- and reports whether the save went through.
func (f *staleSaveFixture) save(base string, events, audit int) bool {
	f.t.Helper()
	form := url.Values{
		"events_retention_days":      {strconv.Itoa(events)},
		"audit_log_retention_days":   {strconv.Itoa(audit)},
		"notice_retention_days":      {"0"},
		"ask_history_retention_days": {"0"},
	}
	if f.stored().NginxLog.Enabled {
		form.Set("nginx_log_enabled", "1")
	}
	if base != "" {
		form.Set("_base", base)
	}
	req := httptest.NewRequest(http.MethodPost, "/unmask/admin/settings/save?section=retention", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	f.h.AdminSettingsSave(rr, req)
	if rr.Code != http.StatusFound {
		f.t.Fatalf("save: status %d", rr.Code)
	}
	return strings.Contains(rr.Header().Get("Location"), "saved=1")
}

// A freshly opened page carries the version a save then finds: the merge is
// for a page left open across another save, not for every save.
func TestFreshPageVersionIsTheSavedOne(t *testing.T) {
	f := newStaleSaveFixture(t)
	v := f.open()
	text, err := settings.SavedYAML(f.stored())
	if err != nil {
		t.Fatal(err)
	}
	if got := settings.Version(text); got != v {
		t.Errorf("the page carries %s, the file loads as %s", v, got)
	}
}

// Two tabs open the retention page.  The second saves a new event retention;
// the first, still showing the old one, saves a new audit retention.  Both
// stay -- the first tab's save used to put the event retention back.
func TestStaleTabSaveKeepsTheOtherChange(t *testing.T) {
	f := newStaleSaveFixture(t)
	tab1, tab2 := f.open(), f.open()
	if !f.save(tab2, 30, 0) {
		t.Fatal("the second tab's save was refused")
	}
	if !f.save(tab1, 7, 90) {
		t.Fatal("the first tab's save was refused; it changed another setting")
	}
	got := f.stored()
	if got.EventsRetentionDays != 30 {
		t.Errorf("event retention %d: the stale tab put back what it showed (want the second tab's 30)", got.EventsRetentionDays)
	}
	if got.AuditLogRetentionDays != 90 {
		t.Errorf("audit retention %d, want the first tab's 90", got.AuditLogRetentionDays)
	}
	if live := f.h.snapshotSettings(); live.EventsRetentionDays != 30 || live.AuditLogRetentionDays != 90 {
		t.Errorf("the running settings: events %d audit %d, want 30 and 90", live.EventsRetentionDays, live.AuditLogRetentionDays)
	}
}

// Both tabs change the same setting to different values: the later save is
// refused, and what the earlier one saved stays.
func TestStaleTabSaveOfTheSameSettingIsRefused(t *testing.T) {
	f := newStaleSaveFixture(t)
	tab1, tab2 := f.open(), f.open()
	if !f.save(tab2, 30, 0) {
		t.Fatal("the second tab's save was refused")
	}
	if f.save(tab1, 14, 0) {
		t.Fatal("two tabs changing the event retention differently: the stale save went through")
	}
	if got := f.stored().EventsRetentionDays; got != 30 {
		t.Errorf("event retention %d after the refused save, want 30", got)
	}
}

// A page whose version the daemon no longer holds (a restart since) cannot
// be merged: refused rather than applied over what changed.  A form with no
// version at all (a page from an older build, a script) is applied as it
// always was.
func TestUnknownVersionRefusedNoVersionApplied(t *testing.T) {
	f := newStaleSaveFixture(t)
	if f.save("0123456789abcdef", 14, 0) {
		t.Fatal("a save from a version the daemon does not hold went through")
	}
	if got := f.stored().EventsRetentionDays; got != 7 {
		t.Errorf("event retention %d after the refused save, want 7", got)
	}
	if !f.save("", 14, 0) {
		t.Fatal("a form without a version was refused")
	}
	if got := f.stored().EventsRetentionDays; got != 14 {
		t.Errorf("event retention %d, want the form's 14", got)
	}
}
