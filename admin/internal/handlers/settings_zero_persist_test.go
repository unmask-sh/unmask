package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/nginxconf"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// A save from the settings page publishes the saved copy as the live settings
// and writes config.yml.  What a restart reads is the file -- and so does the
// next save of any tab, and every write-back of the daemon's own state, which
// load the file first.  These tests save what the page itself offers and hold
// the live settings against the file.
//
// Until 0.1.59 four settings could not be saved as off / empty: their default
// is on, and Save left a zero out of the file (omitempty).  The page showed
// the box unticked; the file said nothing, which reads as the default.
// settings.TestZeroValuesAreKept guards the same rule field by field.

func zeroPersistSeed(t *testing.T) (*Handler, string) {
	t.Helper()
	h := newTestHandler(t)
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yml")
	emptyPath := filepath.Join(dir, "empty-seed.yml")
	if err := os.WriteFile(emptyPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := settings.Load(emptyPath)
	if err != nil {
		t.Fatal(err)
	}
	s.Server.Bind, s.Server.Port, s.Server.BasePath = "127.0.0.1", 9477, "/unmask"
	h.Version = "9.9.9"
	s.Nginx.SeenVersion = "v9.9.9"
	s.Nginx.OutputDir = dir
	s.CommunityBans.MapDir = dir
	if err := settings.Save(s, cfgPath); err != nil {
		t.Fatal(err)
	}
	h.ConfigPath = cfgPath
	loaded, err := settings.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	h.SetSettings(loaded)
	return h, cfgPath
}

// zeroPersistForm returns the fields of one section's form as the page
// renders it now.
func zeroPersistForm(t *testing.T, h *Handler, tab, section string) url.Values {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/settings/"+tab+"/", nil)
	req.SetPathValue("tab", tab)
	rr := httptest.NewRecorder()
	h.AdminSettingsIndex(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET tab=%s: %d", tab, rr.Code)
	}
	for _, f := range parseForms(rr.Body.String()) {
		if sectionOf(f.action) == section {
			return f.values()
		}
	}
	t.Fatalf("no form for section %s on tab %s", section, tab)
	return nil
}

func zeroPersistPost(t *testing.T, h *Handler, section string, v url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/unmask/admin/settings/save?section="+url.QueryEscape(section), strings.NewReader(v.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.AdminSettingsSave(rr, req)
	return rr
}

func zeroPersistSave(t *testing.T, h *Handler, section string, v url.Values) {
	t.Helper()
	rr := zeroPersistPost(t, h, section, v)
	if rr.Code != http.StatusFound || !strings.Contains(rr.Header().Get("Location"), "saved=1") {
		t.Fatalf("save %s: code=%d loc=%q body=%s", section, rr.Code, rr.Header().Get("Location"), rr.Body.String())
	}
}

func TestASettingSavedOffIsOffInTheFile(t *testing.T) {
	t.Run("header integrity off", func(t *testing.T) {
		h, cfgPath := zeroPersistSeed(t)
		v := zeroPersistForm(t, h, "ua-filter", "ua-filter")
		if v.Get("header_integrity") != "1" {
			t.Fatalf("the box is not ticked on a fresh install: %q", v.Get("header_integrity"))
		}
		v.Del("header_integrity") // the operator unticks the box
		zeroPersistSave(t, h, "ua-filter", v)
		if h.cfg().Global.HeaderIntegrity {
			t.Fatal("the save did not turn header_integrity off")
		}
		disk, err := settings.Load(cfgPath)
		if err != nil {
			t.Fatal(err)
		}
		if disk.Global.HeaderIntegrity {
			t.Error("header_integrity is off in the live settings and on in the file a restart reads")
		}
	})

	t.Run("honeypot: every preset on", func(t *testing.T) {
		h, cfgPath := zeroPersistSeed(t)
		v := zeroPersistForm(t, h, "honeypot", "honeypot")
		v.Del("honeypot_preset_enabled")
		for _, g := range nginxconf.HoneypotPresetGroups {
			v.Add("honeypot_preset_enabled", g.ID) // the operator ticks every preset
		}
		zeroPersistSave(t, h, "honeypot", v)
		if n := len(h.cfg().Nginx.Honeypot.DisabledPresets); n != 0 {
			t.Fatalf("the save left %d preset(s) disabled in the live settings", n)
		}
		disk, err := settings.Load(cfgPath)
		if err != nil {
			t.Fatal(err)
		}
		if got := disk.Nginx.Honeypot.DisabledPresets; len(got) != 0 {
			t.Errorf("every honeypot preset is on in the live settings; the file a restart reads disables %v", got)
		}
	})

	t.Run("protected paths: the unmask preset off", func(t *testing.T) {
		h, cfgPath := zeroPersistSeed(t)
		v := zeroPersistForm(t, h, "protected", "protected")
		if len(v["protected_preset_enabled"]) == 0 {
			t.Fatal("no protected preset is on on a fresh install; the test has nothing to untick")
		}
		v.Del("protected_preset_enabled") // the operator unticks the one preset that is on
		zeroPersistSave(t, h, "protected", v)
		if got := h.cfg().Nginx.ProtectedPaths.EnabledPresets; len(got) != 0 {
			t.Fatalf("the save left %v enabled in the live settings", got)
		}
		disk, err := settings.Load(cfgPath)
		if err != nil {
			t.Fatal(err)
		}
		if got := disk.Nginx.ProtectedPaths.EnabledPresets; len(got) != 0 {
			t.Errorf("no protected preset is on in the live settings; the file a restart reads enables %v", got)
		}
	})

	t.Run("crawler address ranges: every preset off", func(t *testing.T) {
		h, cfgPath := zeroPersistSeed(t)
		v := zeroPersistForm(t, h, "bypass-ips", "bypass-ips")
		if len(v["bypass_preset_enabled"]) == 0 {
			t.Fatal("no range preset is on on a fresh install; the test has nothing to untick")
		}
		v.Del("bypass_preset_enabled") // the operator unticks every range preset
		zeroPersistSave(t, h, "bypass-ips", v)
		live := h.cfg().Nginx.BypassIPEnabledPresets
		disk, err := settings.Load(cfgPath)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(append([]string{}, live...), append([]string{}, disk.Nginx.BypassIPEnabledPresets...)) {
			t.Errorf("range presets: the live settings enable %v, the file a restart reads enables %v", live, disk.Nginx.BypassIPEnabledPresets)
		}
		if len(live) != 0 {
			t.Errorf("the save left %v enabled in the live settings", live)
		}
	})
}

// Not only at a restart: every save loads the file first (settings.Mutate),
// so the next save of any other tab published the default again as the live
// settings and rendered nginx's configuration from it.
func TestASettingSavedOffStaysOffAtTheNextSave(t *testing.T) {
	h, _ := zeroPersistSeed(t)
	v := zeroPersistForm(t, h, "ua-filter", "ua-filter")
	v.Del("header_integrity")
	zeroPersistSave(t, h, "ua-filter", v)
	hp := zeroPersistForm(t, h, "honeypot", "honeypot")
	hp.Del("honeypot_preset_enabled")
	for _, g := range nginxconf.HoneypotPresetGroups {
		hp.Add("honeypot_preset_enabled", g.ID)
	}
	zeroPersistSave(t, h, "honeypot", hp)
	if h.cfg().Global.HeaderIntegrity {
		t.Error("the save of the honeypot tab turned header_integrity back on")
	}
	// An unrelated tab, saved as shown.
	zeroPersistSave(t, h, "about", zeroPersistForm(t, h, "about", "about"))
	if h.cfg().Global.HeaderIntegrity {
		t.Error("header_integrity is back on in the live settings after a save of another tab")
	}
	if got := h.cfg().Nginx.Honeypot.DisabledPresets; len(got) != 0 {
		t.Errorf("honeypot presets %v are disabled again in the live settings after a save of another tab", got)
	}
}

// With no operator at all: the Community Bans pull (hourly; the subscription
// is on by default) writes its own state back through UpdateSettings, which
// loads the file, changes two fields, saves and publishes.
func TestASettingSavedOffStaysOffAtAStateWriteBack(t *testing.T) {
	h, _ := zeroPersistSeed(t)
	v := zeroPersistForm(t, h, "ua-filter", "ua-filter")
	v.Del("header_integrity")
	zeroPersistSave(t, h, "ua-filter", v)
	if h.cfg().Global.HeaderIntegrity {
		t.Fatal("the save did not turn header_integrity off")
	}
	// What communitybans.Client.Pull does at its end.
	if err := h.UpdateSettings(func(s *settings.Settings) {
		s.CommunityBans.LastPulledAt = 1795000000
		s.CommunityBans.Entries = 42
	}); err != nil {
		t.Fatal(err)
	}
	if h.cfg().Global.HeaderIntegrity {
		t.Error("header_integrity is back on in the live settings after the Community Bans pull wrote its state")
	}
}

// The honeypot ban duration: the page said "0 = forever" and took a 0, which
// was never forever (ResolvedBanDurationSec reads it as a day) and which the
// file cannot hold -- the field showed 0 until the next load, then 86400.
// A 0 is refused, and the setting stays as it was.
func TestHoneypotBanDurationRefusesZero(t *testing.T) {
	h, cfgPath := zeroPersistSeed(t)
	v := zeroPersistForm(t, h, "honeypot", "honeypot")
	before := h.cfg().Nginx.Honeypot.BanDurationSec
	if before <= 0 {
		t.Fatalf("a fresh install has no ban duration: %d", before)
	}
	v.Set("honeypot_default_ban_duration_sec", "0")
	rr := zeroPersistPost(t, h, "honeypot", v)
	if rr.Code == http.StatusFound && strings.Contains(rr.Header().Get("Location"), "saved=1") {
		t.Errorf("a ban duration of 0 was saved (Location %q)", rr.Header().Get("Location"))
	}
	if got := h.cfg().Nginx.Honeypot.BanDurationSec; got != before {
		t.Errorf("live ban duration: %d, want it left at %d", got, before)
	}
	disk, err := settings.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := disk.Nginx.Honeypot.BanDurationSec; got != before {
		t.Errorf("ban duration in the file: %d, want it left at %d", got, before)
	}

	v.Set("honeypot_default_ban_duration_sec", "3600")
	zeroPersistSave(t, h, "honeypot", v)
	if got := h.cfg().Nginx.Honeypot.BanDurationSec; got != 3600 {
		t.Errorf("live ban duration after saving 3600: %d", got)
	}
}

// The burst notification's minimum: the page took a 0, the notifier read a 0
// as "never notify", the page then showed 50, and the file -- which cannot
// hold the 0 -- put 50 back at the next load.  The page takes 1 or more; the
// switch is the checkbox beside the field.
func TestBurstMinimumTakesOneOrMore(t *testing.T) {
	h, cfgPath := zeroPersistSeed(t)
	v := zeroPersistForm(t, h, "notifications", "notifications")
	before := h.cfg().Notifications.BurstThresholdPer5m
	if before <= 0 {
		t.Fatalf("a fresh install has no burst minimum: %d", before)
	}
	v.Set("burst_threshold_per_5m", "0")
	zeroPersistSave(t, h, "notifications", v)
	if got := h.cfg().Notifications.BurstThresholdPer5m; got != before {
		t.Errorf("live burst minimum after posting 0: %d, want it left at %d", got, before)
	}
	v.Set("burst_threshold_per_5m", "7")
	zeroPersistSave(t, h, "notifications", v)
	if got := h.cfg().Notifications.BurstThresholdPer5m; got != 7 {
		t.Errorf("live burst minimum after posting 7: %d", got)
	}
	disk, err := settings.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := disk.Notifications.BurstThresholdPer5m; got != 7 {
		t.Errorf("burst minimum in the file: %d, want 7", got)
	}
}
