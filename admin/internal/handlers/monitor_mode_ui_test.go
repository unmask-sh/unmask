package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

func modeHandler(t *testing.T, s settings.Settings) *Handler {
	t.Helper()
	h := newTestHandler(t)
	cfgPath := filepath.Join(t.TempDir(), "config.yml")
	s.Server.BasePath = "/unmask"
	if err := settings.Save(s, cfgPath); err != nil {
		t.Fatal(err)
	}
	h.ConfigPath = cfgPath
	h.SetSettings(s)
	return h
}

// TestMonitorModeHasAControl: monitor mode is what an operator reaches for when
// putting unmask in front of a live site, and it had no control anywhere -- the
// only way in or out was editing config.yml and restarting.  The operating-mode
// tab meanwhile offered passthrough, which looks like the same thing and is
// not: it hands out a pass cookie, so returning visitors stop being judged and
// the very measurement the operator turned it on to collect decays away.
func TestMonitorModeHasAControl(t *testing.T) {
	var s settings.Settings
	s.Challenge.Default.ObserveOnly = settings.BoolPtr(true)
	h := modeHandler(t, s)

	body := renderSettings(t, h, "?tab=global")
	m := regexp.MustCompile(`<input[^>]*name="global_observe_only"[^>]*>`).FindString(body)
	if m == "" {
		t.Fatal("the operating-mode tab offers no monitor-mode control")
	}
	if !strings.Contains(m, "checked") {
		t.Error("monitor mode is on but the box renders unchecked")
	}
	// It must sit above passthrough: that is the one an operator introducing
	// unmask should meet first, and picking the other silently costs them the
	// measurement.
	if strings.Index(body, `name="global_observe_only"`) > strings.Index(body, `name="global_passthrough"`) {
		t.Error("passthrough is presented before monitor mode")
	}
	// The difference between the two has to be stated where the choice is made.
	if !strings.Contains(body, "cookie") {
		t.Error("the help does not explain why passthrough is not a substitute")
	}
}

// TestMonitorModeSaves: the control has to actually persist, or it is worse
// than no control at all.
func TestMonitorModeSaves(t *testing.T) {
	h := modeHandler(t, settings.Settings{})
	if h.cfg().Challenge.Default.IsObserveOnly() {
		t.Fatal("precondition: monitor mode should start off")
	}

	post := func(on bool) {
		t.Helper()
		form := url.Values{"section": {"global"}}
		if on {
			form.Set("global_observe_only", "1")
		}
		r := httptest.NewRequest(http.MethodPost, "/unmask/admin/settings/save?section=global",
			strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		h.AdminSettingsSave(httptest.NewRecorder(), r)
	}

	saved := func() bool {
		t.Helper()
		s, err := settings.Load(h.ConfigPath)
		if err != nil {
			t.Fatalf("re-read config: %v", err)
		}
		return s.Challenge.Default.IsObserveOnly()
	}

	post(true)
	if !saved() {
		t.Error("turning monitor mode on did not persist")
	}
	post(false)
	if saved() {
		t.Error("turning monitor mode off did not persist")
	}
}

// TestHeroPointsAtSomethingThatExists: the landing card tells the operator how
// to go live.  It named a setting on a tab that has never had one, so the
// instruction sent them looking for a control that did not exist.
func TestHeroPointsAtSomethingThatExists(t *testing.T) {
	h := observeHandler(t, true, 1)
	body := renderOverview(t, h)

	if strings.Contains(body, "observe_only") {
		t.Error("the card still names the raw config key instead of the control")
	}
	if !strings.Contains(body, "動作モード") {
		t.Error("the card does not name the tab that holds the control")
	}
}
