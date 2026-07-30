package handlers

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/nginxconf"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The policy checkbox has to survive a save round trip, and the per-pattern
// rows it outranks must still be written -- turning the policy off is what
// brings them back, so losing them here would make the switch one-way.
func TestRequireRangeVerificationSaveRoundTrip(t *testing.T) {
	// adminScalarSiteSave / AdminSettingsSave persist through settings.Save,
	// so the handler needs a real config file to write to.
	var base settings.Settings
	base.Server.BasePath = "/unmask"
	h := newTestHandler(t)
	cfgPath := filepath.Join(t.TempDir(), "config.yml")
	if err := settings.Save(base, cfgPath); err != nil {
		t.Fatal(err)
	}
	h.ConfigPath = cfgPath
	h.SetSettings(base)

	page := func() string {
		req := httptest.NewRequest(http.MethodGet, "/unmask/admin/settings/?tab=ua-filter", nil)
		rr := httptest.NewRecorder()
		h.AdminSettingsIndex(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("ua-filter tab: %d", rr.Code)
		}
		return rr.Body.String()
	}
	if !strings.Contains(page(), `name="require_range_verification"`) {
		t.Fatal("the ua-filter tab does not offer the policy checkbox")
	}
	// Off by default: this changes who gets rescued, so it is opt-in.
	// Unset means ON: the safe direction, and the one the per-pattern default
	// already resolved to, so an install that never saw this setting keeps
	// behaving as before.
	if load0, _ := settings.Load(cfgPath); !load0.Nginx.SearchBots.RangeVerificationRequired() {
		t.Error("an unset policy must read as on")
	}

	save := func(form string) {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost,
			"/unmask/admin/settings/save?section=ua-filter", strings.NewReader(form))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		h.AdminSettingsSave(rr, req)
		if rr.Code != http.StatusSeeOther && rr.Code != http.StatusFound {
			t.Fatalf("save: want redirect, got %d: %s", rr.Code, rr.Body.String())
		}
	}

	// AdminSettingsSave persists to disk (fresh-read -> modify -> atomic
	// save), so assert against the file rather than the in-memory snapshot.
	load := func() settings.Nginx {
		t.Helper()
		got, err := settings.Load(cfgPath)
		if err != nil {
			t.Fatal(err)
		}
		return got.Nginx
	}

	save(`require_range_verification=1&upstream_ua_enabled=Googlebot%5C%2F`)
	sb := load().SearchBots
	if !sb.RangeVerificationRequired() {
		t.Error("policy did not persist")
	}
	if len(sb.UpstreamUAEnabled) == 0 {
		t.Error("the per-pattern opt-in was dropped; switching the policy off would not restore it")
	}
	// The in-memory swap happens only after a successful nginx render, which
	// this environment has no config for -- the save itself completed (the
	// file above proves it), so publish what was written and check the form
	// comes back reflecting it.
	if reloaded, err := settings.Load(cfgPath); err == nil {
		h.SetSettings(reloaded)
	}
	if !strings.Contains(page(), `name="require_range_verification" value="1" checked`) {
		t.Error("the saved policy does not render as checked")
	}

	// Unchecking a checkbox submits nothing at all, so the absent field has
	// to read as false rather than leaving the stored value alone.
	save(`upstream_ua_enabled=Googlebot%5C%2F`)
	// Turning it off has to be recorded, not just left unset -- unset means on.
	if load().SearchBots.RangeVerificationRequired() {
		t.Error("unchecking the policy did not turn it off")
	}
}

// The point of the switch is that the two questions stop sharing one control.
// Out of the box a range-backed crawler is ON the rescue list (its checkbox is
// checked -- it is a crawler we intend to let through) while the policy says
// it is verified by address, so the effective path is IP-only.  Before this,
// the same state showed as an UNCHECKED box, which on every other row means
// "blocked" -- that collision is what made the list unreadable.
func TestRangeBackedRowReadsAsRescuedWhilePolicyVerifiesByIP(t *testing.T) {
	h := newTestHandler(t)
	// Google's range presets enabled, as a real install ships them -- without
	// the ranges wired in there is no IP path either, and the honest badge for
	// that is "no rescue".
	var s settings.Settings
	s.Server.BasePath = "/unmask"
	s.Nginx.BypassIPEnabledPresets = []string{"google-common", "google-special", "google-user-triggered"}
	h.SetSettings(s)

	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/settings/?tab=ua-filter", nil)
	rr := httptest.NewRecorder()
	h.AdminSettingsIndex(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("ua-filter: %d", rr.Code)
	}
	body := rr.Body.String()

	// The row for a range-backed pattern: checkbox checked, badge saying the
	// UA path is closed.
	// The attribute holds the pattern verbatim, backslash included.
	row := regexp.MustCompile(`(?s)<label class="upstream-row" data-pattern="Googlebot\\/"[^>]*>.*?</label>`).FindString(body)
	if row == "" {
		t.Fatal("no Googlebot row rendered")
	}
	if !strings.Contains(row, "checked") {
		t.Error("a range-backed crawler must show as ON the rescue list by default; " +
			"an unchecked box reads as \"blocked\", which is not what happens to it")
	}
	if !strings.Contains(row, "rv-ip") {
		t.Errorf("the badge must say the rescue rides the IP range, got: %.200s", row)
	}
	if !strings.Contains(row, `data-rv-forced="1"`) {
		t.Error("the row must be marked as settled by the policy rather than by its own checkbox")
	}

	// And the effective config agrees: the UA string does not rescue it.
	if !nginxconf.EffectiveUpstreamUAOff(h.cfg().Nginx)[`Googlebot\/`] {
		t.Error("default install: a spoofed Googlebot UA would be rescued by the string")
	}
}
