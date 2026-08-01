package handlers

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The default challenge mode is now the same compact select the zone rows and
// the other tabs already use, with the per-mode prose in a "?" popover -- by
// the time an operator reaches this control the four names are vocabulary,
// and the same list was being spelled out in full at every occurrence.
func TestRateLimitModeIsASelectWithTheProseInThePopover(t *testing.T) {
	h := newTestHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/settings/?tab=rate-limit", nil)
	rr := httptest.NewRecorder()
	h.AdminSettingsIndex(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("rate-limit tab: %d", rr.Code)
	}
	body := rr.Body.String()

	if strings.Contains(body, `type="radio" name="default_challenge_mode"`) {
		t.Error("the radio list is still rendered; the mode should be a select now")
	}
	sel := body[strings.Index(body, `name="default_challenge_mode"`):]
	if end := strings.Index(sel, "</select>"); end > 0 {
		sel = sel[:end]
	}
	// A snapshot with no stored value must preselect what the engine actually
	// runs -- ResolvedChallengeMode's pow_then_captcha.  The radio preselected
	// captcha_only here, which described a mode nothing was enforcing.
	for _, line := range strings.Split(sel, "\n") {
		if strings.Contains(line, "selected") && !strings.Contains(line, "pow_then_captcha") {
			t.Errorf("empty stored value preselects the wrong mode: %s", strings.TrimSpace(line))
		}
	}

	if !strings.Contains(body, `id="rl-mode-help"`) {
		t.Error("the mode popover template is missing")
	}
	if !strings.Contains(body, `id="rl-deny-warn"`) {
		t.Error("the deny warning element is missing")
	}
	// The warning renders resolved (not as a raw key), and only the deny
	// selection reveals it -- the element ships hidden.
	if strings.Contains(body, "settings.rate_limit.mode_deny_protected_warn") {
		t.Error("raw i18n key leaked into the render")
	}
	warn := body[strings.Index(body, `id="rl-deny-warn"`):]
	if end := strings.Index(warn, "</div>"); end > 0 {
		warn = warn[:end]
	}
	if !strings.Contains(warn, "display:none") {
		t.Error("the deny warning should start hidden; it appears when deny is selected")
	}
	if !strings.Contains(warn, "1.17.6") {
		t.Error("the deny warning lost its nginx-version constraint")
	}
}

// Zone rows render view-first with per-row edit / reorder controls, and the
// deny-overlap warning machinery is wired: the enforced protected prefixes
// reach the page as data, each row carries its (hidden) warning, and the
// reference prose lives in the zones-heading popover rather than as an
// always-on paragraph under the default-mode control.
func TestZoneRowsRenderViewFirstWithReorderAndWarning(t *testing.T) {
	var base settings.Settings
	base.Server.BasePath = "/unmask"
	base.Nginx.ProtectedPaths.EnabledPresets = []string{"unmask"}
	base.RateLimit.Zones = []settings.RateZone{
		{Name: "api_strict", PathPatterns: []string{"/api/"}, RequestsPerMin: 30, ChallengeMode: "deny"},
	}
	h := newTestHandler(t)
	h.SetSettings(base)
	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/settings/?tab=rate-limit", nil)
	rr := httptest.NewRecorder()
	h.AdminSettingsIndex(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("rate-limit tab: %d", rr.Code)
	}
	body := rr.Body.String()

	row := body[strings.Index(body, `class="zone-row"`):]
	if end := strings.Index(row, "</tr>"); end > 0 {
		row = row[:end]
	}
	if strings.Contains(row, "editing") {
		t.Error("a stored zone row should render in view state, not editing")
	}
	for _, want := range []string{"z-view", "z-in", "z-edit", "z-up", "z-down", "z-del", "z-ok", "z-on"} {
		if !strings.Contains(row, want) {
			t.Errorf("zone row is missing %q", want)
		}
	}
	// The warning is a full-width row of its own (it used to live inside the
	// narrow paths cell), paired right after the zone row.
	after := body[strings.Index(body, `class="zone-row"`):]
	if i := strings.Index(after, "</tr>"); i > 0 {
		after = after[i:]
	}
	if !strings.Contains(after[:400], `class="zone-warn-row"`) || !strings.Contains(after[:400], `colspan="9"`) {
		t.Error("the zone's warning row (full-width, colspan=9) is not paired after the zone row")
	}
	// The warning machinery's data: the unmask preset's literal prefix.
	if !strings.Contains(body, `"/unmask/admin/"`) {
		t.Error("the enforced protected prefixes did not reach the page")
	}
	if !strings.Contains(body, `id="rl-zones-help"`) {
		t.Error("the zones-heading popover is missing")
	}
	if !strings.Contains(body, `id="rl-zone-row-tpl"`) {
		t.Error("the add-row template is missing")
	}
	// The four-mode prose block stopped being an always-on paragraph -- the
	// constraint text renders inside popover templates and the per-row /
	// default warnings only.
	if got := strings.Count(body, "1.17.6"); got < 2 {
		t.Errorf("the constraint text should reach both the popover and the warnings, found %d occurrences", got)
	}
}

// Save still round-trips every concrete mode -- deny included, whose existence
// the validator's error message used to deny -- and an absent field leaves the
// stored value alone.
func TestRateLimitModeSaveRoundTrip(t *testing.T) {
	var base settings.Settings
	base.Server.BasePath = "/unmask"
	base.RateLimit.Default.ChallengeMode = "captcha_only"
	h := newTestHandler(t)
	cfgPath := filepath.Join(t.TempDir(), "config.yml")
	if err := settings.Save(base, cfgPath); err != nil {
		t.Fatal(err)
	}
	h.ConfigPath = cfgPath
	h.SetSettings(base)

	save := func(form string) {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost,
			"/unmask/admin/settings/save?section=rate_limit", strings.NewReader(form))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		h.AdminSettingsSave(rr, req)
		if rr.Code != http.StatusSeeOther && rr.Code != http.StatusFound {
			t.Fatalf("save: want redirect, got %d: %s", rr.Code, rr.Body.String())
		}
	}
	load := func() string {
		t.Helper()
		got, err := settings.Load(cfgPath)
		if err != nil {
			t.Fatal(err)
		}
		return got.RateLimit.Default.ChallengeMode
	}

	save("default_challenge_mode=deny")
	if got := load(); got != "deny" {
		t.Errorf("deny did not round-trip, stored %q", got)
	}
	// A zone's on/off checkbox: absent means off, and switching off must keep
	// everything else about the row (that is the point of the toggle).
	zoneForm := "default_challenge_mode=deny&zone_0_name=z&zone_0_paths=%2Fapi%2F&zone_0_rpm=5&zone_0_burst=3&zone_0_window=60&zone_0_chmode=deny"
	save(zoneForm + "&zone_0_on=1")
	zs, err := settings.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(zs.RateLimit.Zones) != 1 || zs.RateLimit.Zones[0].Disabled {
		t.Fatalf("a ticked row should store as enabled, got %+v", zs.RateLimit.Zones)
	}
	save(zoneForm) // checkbox absent = switched off
	zs, _ = settings.Load(cfgPath)
	if len(zs.RateLimit.Zones) != 1 || !zs.RateLimit.Zones[0].Disabled {
		t.Fatalf("an unticked row should store as disabled, got %+v", zs.RateLimit.Zones)
	}
	if z := zs.RateLimit.Zones[0]; z.RequestsPerMin != 5 || z.Burst != 3 || z.ChallengeMode != "deny" {
		t.Errorf("switching a zone off changed its settings: %+v", z)
	}
	save("default_challenge_mode=pow_then_captcha")
	if got := load(); got != "pow_then_captcha" {
		t.Errorf("pow_then_captcha did not round-trip, stored %q", got)
	}
	// Field absent (a POST from elsewhere): the stored choice stays.
	save("default_rpm=100")
	if got := load(); got != "pow_then_captcha" {
		t.Errorf("a save without the field changed the mode to %q", got)
	}
}
