package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/nginxconf"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestSettingsUAFilterTabRendersRangeBadges executes the UA-filter tab and
// pins the rescue-path badge wiring: the printf-composed i18n keys resolve
// (a missing rv_badge.<state> key would only fail at execute time), the
// effective checkbox state reflects EffectiveUpstreamUAOff (not the raw
// disabled list), and an explicit UA opt-in renders the amber OR badge.
func TestSettingsUAFilterTabRendersRangeBadges(t *testing.T) {
	h := newTestHandler(t)
	h.updateSettingsInMemory(func(s *settings.Settings) {
		ids := make([]string, 0, len(nginxconf.BypassIPGroups))
		for i := range nginxconf.BypassIPGroups {
			ids = append(ids, nginxconf.BypassIPGroups[i].ID)
		}
		s.Nginx.BypassIPEnabledPresets = ids
		s.Nginx.SeenVersion = "v0.1.7"
		s.Nginx.SearchBots.UpstreamUAEnabled = []string{`bingbot`}
	})
	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/settings/?tab=ua-filter", nil)
	req.SetPathValue("tab", "ua-filter")
	rr := httptest.NewRecorder()
	h.AdminSettingsIndex(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
	body := rr.Body.String()

	// With the standing policy on (the default), every range-backed pattern
	// resolves to the same thing: on the rescue list, verified by address.
	// So the row shows a CHECKED box -- it is a crawler we intend to let
	// through -- next to the green badge saying the address is what gets
	// checked.  It used to render unchecked, which on every other row means
	// "blocked".
	for _, want := range []string{
		`class="upstream-rv rv-on"`,
		`data-rv="1"`,
		`data-rv-active="1"`,
		`data-rv-forced="1"`,
		`</html>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("ua-filter tab render missing %q", want)
		}
	}
	if strings.Contains(body, "settings.ua.upstream.rv_badge.") {
		t.Error("raw rv_badge i18n key leaked into the render (printf key missing from dict)")
	}
	row := body[strings.Index(body, `value="Googlebot\/"`):]
	row = row[:strings.Index(row, ">")+1]
	if !strings.Contains(row, "checked") {
		t.Errorf("Googlebot must render as ON the rescue list (the policy decides the path, not this box), got %q", row)
	}
}

// The badge means one thing -- "this bot's range preset is enabled" -- and the
// legend states it as an absolute.  A row the operator opted into UA rescue
// still shows green, because its preset is still enabled; what changes is the
// checkbox next to it.  Rendering it grey there is what made the old legend
// impossible to write without contradicting itself.
func TestBadgeStaysGreenForARowThatAlsoPassesOnItsUA(t *testing.T) {
	h := newTestHandler(t)
	h.updateSettingsInMemory(func(s *settings.Settings) {
		ids := make([]string, 0, len(nginxconf.BypassIPGroups))
		for i := range nginxconf.BypassIPGroups {
			ids = append(ids, nginxconf.BypassIPGroups[i].ID)
		}
		s.Nginx.BypassIPEnabledPresets = ids
		s.Nginx.SeenVersion = "v99.0.0"
		// Policy off + an explicit UA opt-in: this row passes on either path.
		s.Nginx.SearchBots.RequireRangeVerification = settings.BoolPtr(false)
		s.Nginx.SearchBots.UpstreamUAEnabled = []string{`bingbot`}
	})
	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/settings/?tab=ua-filter", nil)
	req.SetPathValue("tab", "ua-filter")
	rr := httptest.NewRecorder()
	h.AdminSettingsIndex(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
	body := rr.Body.String()

	i := strings.Index(body, `data-pattern="bingbot"`)
	if i < 0 {
		t.Fatal("bingbot row not rendered")
	}
	row := body[i:]
	if end := strings.Index(row, "</label>"); end > 0 {
		row = row[:end]
	}
	if !strings.Contains(row, "upstream-rv rv-on") {
		t.Errorf("bingbot's preset is enabled, so its badge must be green regardless of the UA opt-in: %q", row)
	}
	// And the badge carries no per-row explanation any more: the legend covers
	// both colours, so a title here would only restate it.
	if strings.Contains(row, `class="upstream-rv rv-on" title=`) {
		t.Error("the badge should not carry a tooltip; the legend explains both colours")
	}
	// cursor:help promises a tooltip that no longer exists -- the pointer
	// changes, the operator waits, nothing appears.
	if strings.Contains(body, ".upstream-rv{cursor:help}") {
		t.Error("the badge still styles itself as hoverable, but it has no title to show")
	}
}
