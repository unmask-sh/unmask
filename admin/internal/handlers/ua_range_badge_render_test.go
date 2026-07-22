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
	rr := httptest.NewRecorder()
	h.AdminSettingsIndex(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
	body := rr.Body.String()

	// Auto default: Googlebot is UA-off with every preset live -> unchecked
	// checkbox + the green ip badge; bingbot's explicit opt-in -> the amber
	// or badge.  A raw i18n key leaking into the page means the printf key
	// composition broke.
	for _, want := range []string{
		`class="upstream-rv rv-ip"`,
		`class="upstream-rv rv-or"`,
		`data-rv="1"`,
		`data-rv-active="1"`,
		`</html>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("ua-filter tab render missing %q", want)
		}
	}
	if strings.Contains(body, "settings.ua.upstream.rv_badge.") {
		t.Error("raw rv_badge i18n key leaked into the render (printf key missing from dict)")
	}
	// The Googlebot row must render unchecked (UA-off), i.e. its checkbox tag
	// carries no "checked".
	row := body[strings.Index(body, `value="Googlebot\/"`):]
	row = row[:strings.Index(row, ">")+1]
	if strings.Contains(row, "checked") {
		t.Errorf("Googlebot checkbox must render unchecked under the auto default, got %q", row)
	}
}
