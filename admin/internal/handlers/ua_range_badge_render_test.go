package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/i18n"
	"github.com/unmask-sh/unmask/admin/internal/nginxconf"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestSettingsUAFilterTabRendersRangeBadges executes the UA-filter tab and
// pins the crawler card's wiring: the printf-composed i18n keys resolve (a
// missing key would only show at execute time), each row says how it is set
// -- following its group, or on its own -- and the range badge is green
// where the vendor's presets are live.
func TestSettingsUAFilterTabRendersRangeBadges(t *testing.T) {
	h := newTestHandler(t)
	h.updateSettingsInMemory(func(s *settings.Settings) {
		ids := make([]string, 0, len(nginxconf.BypassIPGroups))
		for i := range nginxconf.BypassIPGroups {
			ids = append(ids, nginxconf.BypassIPGroups[i].ID)
		}
		s.Nginx.BypassIPEnabledPresets = ids
		s.Nginx.SeenVersion = "v0.1.7"
		s.Nginx.SearchBots.UpstreamPatternMode = map[string]string{`bingbot`: "white", `MJ12bot`: "black"}
	})
	req := jaRequest(http.MethodGet, "/unmask/admin/settings/?tab=ua-filter", nil)
	req.SetPathValue("tab", "ua-filter")
	rr := httptest.NewRecorder()
	h.AdminSettingsIndex(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
	body := rr.Body.String()

	for _, want := range []string{
		`class="upstream-rv rv-on"`,
		`name="upstream_group_mode__seo" value="black"`,
		`</html>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("ua-filter tab render missing %q", want)
		}
	}
	if strings.Contains(body, "settings.ua.upstream.") {
		i := strings.Index(body, "settings.ua.upstream.")
		t.Errorf("raw i18n key leaked into the render (key missing from dict): %.80s", body[i:])
	}

	// With the standing policy on (the default), a range-backed crawler
	// following its passing group reads as passing -- the green badge says
	// the address is what gets checked.
	if row := upstreamRow(t, body, `Googlebot\/`); !strings.Contains(row, `data-own=""`) ||
		!strings.Contains(row, `<option value="" selected>`) {
		t.Errorf("Googlebot must render as following its group, got %q", row)
	}
	// One set on its own says so, in its own mode.
	if row := upstreamRow(t, body, `bingbot`); !strings.Contains(row, `data-own="white"`) ||
		!strings.Contains(row, `<option value="white" selected>`) {
		t.Errorf("bingbot is set to pass on its own, got %q", row)
	}
	// The seo group now holds a stopped crawler, so its chain picker shows
	// and the group counts the crawler set on its own.
	grp := body[strings.Index(body, `<div class="upstream-group" data-cat="seo"`):]
	grp = grp[:strings.Index(grp, `<button type="button" class="upstream-detail-btn"`)]
	if strings.Contains(grp, `class="upstream-action-wrap" hidden`) {
		t.Error("seo holds a crawler stopped on its own: the chain picker must show")
	}
	own := ">" + i18n.Tf(i18n.LangJA, "settings.ua.upstream.count_own", 1) + "<"
	if strings.Contains(grp, `" hidden> · <span class="upstream-own-n">`) || !strings.Contains(grp, own) {
		t.Errorf("seo must count its one crawler set on its own (%s), got %q", own, grp)
	}
}

// upstreamRow: the rendered Detail row for pat, up to its end.
func upstreamRow(t *testing.T, body, pat string) string {
	t.Helper()
	i := strings.Index(body, `<div class="upstream-row" data-pattern="`+pat+`"`)
	if i < 0 {
		t.Fatalf("%s row not rendered", pat)
	}
	row := body[i:]
	if end := strings.Index(row, "</div>"); end > 0 {
		row = row[:end]
	}
	return row
}

// The badge means one thing -- "this bot's range preset is enabled" -- and the
// legend states it as an absolute.  A row passing on its UA too (policy off)
// still shows green, because its preset is still enabled; what differs is the
// row's own setting.  Rendering it grey there is what made an earlier legend
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
		// Policy off + set to pass: this row passes on either path.
		s.Nginx.SearchBots.RequireRangeVerification = settings.BoolPtr(false)
		s.Nginx.SearchBots.UpstreamPatternMode = map[string]string{`bingbot`: "white"}
	})
	req := jaRequest(http.MethodGet, "/unmask/admin/settings/?tab=ua-filter", nil)
	req.SetPathValue("tab", "ua-filter")
	rr := httptest.NewRecorder()
	h.AdminSettingsIndex(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
	body := rr.Body.String()

	row := upstreamRow(t, body, `bingbot`)
	if !strings.Contains(row, "upstream-rv rv-on") {
		t.Errorf("bingbot's preset is enabled, so its badge must be green regardless of how the row is set: %q", row)
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
