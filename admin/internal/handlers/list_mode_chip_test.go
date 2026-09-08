package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// ruleListMarkup returns one rule list's markup: from its opening tag up to
// the next rule list on the page (rows and <template> included).
func ruleListMarkup(t *testing.T, body, name string) (string, bool) {
	t.Helper()
	i := strings.Index(body, `data-rule-name="`+name+`"`)
	if i < 0 {
		return "", false
	}
	rest := body[i+1:]
	// Up to the next list, or the page scripts (which mention the chip's
	// class name in code), whichever comes first.
	for _, stop := range []string{`data-rule-name="`, "<script"} {
		if j := strings.Index(rest, stop); j >= 0 {
			rest = rest[:j]
		}
	}
	return rest, true
}

// The pattern-mode chip belongs to lists whose values are read as patterns.
// A list of addresses or codes (bypass IPs, stats-excluded IPs, LB ranges,
// countries, ASNs) must not carry it: a new bypass-IP row used to submit as
// "exact:10.2.201.0/24" and be refused.  A pattern list keeps the chip and
// shows the mode as a badge in its confirmed rows, so the list can be read
// without opening each row.
func TestLiteralListsHaveNoChipAndPatternListsShowBadge(t *testing.T) {
	h := newTestHandler(t)
	h.updateSettingsInMemory(func(s *settings.Settings) {
		s.Nginx.BypassPaths.Paths = []settings.BypassPath{{Path: "contains:/feed/", Title: "feed"}}
	})
	render := func(tab string) string {
		req := httptest.NewRequest(http.MethodGet, "/unmask/admin/settings/?tab="+tab, nil)
		req.SetPathValue("tab", tab)
		rr := httptest.NewRecorder()
		h.AdminSettingsIndex(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("tab %s: want 200, got %d", tab, rr.Code)
		}
		return rr.Body.String()
	}
	bodies := map[string]string{}
	for _, tab := range []string{"bypass-ips", "network", "geo", "asn", "bypass-paths"} {
		bodies[tab] = render(tab)
	}
	find := func(name string) string {
		for tab, b := range bodies {
			if m, ok := ruleListMarkup(t, b, name); ok {
				_ = tab
				return m
			}
		}
		t.Fatalf("rule list %s not rendered on any of the tabs", name)
		return ""
	}
	for _, name := range []string{"bypass_ip", "stats_exclude_ips", "lb_extra", "geo_country", "asn_number"} {
		if strings.Contains(find(name), "rule-pat-mode") {
			t.Errorf("%s holds values, not patterns: it must not render the pattern-mode chip", name)
		}
	}
	bp := find("bp_path")
	if !strings.Contains(bp, "rule-pat-mode") {
		t.Errorf("bp_path is a pattern list and keeps its chip")
	}
	if !strings.Contains(bp, `/feed/<span class="pat-lit" data-mode="contains">`) {
		t.Errorf("a confirmed bypass-path row must show the marker-stripped text and the mode badge")
	}
}
