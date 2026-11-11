package handlers

import (
	"net/url"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/i18n"
)

// Every filter the hunt page reads has to survive the paging links: the next
// page dropped from / to (a custom range), force_reason, asn, ref and site,
// so a drill-down from a network row or a Ref ID listed the whole window on
// page 2.
func TestHuntPagerKeepsEveryFilter(t *testing.T) {
	q := url.Values{
		"from": {"2026-11-01"}, "to": {"2026-11-02"}, "force_reason": {"rate_limit"},
		"asn": {"AS132203"}, "ref": {"a1b2c3d4e5f60718"}, "site": {"shop.example.com"},
	}
	seek := buildHuntPagerSeek(i18n.LangEN, "custom", "203.0.113.", "", "", "", q, 100, 100, true, true, "", 0)
	for _, link := range []struct{ name, url string }{{"next", seek.NextURL}, {"prev", seek.PrevURL}, {"first", seek.FirstURL}} {
		got, err := url.ParseQuery(strings.TrimPrefix(link.url, "?"))
		if err != nil {
			t.Fatalf("%s: %v", link.name, err)
		}
		for k, v := range q {
			if got.Get(k) != v[0] {
				t.Errorf("%s link lost %s=%s: %q", link.name, k, v[0], link.url)
			}
		}
		if got.Get("range") != "custom" || got.Get("ip") != "203.0.113." {
			t.Errorf("%s link lost range / ip: %q", link.name, link.url)
		}
	}
	// A preset range carries no stale custom dates.
	if s := buildHuntPagerSeek(i18n.LangEN, "1h", "", "", "", "", q, 100, 100, true, true, "", 0); strings.Contains(s.NextURL, "from=") {
		t.Errorf("a preset range carried the custom dates: %q", s.NextURL)
	}
}
