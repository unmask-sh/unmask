package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The country tab's estimate: the proposed rules run over the last day's
// name-only passes of the social-preview crawlers, a verified fetcher left out
// once an ASN mmdb is there to verify it by.
func TestGeoPreviewImpact(t *testing.T) {
	h := newTestHandler(t)
	if _, err := h.DB.ExecContext(context.Background(), `CREATE TABLE IF NOT EXISTS unmask_crawler_named_hourly (
		bucket_hour INTEGER NOT NULL, crawler VARCHAR(48) NOT NULL, country VARCHAR(2) NOT NULL DEFAULT '',
		cnt INTEGER NOT NULL DEFAULT 0, ips BLOB, PRIMARY KEY (bucket_hour, crawler, country))`); err != nil {
		t.Fatal(err)
	}
	hour := time.Now().Unix() / 3600
	for _, row := range []struct {
		hour    int64
		crawler string
		cc      string
		cnt     int
	}{
		{hour, "Twitterbot", "US", 700}, {hour - 2, "Twitterbot", "JP", 80}, {hour - 1, "Slackbot", "US", 135},
		{hour, "Slackbot", "", 3},             // an address the mmdb could not place: the default applies
		{hour, "Googlebot", "US", 5},          // not a link-preview fetcher
		{hour - 30, "Twitterbot", "US", 1000}, // outside the day
	} {
		if _, err := h.DB.ExecContext(context.Background(),
			`INSERT INTO unmask_crawler_named_hourly (bucket_hour, crawler, country, cnt) VALUES (?, ?, ?, ?)`,
			row.hour, row.crawler, row.cc, row.cnt); err != nil {
			t.Fatal(err)
		}
	}
	ask := func(query string) previewImpact {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/admin/settings/geo/preview-impact?"+query, nil)
		rec := httptest.NewRecorder()
		h.AdminGeoPreviewImpact(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
		}
		var out previewImpact
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	rowsOf := func(out previewImpact) map[string]int64 {
		m := map[string]int64{}
		for _, r := range out.Rows {
			m[r.Crawler] = r.Requests
		}
		return m
	}

	// The world challenged, Japan spared: the US fetches and the unplaced
	// ones are stopped, Japan's are not, and Googlebot is nobody's preview.
	out := ask("default=pow_then_captcha&rules=JP:skip")
	if got := rowsOf(out); len(out.Rows) != 2 || got["Twitterbot"] != 700 || got["Slackbot"] != 138 {
		t.Errorf("rows = %+v, want Twitterbot 700, Slackbot 138", out.Rows)
	}
	if out.Rows[0].Crawler != "Twitterbot" {
		t.Errorf("rows are not most first: %+v", out.Rows)
	}
	if out.ASNMMDB || len(out.Verified) != 0 {
		t.Errorf("no ASN mmdb, yet asn_mmdb=%v verified=%v", out.ASNMMDB, out.Verified)
	}
	// A blank rule inherits the rule default (②), which itself inherits ①.
	if got := rowsOf(ask("default=skip&rule_default=deny&rules=US:")); got["Twitterbot"] != 700 || got["Slackbot"] != 135 {
		t.Errorf("a blank rule under rule_default=deny: %v", got)
	}
	if got := rowsOf(ask("default=deny&rules=US:")); got["Twitterbot"] != 780 || got["Slackbot"] != 138 {
		t.Errorf("a blank rule under default=deny alone: %v", got)
	}
	// Nothing to stop.
	if out := ask("default=skip"); len(out.Rows) != 0 {
		t.Errorf("default=skip stops %+v", out.Rows)
	}
	if out := ask("default=bogus&rules=US:nonsense"); len(out.Rows) != 0 {
		t.Errorf("unknown actions stop %+v", out.Rows)
	}

	// With an ASN mmdb configured the pair verifies Twitterbot, so it is
	// named and not counted; Slackbot, which no network verifies, stays.
	s := h.snapshotSettings()
	s.IPGeo.MMDBASNPath = "/nonexistent/asn.mmdb"
	out = h.previewImpact(context.Background(), s, settings.RateChallengePoWThenCaptcha, map[string]string{"JP": settings.GeoActionSkip})
	if !out.ASNMMDB {
		t.Error("asn_mmdb=false with the path set")
	}
	if got := rowsOf(out); len(out.Rows) != 1 || got["Slackbot"] != 138 {
		t.Errorf("rows with the pair live = %+v, want Slackbot 138 only", out.Rows)
	}
	seen := map[string]bool{}
	for _, v := range out.Verified {
		seen[v] = true
	}
	if !seen["Twitterbot"] || !seen["facebookexternalhit"] {
		t.Errorf("verified = %v, want Twitterbot and facebookexternalhit", out.Verified)
	}
}

// The country and ASN tabs carry the note on named crawlers with the ASN
// mmdb's state, the country tab the estimate's box wired to its endpoint, and
// the UA filter the three fetchers' network badge -- with no raw i18n key.
func TestPreviewVerifyRendersOnTheTabs(t *testing.T) {
	h := newTestHandler(t)
	render := func(tab string) string {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/unmask/admin/settings/?tab="+tab, nil)
		req.SetPathValue("tab", tab)
		rr := httptest.NewRecorder()
		h.AdminSettingsIndex(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("%s: want 200, got %d", tab, rr.Code)
		}
		body := rr.Body.String()
		for _, leak := range []string{"settings.geo.preview", "settings.ua.upstream.pv_"} {
			if strings.Contains(body, leak) {
				t.Errorf("%s: raw %s* i18n key leaked", tab, leak)
			}
		}
		return body
	}
	geo := render("geo")
	for _, want := range []string{
		`id="geo-preview-impact"`,
		`/admin/settings/geo/preview-impact"`, // the box's data-url, under the install's base path
		"AS13414",                             // the note names the networks
		`getElementById('geo-preview-impact')`,
	} {
		if !strings.Contains(geo, want) {
			t.Errorf("geo tab lacks %q", want)
		}
	}
	if asn := render("asn"); !strings.Contains(asn, "AS38631") || strings.Contains(asn, `id="geo-preview-impact"`) {
		t.Error("the asn tab lacks the note, or carries the country tab's estimate")
	}
	if ua := render("ua-filter"); !strings.Contains(ua, "AS13414") || !strings.Contains(ua, "AS32934, AS38631") {
		t.Error("the UA filter lacks the fetchers' network badges")
	}
}
