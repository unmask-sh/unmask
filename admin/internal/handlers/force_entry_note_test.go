package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/i18n"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The popover behind a reason badge: the stats card's sentence for the
// entry, its name in bold and linking to where it is set; a custom rule
// since deleted by its id, marked; nothing for a reason without an entry.
func TestForceEntryNote(t *testing.T) {
	h := newTestHandler(t)
	cur := h.snapshotSettings()
	cur.Server.BasePath = "/unmask"
	cur.Nginx.CustomRules = []settings.CustomRule{
		{ID: "cr1", Label: "the scraper", Enabled: true},
		{ID: "cr2", Label: `<i>x</i> & "y"`, Enabled: true},
	}
	cur.Nginx.Asn = settings.AsnConfig{Rules: []settings.AsnRule{{ASN: 132203, Label: "the farm", Enabled: true}}}
	h.SetSettings(cur)
	for _, c := range []struct{ lang, reason, entry, want string }{
		{"ja", "custom_rule", "cr1", `カスタムルール「<a href="/unmask/admin/settings/custom-rules/#rule-cr1"><b>the scraper</b></a>」の条件に当たり、そのアクションで challenge になった訪問者。`},
		{"ja", "custom_rule", "cr9", `カスタムルール「<b>cr9</b>」の条件に当たり、そのアクションで challenge になった訪問者。 <span class="muted">(削除済み)</span>`},
		// the name is the operator's text: escaped, never markup
		{"ja", "custom_rule", "cr2", `カスタムルール「<a href="/unmask/admin/settings/custom-rules/#rule-cr2"><b>&lt;i&gt;x&lt;/i&gt; &amp; &#34;y&#34;</b></a>」の条件に当たり、そのアクションで challenge になった訪問者。`},
		{"ja", "ua_target", "preset:empty", `UA フィルタの「<a href="/unmask/admin/settings/ua-filter/"><b>Empty UA / extremely short UA (5 chars or fewer)</b></a>」に当たった訪問者。`},
		{"en", "ua_target", "preset:empty", `Matched “<a href="/unmask/admin/settings/ua-filter/"><b>Empty UA / extremely short UA (5 chars or fewer)</b></a>” in the UA filter.`},
		{"ja", "asn", "AS132203", `ASN ルール <a href="/unmask/admin/settings/asn/"><b>AS132203 · the farm</b></a> に当たった訪問者。`},
		{"ja", "stale", "chrome 100", `<a href="/unmask/admin/settings/ua-filter/#ua-stale"><b>Chrome 100</b></a> は、古いブラウザとみなす版より前。`},
		{"ja", "rate_limit", "", ``},
		{"ja", "none", "", ``},
	} {
		if got := string(h.forceEntryNote(i18n.Lang(c.lang), c.reason, c.entry)); got != c.want {
			t.Errorf("%s %s %q:\n got %s\nwant %s", c.lang, c.reason, c.entry, got, c.want)
		}
	}
}

// The hunt badge names the reason alone -- a rule's name can run to a
// sentence -- and carries the entry's note beside it, hidden, for the
// popover; a reason without an entry is a plain badge.
func TestHuntBadgeCarriesTheEntryNote(t *testing.T) {
	h := newTestHandler(t)
	cur := h.snapshotSettings()
	cur.Server.BasePath = "/unmask"
	cur.Nginx.CustomRules = []settings.CustomRule{{ID: "cr1", Label: "the scraper", Enabled: true}}
	h.SetSettings(cur)
	for i, payload := range []string{`{"force_reason":"custom_rule","force_rule":"cr1"}`, `{"force_reason":"rate_limit"}`} {
		if _, err := h.DB.Exec(`INSERT INTO unmask_event (ip_address, ja4, user_agent, host, phase, payload_json, date_created) `+
			`VALUES (?, 't13d1516h2_8daaf6152771_b186095e22b6', 'UA', 'example.com', 'serve', ?, datetime('now'))`,
			[]byte{127, 0, 0, byte(2 + i)}, payload); err != nil {
			t.Fatalf("seed[%d]: %v", i, err)
		}
	}
	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/hunt/?range=1h", nil)
	rr := httptest.NewRecorder()
	h.AdminHuntIndex(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("hunt status %d", rr.Code)
	}
	body := rr.Body.String()
	want := `<span class="fr-badge" data-fr-note>custom_rule</span><span class="fr-note" hidden>` +
		`カスタムルール「<a href="/unmask/admin/settings/custom-rules/#rule-cr1"><b>the scraper</b></a>」の条件に当たり、そのアクションで challenge になった訪問者。</span>`
	if !strings.Contains(body, want) {
		t.Errorf("the badge lacks its note:\n%s", want)
	}
	if !strings.Contains(body, `<span class="fr-badge">rate_limit</span>`) {
		t.Error("a reason without an entry must be a plain badge")
	}
	if strings.Contains(body, "custom_rule · ") {
		t.Error("the entry's name must not be inline on the badge")
	}
}

// The CAPTCHA-pass list on the stats page: the reason badge alone, the
// entry's note hidden beside it for the help popover to append.
func TestStatsPassListCarriesTheEntryNote(t *testing.T) {
	h := newTestHandler(t)
	cur := h.snapshotSettings()
	cur.Server.BasePath = "/unmask"
	cur.Nginx.CustomRules = []settings.CustomRule{{ID: "cr1", Label: "the scraper", Enabled: true}}
	h.SetSettings(cur)
	if _, err := h.DB.Exec(`INSERT INTO unmask_event
		(site, host, scheme, port, ip_address, user_agent, ja4, ja4_verdict, ja4_verdict_id,
		 phase, flags, reload_count, cookie_bv, cookie_br, payload_json, date_created)
		VALUES ('','','',0,?,'UA','','',0,'bv_captcha_only',0,0,'','',?,datetime('now','-30 minutes'))`,
		[]byte{1, 1, 1, 1}, `{"force_reason":"custom_rule","force_rule":"cr1","orig_path":"/x"}`); err != nil {
		t.Fatalf("seed: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/stats/default/?range=24h", nil)
	req.SetPathValue("site", "default")
	rr := httptest.NewRecorder()
	h.AdminStats(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("stats status %d", rr.Code)
	}
	body := rr.Body.String()
	want := `<span class="cp-fr help-dotted" data-help-key="captcha_force.kind.custom_rule">custom_rule</span><span class="help-note" hidden>` +
		`カスタムルール「<a href="/unmask/admin/settings/custom-rules/#rule-cr1"><b>the scraper</b></a>」の条件に当たり、そのアクションで challenge になった訪問者。</span>`
	if !strings.Contains(body, want) {
		t.Errorf("the pass list's badge lacks its note:\n%s", want)
	}
	if strings.Contains(body, "custom_rule · ") {
		t.Error("the entry's name must not be inline on the badge")
	}
}
