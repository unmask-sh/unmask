package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The stats card's custom_rule row is broken down by rule: a rule on the
// list by its name, linking to it; a rule since deleted by its id, marked;
// and the loads whose page named no rule as the remainder, without an
// address count.
func TestStatsCardNamesTheCustomRules(t *testing.T) {
	h := newTestHandler(t)
	cur := h.snapshotSettings()
	cur.Server.BasePath = "/unmask"
	cur.Nginx.CustomRules = []settings.CustomRule{{ID: "cr1", Label: "the scraper", Enabled: true}}
	h.SetSettings(cur)
	for i, s := range []struct{ ip, payload string }{
		{"1.1.1.1", `{"force_reason":"custom_rule","force_rule":"cr1"}`},
		{"2.2.2.2", `{"force_reason":"custom_rule","force_rule":"cr1"}`},
		{"3.3.3.3", `{"force_reason":"custom_rule","force_rule":"cr2"}`},
		{"4.4.4.4", `{"force_reason":"custom_rule"}`},
	} {
		if _, err := h.DB.Exec(`INSERT INTO unmask_event
			(site, host, scheme, port, ip_address, user_agent, ja4, ja4_verdict, ja4_verdict_id,
			 phase, flags, reload_count, cookie_bv, cookie_br, payload_json, date_created)
			VALUES ('','','','','`+s.ip+`','UA','','',0,'load',0,0,'','',?,datetime('now','-30 minutes'))`, s.payload); err != nil {
			t.Fatalf("seed[%d]: %v", i, err)
		}
	}
	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/stats/default/?range=24h", nil)
	req.SetPathValue("site", "default")
	rr := httptest.NewRecorder()
	h.AdminStats(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("stats page status %d", rr.Code)
	}
	body := rr.Body.String()
	if n := strings.Count(body, `class="cf-rule"`); n != 3 {
		t.Errorf("rule rows under custom_rule: %d, want 3 (two rules and the remainder)", n)
	}
	for _, want := range []string{
		`<a href="/unmask/admin/settings/custom-rules/#rule-cr1">the scraper</a>`,
		`└ cr2 <span class="muted">(削除済み)</span>`,
		`└ ルールの記録なし</span>`,
		`カスタムルール「the scraper」の条件に当たり`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the card lacks %q", want)
		}
	}
}
