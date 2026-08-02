package handlers

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/i18n"
)

// The abandon rate counts only visitors whose browser ran the challenge JS.
// Using serves as the denominator would fold in every scraper that never
// executes JS, turning a "how much is this costing real people" number into a
// restatement of the block count -- and an operator tuning PoW difficulty
// would be reading the wrong signal.
func TestAbandonRateExcludesClientsThatNeverRanTheJS(t *testing.T) {
	h := newTestHandler(t)
	s := h.snapshotSettings()
	s.Server.BasePath = "/unmask"
	h.SetSettings(s)

	ins := func(phase, bt string) {
		t.Helper()
		if _, err := h.DB.Exec(`INSERT INTO unmask_event
			(site,host,scheme,port,ip_address,user_agent,ja4,ja4_verdict,ja4_verdict_id,
			 phase,flags,reload_count,cookie_bv,cookie_br,payload_json,date_created)
			VALUES ('','','https',443,x'7f000001','ua','','',0,?,0,0,'','',?,datetime('now'))`,
			phase, `{"bt":"`+bt+`"}`); err != nil {
			t.Fatal(err)
		}
	}
	// 10 bots: served, never ran the JS.
	for i := 0; i < 10; i++ {
		ins("serve", "bot")
	}
	// 4 real visitors loaded the page; 3 finished, 1 gave up.
	for i := 0; i < 4; i++ {
		ins("serve", "human")
		ins("load", "human")
	}
	for i := 0; i < 3; i++ {
		ins("bv_pow_only", "human")
	}

	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/", nil)
	req.AddCookie(&http.Cookie{Name: i18n.CookieName, Value: "en"}) // assertions read the EN copy
	rr := httptest.NewRecorder()
	h.AdminTopOverview(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("overview: %d", rr.Code)
	}
	body := rr.Body.String()

	// Read the tile's own value rather than searching the page: a bare "7.1"
	// matches SVG path coordinates, which is how the first version of this
	// test failed for a reason that had nothing to do with the metric.
	sub := regexp.MustCompile(`(?s)<div class="sub">([^<]*did not finish[^<]*)</div>`).FindStringSubmatch(body)
	if sub == nil {
		t.Fatal("the abandon tile is missing from the overview")
	}
	// 1 of 4 loads did not finish.  Had the denominator been serves (14), the
	// same data would read 1 of 14 and hide the problem.
	if !strings.Contains(sub[1], "1") || !strings.Contains(sub[1], "4") {
		t.Errorf("abandon tile reads %q, want 1 of 4 (loads), not a count against serves", sub[1])
	}
	if strings.Contains(sub[1], "14") {
		t.Errorf("the denominator is serves (14), so bots that never ran the JS are diluting it: %q", sub[1])
	}
	val := regexp.MustCompile(`(?s)<div class="value">([0-9.]+)<span[^>]*>%`).FindStringSubmatch(body)
	if val == nil || val[1] != "25.0" {
		t.Errorf("abandon rate = %v, want 25.0 (1 unfinished of 4 loads)", val)
	}
}
