package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/classify"
	"github.com/unmask-sh/unmask/admin/internal/i18n"
	"github.com/unmask-sh/unmask/admin/internal/nginxconf"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

const gbotUA = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"

// The badge's "did not pass verification" claim is only true for crawlers the
// policy actually rescues.  A crawler the operator deliberately challenges
// (group black / none, pattern upstream-disabled) lands in the log genuine
// and spoofed alike, so those resolve to "challenged" and get the other title.
func TestCrawlerBadgeChallenged(t *testing.T) {
	tag := classify.LookupTag(gbotUA)
	if tag == "" {
		t.Fatal("Googlebot UA no longer resolves to an upstream tag")
	}

	if crawlerBadgeChallenged(gbotUA, tag, settings.SearchBotsConfig{}) {
		t.Error("default policy rescues Googlebot; badge must keep the spoof-signal title")
	}
	for _, mode := range []string{classify.GroupModeBlack, classify.GroupModeNone} {
		sb := settings.SearchBotsConfig{UpstreamGroupMode: map[string]string{tag: mode}}
		if !crawlerBadgeChallenged(gbotUA, tag, sb) {
			t.Errorf("group mode %q deliberately challenges the crawler; badge must not claim a failed verification", mode)
		}
	}
	if !crawlerBadgeChallenged(gbotUA, tag, settings.SearchBotsConfig{UpstreamDisabled: []string{"Googlebot"}}) {
		t.Error("an upstream-disabled pattern is deliberately challenged")
	}
	// An enabled operator Extra rescue wins over everything, mirroring
	// isSearchBotUA -- the crawler passes, so a row of it here is back to
	// being unexplained-by-policy and keeps the spoof-signal reading.
	sb := settings.SearchBotsConfig{
		Extra:             []string{"Googlebot"},
		UpstreamGroupMode: map[string]string{tag: classify.GroupModeBlack},
	}
	if crawlerBadgeChallenged(gbotUA, tag, sb) {
		t.Error("an operator Extra rescue overrides the black group")
	}
	// ...but not when the Extra row is switched off.
	sb.ExtraDisabled = []bool{true}
	if !crawlerBadgeChallenged(gbotUA, tag, sb) {
		t.Error("a disabled Extra row must not count as a rescue")
	}

	// The default-black tags (scanner / http-library / browser-automation)
	// sit outside CrawlerTagOrder, so LookupTag -- and therefore the listed
	// badge -- never sees them; the challenged title can only arise from an
	// operator override.  A junk override value falls back to the default
	// (white here), same as ResolveGroupMode.
	junk := settings.SearchBotsConfig{UpstreamGroupMode: map[string]string{tag: "garbage"}}
	if crawlerBadgeChallenged(gbotUA, tag, junk) {
		t.Error("an invalid group-mode override must fall back to the white default")
	}

	if crawlerBadgeChallenged("", "", settings.SearchBotsConfig{}) ||
		crawlerBadgeChallenged("curl/8.0", "", settings.SearchBotsConfig{}) {
		t.Error("a UA with no upstream tag is never challenged-by-crawler-policy")
	}
}

func huntBodyEN(t *testing.T, h *Handler) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/hunt/?range=24h", nil)
	req.AddCookie(&http.Cookie{Name: i18n.CookieName, Value: "en"})
	rr := httptest.NewRecorder()
	h.AdminHuntIndex(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("hunt: %d", rr.Code)
	}
	return rr.Body.String()
}

// End to end through the hunt page: the same Googlebot row swaps its badge
// title when the operator flips the search-engine group to a challenge
// target.  Assertions scope to the rows -- the column-header legend describes
// both titles and would otherwise satisfy any Contains.
func TestHuntBadgeTitleFollowsCrawlerPolicy(t *testing.T) {
	h := newTestHandler(t)
	if _, err := h.DB.Exec(`INSERT INTO unmask_event
		(site,host,scheme,port,ip_address,user_agent,ja4,ja4_verdict,ja4_verdict_id,
		 phase,flags,reload_count,cookie_bv,cookie_br,payload_json,date_created)
		VALUES ('','','https',443,x'7f000001',?,'','',0,'serve',0,0,'','','{}',datetime('now'))`, gbotUA); err != nil {
		t.Fatal(err)
	}

	rows := rowsOnly(huntBodyEN(t, h))
	if !strings.Contains(rows, "did not pass verification") {
		t.Error("default policy: the listed badge must carry the spoof-signal title")
	}
	if strings.Contains(rows, "Configured as a challenge target") {
		t.Error("default policy: no row is a configured challenge target")
	}

	s := h.snapshotSettings()
	s.Nginx.SearchBots.UpstreamGroupMode = map[string]string{"search-engine": classify.GroupModeBlack}
	h.SetSettings(s)

	rows = rowsOnly(huntBodyEN(t, h))
	if !strings.Contains(rows, "Configured as a challenge target") {
		t.Error("black group: the note must say the crawler is a configured target")
	}
	if strings.Contains(rows, "did not pass verification") {
		t.Error("black group: the spoof-signal note is a false accusation here")
	}

	// ...unless the vendor's ranges are live.  Then the bypass-IP veto runs
	// BEFORE the challenge-target decision, so a genuine crawler never
	// reaches this log however the UA policy is set -- and the row is back to
	// being a spoof signal, named after the check it actually failed.
	s = h.snapshotSettings()
	s.Nginx.BypassIPEnabledPresets = nginxconf.UARangePresets[`Googlebot\/`]
	h.SetSettings(s)
	rows = rowsOnly(huntBodyEN(t, h))
	if !strings.Contains(rows, "Likely spoofed") {
		t.Error("with the vendor ranges live, a listed row means the address check failed")
	}
	if strings.Contains(rows, "Configured as a challenge target") {
		t.Error("the range reading must outrank the configured-target one")
	}
}

// The seek-pager caption counts what the collapse leaves on screen, not the
// raw rows: 3 rows folding into 2 visible sessions must caption "1-3 (2
// sessions)", otherwise a 100-row page rendering ~20 session lines reads as
// the pager lying about its own page size.
func TestHuntPagerCaptionShowsSessionCount(t *testing.T) {
	h := newTestHandler(t)
	for _, ev := range []struct{ ua, payload string }{
		{"Mozilla/5.0 test-a", `{"bt":"tok-shared"}`},
		{"Mozilla/5.0 test-b", `{"bt":"tok-shared"}`},
		{"Mozilla/5.0 test-c", `{}`},
	} {
		if _, err := h.DB.Exec(`INSERT INTO unmask_event
			(site,host,scheme,port,ip_address,user_agent,ja4,ja4_verdict,ja4_verdict_id,
			 phase,flags,reload_count,cookie_bv,cookie_br,payload_json,date_created)
			VALUES ('','','https',443,x'7f000001',?,'','',0,'serve',0,0,'','',?,datetime('now'))`, ev.ua, ev.payload); err != nil {
			t.Fatal(err)
		}
	}
	body := huntBodyEN(t, h)
	if !strings.Contains(body, "showing 1-3 (2 sessions)") {
		t.Error("pager caption does not carry the visible session count")
	}
}
