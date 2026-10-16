package dashboard

import (
	"context"
	"database/sql"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/events"
)

// cardAnswers is everything the stats page's per-visitor cards answer, read
// in one go so two readings can be compared whole.
type cardAnswers struct {
	Reload         []ReloadLoopRow
	VerifyNG       []VerifyNGRow
	FailReasons    map[string]int
	PassReasons    map[string]int
	PassVerdicts   map[string]int
	PassTopIPs     []CaptchaPassIPRow
	PassRecent     []CaptchaPassRow
	CookieFails    []CookieFailRow
	Stealth        []StealthRow
	RLSummary      RLSummary
	RLIPs          []RLIPRow
	RLPaths        []RLPathRow
	RLQueries      map[string][]RLQueryCount
	RebindLineages []events.RebindLineageRow
	RLFunnel       FunnelRow
}

func readCards(ctx context.Context, t *testing.T, d *db.DB, site string) cardAnswers {
	t.Helper()
	var a cardAnswers
	var err error
	must := func(what string) {
		t.Helper()
		if err != nil {
			t.Fatalf("%s (site %q): %v", what, site, err)
		}
	}
	a.Reload, err = ReloadLoops(ctx, d, site, nil, 24)
	must("ReloadLoops")
	a.VerifyNG, err = VerifyNGRanking(ctx, d, site, nil, 24, 30)
	must("VerifyNGRanking")
	a.FailReasons, err = CaptchaFailForceReasonCounts(ctx, d, site, nil, 24)
	must("CaptchaFailForceReasonCounts")
	a.PassReasons, err = CaptchaPassForceReasonCounts(ctx, d, site, nil, 24)
	must("CaptchaPassForceReasonCounts")
	a.PassVerdicts, err = CaptchaPassVerdictCounts(ctx, d, site, nil, 24)
	must("CaptchaPassVerdictCounts")
	a.PassTopIPs, err = CaptchaPassTopIPs(ctx, d, site, nil, 24, 30)
	must("CaptchaPassTopIPs")
	a.PassRecent, err = CaptchaPassRecent(ctx, d, site, nil, 24, 10)
	must("CaptchaPassRecent")
	a.CookieFails, err = CookieSetFails(ctx, d, site, nil, 24)
	must("CookieSetFails")
	a.Stealth, err = StealthPassed(ctx, d, site, nil, 24, []string{"bot_x"})
	must("StealthPassed")
	a.RLSummary, a.RLIPs, a.RLPaths, a.RLQueries, err = RateLimitAll(ctx, d, site, nil, 24, 30, 30, 10)
	must("RateLimitAll")
	if site == "" {
		a.RebindLineages, err = events.RankByRebindLineage(ctx, d, 24*60, 30)
		must("RankByRebindLineage")
	}
	since := "date_created > '" + time.Now().Add(-24*time.Hour).UTC().Format("2006-01-02 15:04:05") + "'"
	a.RLFunnel, err = rateLimitFunnelRow(ctx, d, site, nil, since, []string{"bot_x"})
	must("rateLimitFunnelRow")
	return a
}

// The cards' partial indexes (migration 0037) and the date cover index (0038)
// change how fast the cards read, never what they answer: every card gives
// the same rows with the indexes as from the table.  A card whose query stops carrying its index's terms fails here too --
// with the index pinned, SQLite refuses a plan it cannot use it in.  A payload
// that is not JSON does not fail its write: the index leaves the row out.
func TestCardIndexesAnswerAsTheTable(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	ctx := context.Background()
	if err := d.RefreshIndexes(ctx); err != nil {
		t.Fatal(err)
	}
	all := []string{db.IdxEventReload, db.IdxEventVerifyNG, db.IdxEventCaptchaPass,
		db.IdxEventCookieFail, db.IdxEventRebind, db.IdxEventRateLimited, db.IdxEventDateCover}
	for _, ix := range all {
		if !d.HasIndex(ix) {
			t.Fatalf("migrations 0037/0038 did not build %s", ix)
		}
	}

	minute := 0
	add := func(site string, ip byte, phase string, reload, flags int, verdict, ua, payload string) {
		t.Helper()
		minute++
		var p sql.NullString
		if payload != "" {
			p = sql.NullString{String: payload, Valid: true}
		}
		if _, err := d.Exec(`INSERT INTO unmask_event
			(site, host, scheme, port, ip_address, user_agent, ja4, ja4_verdict, ja4_verdict_id,
			 phase, flags, reload_count, cookie_bv, cookie_br, payload_json, date_created)
			VALUES (?, 'node1', 'https', 443, ?, ?, 't13d1516h2_aaaaaaaaaaaa_bbbbbbbbbbbb', ?, 0,
			        ?, ?, ?, '', '', ?, datetime('now', ?))`,
			site, []byte{10, 0, 0, ip}, ua, verdict, phase, flags, reload, p, "-"+strconv.Itoa(minute)+" minutes"); err != nil {
			t.Fatalf("insert %s for .%d: %v", phase, ip, err)
		}
	}
	// Reload loops: .1 reloads up to 4, .2 three times once, .3 once (below
	// the card's bar), .4 never reloads (not in the index at all).
	for rc := 1; rc <= 4; rc++ {
		add("a.example", 1, "load", rc, rc%2, "", "UA-one", `{"orig_path":"/r"}`)
	}
	for i := 0; i < 3; i++ {
		add("b.example", 2, "load", 1, 0, "", "UA-two", "")
	}
	add("a.example", 3, "load", 1, 0, "", "UA-three", `{}`)
	add("a.example", 4, "load", 0, 0, "", "UA-four", `{}`)
	// Verification failures, with method, score and reason in the payload.
	add("a.example", 5, "verify_ng", 0, 0, "bot_x", "UA-five", `{"method":"math","score":0.1,"force_reason":"ja4_bot"}`)
	add("a.example", 5, "verify_ng", 0, 0, "bot_x", "UA-five", `{"method":"behavioral","score":0.3,"force_reason":"rate_limit"}`)
	add("b.example", 5, "verify_ng", 0, 0, "bot_x", "UA-five", `{"method":"behavioral","score":0.2}`)
	add("a.example", 6, "verify_ng", 0, 0, "", "UA-six", `{"method":"math","score":0.4,"force_reason":"none"}`)
	add("a.example", 6, "verify_ng", 0, 0, "", "UA-six", `{"method":"math","score":0.5}`)
	add("b.example", 7, "verify_ng", 0, 0, "", "UA-seven", "")
	add("a.example", 8, "verify_ng", 0, 0, "", "UA-eight", `not json at all`) // kept out, not a failed write
	// CAPTCHA passes.
	for i, path := range []string{"/a", "/b", "/a", "/c"} {
		add("a.example", 9, "bv_captcha_only", 0, 0, "bot_x", "UA-nine", `{"force_reason":"ja4_bot","orig_path":"`+path+`","ref":"r9`+strconv.Itoa(i)+`"}`)
	}
	add("b.example", 10, "bv_pow_then_captcha", 0, 0, "h1_lax", "UA-ten", `{"force_reason":"geo_country","orig_path":"/z"}`)
	add("b.example", 10, "bv_pow_then_captcha", 0, 0, "h1_lax", "UA-ten", `{"orig_path":"/z"}`)
	add("a.example", 11, "bv_captcha_only", 0, 0, "", "UA-eleven", "")
	add("a.example", 12, "bv_captcha_only", 0, 0, "bot_x", "UA-twelve", `{"force_reason":`) // malformed
	// PoW passes whose cookie did not stick: .13 three times, .14 twice (as
	// the number 0), .15 stuck (not a failure).
	for i := 0; i < 3; i++ {
		add("a.example", 13, "bv_pow_only", 0, 0, "", "UA-thirteen", `{"cookie_set_ok":false}`)
	}
	add("b.example", 14, "bv_pow_only", 0, 0, "", "UA-fourteen", `{"cookie_set_ok":0}`)
	add("b.example", 14, "bv_pow_only", 0, 0, "", "UA-fourteen", `{"cookie_set_ok":0}`)
	add("a.example", 15, "bv_pow_only", 0, 0, "", "UA-fifteen", `{"cookie_set_ok":true}`)
	// Rebinds: lineage L1 onto three addresses, L2 onto one and refused twice.
	for ip := byte(16); ip <= 18; ip++ {
		add("a.example", ip, "bv_rebind", 0, 0, "", "UA-r", `{"lineage":"L1"}`)
	}
	add("a.example", 19, "bv_rebind", 0, 0, "", "UA-r", `{"lineage":"L2"}`)
	add("a.example", 19, "bv_rebind_reject", 0, 0, "", "UA-r", `{"lineage":"L2","reason":"ja4_mismatch"}`)
	add("a.example", 20, "bv_rebind_reject", 0, 0, "", "UA-r", `{"lineage":"L2","reason":"cap"}`)
	// Rate-limited serves: .21 three times over two paths, .22 twice, .23 not
	// rate-limited.  No two counts tie, so every ranking has one order.
	add("a.example", 21, "serve", 0, 0, "", "UA-21", `{"rl":1,"orig_path":"/x?q=1","force_reason":"rate_limit"}`)
	add("a.example", 21, "serve", 0, 0, "", "UA-21", `{"rl":1,"orig_path":"/x?q=1","force_reason":"rate_limit"}`)
	add("a.example", 21, "serve", 0, 0, "", "UA-21", `{"rl":"1","orig_path":"/y","force_reason":"rate_limit"}`)
	add("b.example", 22, "serve", 0, 0, "", "UA-22", `{"rl":1,"orig_path":"/x?q=2"}`)
	add("b.example", 22, "serve", 0, 0, "", "UA-22", `{"rl":1}`)
	add("a.example", 23, "serve", 0, 0, "", "UA-23", `{"rl":0,"orig_path":"/x"}`)
	add("a.example", 21, "load", 0, 0, "bot_x", "UA-21", `{}`) // what a rate-limited visitor did next

	withIdx := map[string]cardAnswers{}
	for _, site := range []string{"", "a.example"} {
		withIdx[site] = readCards(ctx, t, d, site)
	}
	// The cards found what was planted (not merely the same nothing twice).
	if got := withIdx[""]; len(got.Reload) != 2 || len(got.VerifyNG) != 3 || len(got.PassTopIPs) != 3 ||
		len(got.CookieFails) != 2 || len(got.Stealth) != 1 || got.RLSummary.Total != 5 || len(got.RebindLineages) != 2 ||
		got.RLFunnel.Serve != 5 || got.RLFunnel.Load != 1 || got.RLFunnel.Stealth != 1 {
		t.Fatalf("the cards missed planted rows: reload %d, verify %d, pass IPs %d, cookie %d, stealth %d, rl %d, lineages %d, rl funnel %+v",
			len(got.Reload), len(got.VerifyNG), len(got.PassTopIPs), len(got.CookieFails), len(got.Stealth),
			got.RLSummary.Total, len(got.RebindLineages), got.RLFunnel)
	}

	for _, ix := range all {
		if _, err := d.Exec(`DROP INDEX ` + ix); err != nil {
			t.Fatal(err)
		}
	}
	if err := d.RefreshIndexes(ctx); err != nil {
		t.Fatal(err)
	}
	for _, ix := range all {
		if d.CardIndexHint(ix) != "" {
			t.Fatalf("%s is still hinted after it was dropped", ix)
		}
	}
	for site, want := range withIdx {
		if got := readCards(ctx, t, d, site); !reflect.DeepEqual(got, want) {
			t.Errorf("site %q: the cards answer differently from the table:\nindex: %+v\ntable: %+v", site, want, got)
		}
	}
}
