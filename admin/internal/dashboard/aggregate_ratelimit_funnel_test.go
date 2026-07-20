package dashboard

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// TestRateLimitFunnel_RollupMatchesRawScan seeds events where every IP is active
// in exactly one hour and rate-limited there, so the hour-local rollup must equal
// the window-global raw scan.  This pins the rollup's counting to the existing
// rateLimitFunnelRow semantics for the no-straddle / no-late-activity case.
func TestRateLimitFunnel_RollupMatchesRawScan(t *testing.T) {
	d := iwTestDB(t)
	ctx := context.Background()
	ip := func(n byte) []byte { return []byte{10, 0, 0, n} }
	at := func(hoursAgo int) string {
		return time.Now().Add(-time.Duration(hoursAgo) * time.Hour).UTC().Format("2006-01-02 15:04:05")
	}
	seed := func(ipb []byte, phase string, rl, flags int, verdict, when string) {
		pj := fmt.Sprintf(`{"rl":%d}`, rl)
		if _, err := d.ExecContext(ctx, `INSERT INTO unmask_event
			(site,host,scheme,port,ip_address,user_agent,ja4,ja4_verdict,ja4_verdict_id,phase,flags,reload_count,cookie_bv,cookie_br,payload_json,date_created)
			VALUES ('','','',0,?,'UA','',?,0,?,?,0,'','',?,?)`,
			ipb, verdict, phase, flags, pj, when); err != nil {
			t.Fatal(err)
		}
	}
	h100, h60 := at(100), at(60)
	// ip1, ip2 rate-limited at -100h; ip3 at -60h. ip4 has an rl=0 serve (not
	// rate-limited); ip5 only loads (never served). Only ip1..ip3 count.
	seed(ip(1), "serve", 1, 0, "bot_x", h100)
	seed(ip(1), "load", 0, 0, "bot_x", h100)
	seed(ip(1), "pow_pass", 0, 0, "bot_x", h100)
	seed(ip(2), "serve", 1, 0, "ok", h100)
	seed(ip(2), "load", 0, 0, "ok", h100)
	seed(ip(2), "captcha", 0, 0, "ok", h100)
	seed(ip(3), "serve", 1, 0, "bot_x", h60)
	seed(ip(3), "load", 0, 0, "bot_x", h60)
	seed(ip(4), "serve", 0, 0, "ok", h60) // rl=0 -> not rate-limited
	seed(ip(4), "load", 0, 0, "ok", h60)
	seed(ip(5), "load", 0, 0, "ok", h60) // no serve

	bot := []string{"bot_x"}
	since := "date_created > '" + time.Now().Add(-200*time.Hour).UTC().Format("2006-01-02 15:04:05") + "'"
	raw, err := rateLimitFunnelRow(ctx, d, "", nil, since, bot)
	if err != nil {
		t.Fatal(err)
	}
	if raw.Serve != 3 || raw.Load != 3 || raw.PowPass != 1 || raw.Captcha != 1 || raw.Stealth != 2 {
		t.Fatalf("raw baseline unexpected: %+v", raw)
	}

	if err := RollupRateLimitFunnel(ctx, d); err != nil {
		t.Fatal(err)
	}
	agg, rolled, err := rateLimitFunnelRowAgg(ctx, d, 200, bot)
	if err != nil {
		t.Fatal(err)
	}
	if !rolled {
		t.Fatal("rolled = false after RollupRateLimitFunnel")
	}
	if agg.Serve != raw.Serve || agg.Load != raw.Load || agg.PowPass != raw.PowPass ||
		agg.Captcha != raw.Captcha || agg.Stealth != raw.Stealth || agg.Silent != raw.Silent {
		t.Errorf("agg != raw:\n agg=%+v\n raw=%+v", agg, raw)
	}
}

// TestRateLimitFunnel_BoundaryOverlap seeds an interaction whose rl=1 serve lands
// 5 min before an hour boundary and whose load lands 3 min after it (next hour).
// The 10-min overlap lookback must still attribute that load to the rate_limit
// row — without it the next hour's rate-limited-IP set would miss the serve.
func TestRateLimitFunnel_BoundaryOverlap(t *testing.T) {
	d := iwTestDB(t)
	ctx := context.Background()
	nowHour := time.Now().Unix() / 3600
	boundary := (nowHour - 50) * 3600 // a settled hour boundary
	serveAt := time.Unix(boundary-300, 0).UTC().Format("2006-01-02 15:04:05")
	loadAt := time.Unix(boundary+180, 0).UTC().Format("2006-01-02 15:04:05")
	ipb := []byte{10, 0, 0, 9}
	ins := func(phase string, rl int, when string) {
		pj := fmt.Sprintf(`{"rl":%d}`, rl)
		if _, err := d.ExecContext(ctx, `INSERT INTO unmask_event
			(site,host,scheme,port,ip_address,user_agent,ja4,ja4_verdict,ja4_verdict_id,phase,flags,reload_count,cookie_bv,cookie_br,payload_json,date_created)
			VALUES ('','','',0,?,'UA','','',0,?,0,0,'','',?,?)`,
			ipb, phase, pj, when); err != nil {
			t.Fatal(err)
		}
	}
	ins("serve", 1, serveAt) // hour H (last 5 min)
	ins("load", 0, loadAt)   // hour H+1 (first 3 min)

	if err := RollupRateLimitFunnel(ctx, d); err != nil {
		t.Fatal(err)
	}
	agg, rolled, err := rateLimitFunnelRowAgg(ctx, d, 200, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !rolled {
		t.Fatal("rolled = false")
	}
	if agg.Serve != 1 {
		t.Errorf("serve = %d, want 1", agg.Serve)
	}
	if agg.Load != 1 {
		t.Errorf("load = %d, want 1 (10-min overlap must attribute the straddling load)", agg.Load)
	}
}

// TestRateLimitFunnel_Idempotent verifies a second rollup pass changes neither
// the cursor (downward) nor the reported counts.
func TestRateLimitFunnel_Idempotent(t *testing.T) {
	d := iwTestDB(t)
	ctx := context.Background()
	ipb := []byte{10, 0, 0, 7}
	when := time.Now().Add(-40 * time.Hour).UTC().Format("2006-01-02 15:04:05")
	ins := func(phase string, rl int) {
		pj := fmt.Sprintf(`{"rl":%d}`, rl)
		if _, err := d.ExecContext(ctx, `INSERT INTO unmask_event
			(site,host,scheme,port,ip_address,user_agent,ja4,ja4_verdict,ja4_verdict_id,phase,flags,reload_count,cookie_bv,cookie_br,payload_json,date_created)
			VALUES ('','','',0,?,'UA','','',0,?,0,0,'','',?,?)`,
			ipb, phase, pj, when); err != nil {
			t.Fatal(err)
		}
	}
	ins("serve", 1)
	ins("load", 0)
	ins("pow_pass", 0)

	if err := RollupRateLimitFunnel(ctx, d); err != nil {
		t.Fatal(err)
	}
	a1, _, _ := rateLimitFunnelRowAgg(ctx, d, 200, nil)
	c1, _ := stateCursor(ctx, d, rlfState)
	if err := RollupRateLimitFunnel(ctx, d); err != nil {
		t.Fatal(err)
	}
	a2, _, _ := rateLimitFunnelRowAgg(ctx, d, 200, nil)
	c2, _ := stateCursor(ctx, d, rlfState)
	if c2 < c1 {
		t.Fatalf("cursor regressed: %d -> %d", c1, c2)
	}
	if a1.Serve != a2.Serve || a1.Load != a2.Load || a1.PowPass != a2.PowPass {
		t.Fatalf("counts changed across passes: %+v -> %+v", a1, a2)
	}
	if a1.Load != 1 || a1.Serve != 1 || a1.PowPass != 1 {
		t.Fatalf("unexpected counts: %+v", a1)
	}
}
