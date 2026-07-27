package dashboard

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// TestForceReasonFunnel_ScanMatchesAgg seeds header/asn/geo challenges across the
// funnel phases and checks the scan path (forceReasonFunnelRowsScan) and the
// hourly-aggregate path (forceReasonFunnelRowsAgg) return the same rows.  Unlike
// the rate_limit row, force_reason rides every phase event, so no IP-window
// correlation is involved -- a plain per-phase count on both sides must agree.
// It also pins the row semantics: a 'none' challenge never lands in an axis row,
// and pass/silent are derived like the verdict rows.
func TestForceReasonFunnel_ScanMatchesAgg(t *testing.T) {
	d := iwTestDB(t)
	ctx := context.Background()
	at := func(hoursAgo int) string {
		return time.Now().Add(-time.Duration(hoursAgo) * time.Hour).UTC().Format("2006-01-02 15:04:05")
	}
	seed := func(ipn byte, phase, reason, when string) {
		pj := fmt.Sprintf(`{"force_reason":%q}`, reason)
		if _, err := d.ExecContext(ctx, `INSERT INTO unmask_event
			(site,host,scheme,port,ip_address,user_agent,ja4,ja4_verdict,ja4_verdict_id,phase,flags,reload_count,cookie_bv,cookie_br,payload_json,date_created)
			VALUES ('','','',0,?,'UA','','ok',0,?,0,0,'','',?,?)`,
			[]byte{10, 0, 0, ipn}, phase, pj, when); err != nil {
			t.Fatal(err)
		}
	}
	h := at(50)
	// header: served, loaded, cleared via CAPTCHA (a false positive -- a human
	// passed the header-integrity challenge).
	seed(1, "serve", "header", h)
	seed(1, "load", "header", h)
	seed(1, "captcha", "header", h)
	seed(1, "bv_captcha_only", "header", h)
	// header: served + loaded, never passed (a bot that stalled).
	seed(2, "serve", "header", h)
	seed(2, "load", "header", h)
	// asn: a serve that never loaded (silent = 1).
	seed(3, "serve", "asn", h)
	// geo: a full PoW pass.
	seed(4, "serve", "geo", h)
	seed(4, "load", "geo", h)
	seed(4, "bv_pow_only", "geo", h)
	// stale: served, loaded, cleared via PoW (a genuine old browser passed).
	seed(6, "serve", "stale", h)
	seed(6, "load", "stale", h)
	seed(6, "bv_pow_only", "stale", h)
	// a 'none' challenge must NOT appear in any axis row.
	seed(5, "serve", "none", h)
	seed(5, "load", "none", h)

	since := "date_created > '" + at(100) + "'"
	scan, err := forceReasonFunnelRowsScan(ctx, d, "", nil, since)
	if err != nil {
		t.Fatal(err)
	}
	if err := AggregateHourly(ctx, d, nil); err != nil {
		t.Fatal(err)
	}
	defer hourlyReady.Store(false)
	agg, err := forceReasonFunnelRowsAgg(ctx, d, 100)
	if err != nil {
		t.Fatal(err)
	}

	// header, stale, asn, geo -- all non-empty here -- in that fixed order on both paths.
	if len(scan) != 4 || len(agg) != 4 {
		t.Fatalf("row counts: scan=%d agg=%d (want 4 each)", len(scan), len(agg))
	}
	for i := range scan {
		s, a := scan[i], agg[i]
		if s.Verdict != a.Verdict {
			t.Errorf("[%d] verdict scan=%q agg=%q", i, s.Verdict, a.Verdict)
		}
		if s.Serve != a.Serve || s.Load != a.Load || s.Captcha != a.Captcha ||
			s.BVPowOnly != a.BVPowOnly || s.BVCaptchaOnly != a.BVCaptchaOnly || s.Silent != a.Silent {
			t.Errorf("[%s] scan != agg:\n scan=%+v\n agg=%+v", s.Verdict, s, a)
		}
	}

	byV := map[string]FunnelRow{}
	for _, r := range scan {
		byV[r.Verdict] = r
	}
	if hdr := byV["header"]; hdr.Serve != 2 || hdr.Load != 2 || hdr.Captcha != 1 || hdr.BVCaptchaOnly != 1 {
		t.Errorf("header row: %+v (want serve=2 load=2 captcha=1 bv_captcha_only=1)", hdr)
	}
	if a := byV["asn"]; a.Serve != 1 || a.Load != 0 || a.Silent != 1 {
		t.Errorf("asn row: %+v (want serve=1 load=0 silent=1)", a)
	}
	if g := byV["geo"]; g.Serve != 1 || g.BVPowOnly != 1 {
		t.Errorf("geo row: %+v (want serve=1 bv_pow_only=1)", g)
	}
	if s := byV["stale"]; s.Serve != 1 || s.Load != 1 || s.BVPowOnly != 1 {
		t.Errorf("stale row: %+v (want serve=1 load=1 bv_pow_only=1)", s)
	}
}
