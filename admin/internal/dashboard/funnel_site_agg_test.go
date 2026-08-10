package dashboard

import (
	"context"
	"testing"
	"time"
)

// A declared site's funnel reads the per-site aggregate twins (fnls/lf0s/srls +
// lvips + frfs) and must return EXACTLY what a raw scan of the same site
// returns -- full rows, in the same order, force-reason and rate_limit
// pseudo-rows included -- so shortening events_retention (which bounds only the
// raw scan) no longer changes a declared site's 30-day funnel.  An UNDECLARED
// site writes no twins, so its aggregate path is empty and Funnel's dispatch
// keeps it on the raw scan.
func TestFunnelAggSite_MatchesScanForDeclaredSite(t *testing.T) {
	d := iwTestDB(t)
	ctx := context.Background()
	at := func(hoursAgo int) string {
		return time.Now().Add(-time.Duration(hoursAgo) * time.Hour).UTC().Format("2006-01-02 15:04:05")
	}
	seed := func(site string, ipn byte, verdict, phase, payload, when string) {
		if _, err := d.ExecContext(ctx, `INSERT INTO unmask_event
			(site,host,scheme,port,ip_address,user_agent,ja4,ja4_verdict,ja4_verdict_id,phase,flags,reload_count,cookie_bv,cookie_br,payload_json,date_created)
			VALUES (?,'','',0,?,'UA','',?,0,?,0,0,'','',?,?)`,
			site, []byte{10, 0, 0, ipn}, verdict, phase, payload, when); err != nil {
			t.Fatal(err)
		}
	}
	h := at(10)
	// declared site a.example: two verdicts through the funnel, a rate-limited
	// serve (drives ServeRL + the rate_limit pseudo-row) and a header-forced
	// chain (drives the force-reason pseudo-row).
	seed("a.example", 1, "ok", "serve", `{}`, h)
	seed("a.example", 1, "ok", "load", `{}`, h)
	seed("a.example", 1, "ok", "bv_pow_only", `{}`, h)
	seed("a.example", 2, "bot_x", "serve", `{}`, h)
	seed("a.example", 2, "bot_x", "load", `{}`, h)
	seed("a.example", 4, "ok", "serve", `{"rl":1}`, h)
	seed("a.example", 5, "ok", "serve", `{"force_reason":"header"}`, h)
	seed("a.example", 5, "ok", "load", `{"force_reason":"header"}`, h)
	// undeclared site b.example: also has traffic (must NOT get a per-site agg).
	seed("b.example", 3, "ok", "serve", `{}`, h)
	seed("b.example", 3, "ok", "load", `{}`, h)

	prev := DefinedSitesFn
	DefinedSitesFn = func() map[string]bool { return map[string]bool{"a.example": true} }
	defer func() { DefinedSitesFn = prev }()

	if err := AggregateHourly(ctx, d, nil); err != nil {
		t.Fatal(err)
	}
	defer hourlyReady.Store(false)

	bots := []string{"bot_x"}
	scan, err := funnelScan(ctx, d, "a.example", nil, 100, bots, nil)
	if err != nil {
		t.Fatal(err)
	}
	agg, err := funnelAgg(ctx, d, "a.example", 100, bots, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Full parity: same rows, same order, every field.  (HLL estimates are
	// exact at this cardinality, and both paths share the row builders.)
	if len(scan) != len(agg) {
		t.Fatalf("row counts differ: scan=%d agg=%d\n scan=%+v\n agg=%+v", len(scan), len(agg), scan, agg)
	}
	for i := range scan {
		if scan[i] != agg[i] {
			t.Errorf("row %d differs:\n scan=%+v\n agg =%+v", i, scan[i], agg[i])
		}
	}
	// And the aggregate genuinely holds the numbers (not silently empty): the
	// rate_limit pseudo-row leads, the header pseudo-row is present, and the ok
	// verdict row carries the rate-limited serve in ServeRL.
	if len(agg) == 0 || agg[0].Verdict != "rate_limit" {
		t.Fatalf("agg should lead with the rate_limit pseudo-row, got %+v", agg)
	}
	var okRow, headerRow FunnelRow
	for _, r := range agg {
		switch r.Verdict {
		case "ok":
			okRow = r
		case "header":
			headerRow = r
		}
	}
	if okRow.Serve != 3 || okRow.ServeRL != 1 || okRow.Load != 2 || okRow.BVPowOnly != 1 {
		t.Errorf("agg ok row: %+v (want serve=3 serve_rl=1 load=2 bv_pow_only=1)", okRow)
	}
	if headerRow.Serve != 1 || headerRow.Load != 1 {
		t.Errorf("agg header pseudo-row: %+v (want serve=1 load=1)", headerRow)
	}

	// Undeclared site: no twins were written, so the aggregate path is empty.
	bAgg, err := funnelAgg(ctx, d, "b.example", 100, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range bAgg {
		if r.Verdict == "ok" && (r.Serve != 0 || r.Load != 0) {
			t.Errorf("undeclared-site agg should be empty (falls back to raw scan via Funnel), got ok row %+v", r)
		}
	}
}
