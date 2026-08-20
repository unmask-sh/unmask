package dashboard

import (
	"context"
	"testing"
	"time"
)

// TestFunnel_NoSignalRowsSinkToBottom pins two funnel-order facts.  "(none)"
// (the no-verdict bucket -- current versions record a rule miss as NULL) reads
// last among the verdict rows no matter what extra verdicts the window
// observed; without that, verdicts first seen in the DB (user extra rules,
// auto hunt_* rules) append after the fixed preset list and strand "(none)"
// mid-table.  And "ok" claims no fixed seat: nothing records it any more, so
// a fresh install's funnel simply has no such row -- legacy data that still
// holds 'ok' rides as an ordinary observed verdict instead.
func TestFunnel_NoSignalRowsSinkToBottom(t *testing.T) {
	d := iwTestDB(t)
	ctx := context.Background()
	when := time.Now().Add(-1 * time.Hour).UTC().Format("2006-01-02 15:04:05")
	seed := func(ipn byte, verdict any) {
		if _, err := d.ExecContext(ctx, `INSERT INTO unmask_event
			(site,host,scheme,port,ip_address,user_agent,ja4,ja4_verdict,ja4_verdict_id,phase,flags,reload_count,cookie_bv,cookie_br,payload_json,date_created)
			VALUES ('','','',0,?,'UA','',?,0,'serve',0,0,'','','{}',?)`,
			[]byte{10, 0, 0, ipn}, verdict, when); err != nil {
			t.Fatal(err)
		}
	}
	seed(1, "bot_curl")  // a preset-style named verdict
	seed(2, "hunt_zzzz") // an extra verdict unknown to the fixed list
	seed(3, nil)         // NULL ja4_verdict -> the "(none)" row

	rows, err := funnelScan(ctx, d, "", nil, 24, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	pos := map[string]int{}
	for i, r := range rows {
		pos[r.Verdict] = i
	}
	if i, found := pos["ok"]; found {
		t.Errorf("an 'ok' row appeared at %d with no 'ok' in the data; it lost its fixed seat", i)
	}
	for _, v := range []string{"hunt_zzzz", "(none)", "TOTAL"} {
		if _, found := pos[v]; !found {
			t.Fatalf("row %q missing from funnel: %+v", v, rows)
		}
	}
	if pos["hunt_zzzz"] > pos["(none)"] {
		t.Errorf("(none) did not sink below the observed verdict: hunt_zzzz=%d (none)=%d",
			pos["hunt_zzzz"], pos["(none)"])
	}
	if pos["(none)"] != pos["TOTAL"]-1 {
		t.Errorf("(none) is not the last verdict row before TOTAL: (none)=%d TOTAL=%d",
			pos["(none)"], pos["TOTAL"])
	}
}
