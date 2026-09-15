package advisor

import (
	"context"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/events"
)

// The collateral of a fingerprint ban: how many addresses got through the
// challenge with it in the last week, graded none / some / block.
func TestJA4Collateral(t *testing.T) {
	d := newTestDB(t)
	// A herd that never passes: three addresses, serves only.
	for _, ip := range []string{"203.0.113.1", "203.0.113.2", "203.0.113.3"} {
		insertEvent(t, d, ip, "t13d_herd", "serve", "curl/8", "")
	}
	// A shared browser fingerprint: real visitors pass with it.
	for i, ip := range []string{"198.51.100.1", "198.51.100.2", "198.51.100.3"} {
		insertEvent(t, d, ip, "t13d_browser", "serve", "Mozilla/5.0 (iPhone)", "")
		if i < 2 {
			insertEvent(t, d, ip, "t13d_browser", "bv_pow_only", "Mozilla/5.0 (iPhone)", "")
		}
	}
	herd, err := JA4Collateral(context.Background(), d, "t13d_herd")
	if err != nil {
		t.Fatal(err)
	}
	if herd.IPs != 3 || herd.Passes != 0 || herd.PassIPs != 0 || herd.Level != "none" || len(herd.PassUAs) != 0 {
		t.Errorf("herd: %+v", herd)
	}
	br, err := JA4Collateral(context.Background(), d, "t13d_browser")
	if err != nil {
		t.Fatal(err)
	}
	if br.IPs != 3 || br.Passes != 2 || br.PassIPs != 2 || br.Level != "some" || len(br.PassUAs) != 1 || br.PassUAs[0] != "Mozilla/5.0 (iPhone)" {
		t.Errorf("browser: %+v", br)
	}
	// Enough passers and a ban is refused outright.
	for i := 10; i < 10+collateralAckMax; i++ {
		insertEvent(t, d, "198.51.100."+itoa(i), "t13d_common", "bv_captcha_only", "Mozilla/5.0", "")
	}
	common, err := JA4Collateral(context.Background(), d, "t13d_common")
	if err != nil {
		t.Fatal(err)
	}
	if common.PassIPs != collateralAckMax || common.Level != "block" {
		t.Errorf("common: %+v", common)
	}
	if unknown, err := JA4Collateral(context.Background(), d, "t13d_nobody"); err != nil || unknown.Level != "none" || unknown.IPs != 0 {
		t.Errorf("unknown fingerprint: %+v %v", unknown, err)
	}
}

func itoa(i int) string {
	if i < 10 {
		return string(rune('0' + i))
	}
	return itoa(i/10) + string(rune('0'+i%10))
}

// The consultation reads every fingerprint candidate's collateral in one
// grouped pass; it must say what the one-at-a-time read says, fingerprint by
// fingerprint, and carry each one's most common serve verdict.
func TestJA4CollateralManyMatchesSingle(t *testing.T) {
	d := newTestDB(t)
	for _, ip := range []string{"203.0.113.1", "203.0.113.2", "203.0.113.3"} {
		insertEvent(t, d, ip, "t13d_herd", "serve", "curl/8", "")
	}
	for i, ip := range []string{"198.51.100.1", "198.51.100.2", "198.51.100.3"} {
		insertEvent(t, d, ip, "t13d_browser", "serve", "Mozilla/5.0 (iPhone)", "")
		if i < 2 {
			insertEvent(t, d, ip, "t13d_browser", "bv_pow_only", "Mozilla/5.0 (iPhone)", "")
		}
	}
	for i := 10; i < 10+collateralAckMax; i++ {
		insertEvent(t, d, "198.51.100."+itoa(i), "t13d_common", "bv_captcha_only", "Mozilla/5.0", "")
	}
	// Two of the herd's serves carry a verdict, one does not: the majority wins.
	if _, err := d.Exec(`UPDATE unmask_event SET ja4_verdict = 'bot_curl' WHERE ja4 = 't13d_herd' AND ip_address <> ?`, events.PackIP("203.0.113.3")); err != nil {
		t.Fatal(err)
	}
	ja4s := []string{"t13d_herd", "t13d_browser", "t13d_common", "t13d_nobody", "t13d_herd", ""}
	many, err := JA4CollateralMany(context.Background(), d, ja4s)
	if err != nil {
		t.Fatal(err)
	}
	if len(many) != 4 {
		t.Fatalf("want 4 fingerprints (duplicates and blanks dropped), got %d: %v", len(many), many)
	}
	for _, j := range []string{"t13d_herd", "t13d_browser", "t13d_common", "t13d_nobody"} {
		one, err := JA4Collateral(context.Background(), d, j)
		if err != nil {
			t.Fatal(err)
		}
		got, ok := many[j]
		if !ok {
			t.Fatalf("%s missing from the grouped read", j)
		}
		if got.IPs != one.IPs || got.Passes != one.Passes || got.PassIPs != one.PassIPs || got.Level != one.Level || got.Verdict != one.Verdict {
			t.Errorf("%s: grouped %+v, single %+v", j, got, one)
		}
		if got.JA4 != j || got.Days != collateralDays {
			t.Errorf("%s: identity %+v", j, got)
		}
	}
	if many["t13d_herd"].Verdict != "bot_curl" || many["t13d_browser"].Verdict != "" {
		t.Errorf("verdicts: herd %q browser %q", many["t13d_herd"].Verdict, many["t13d_browser"].Verdict)
	}
	if many["t13d_common"].Level != "block" || many["t13d_nobody"].Level != "none" || many["t13d_browser"].Level != "some" {
		t.Errorf("levels: %v", many)
	}
	if empty, err := JA4CollateralMany(context.Background(), d, nil); err != nil || len(empty) != 0 {
		t.Errorf("no fingerprints: %v %v", empty, err)
	}
}

// The collateral reads are pinned to the fingerprint index (migration 0032).
// INDEXED BY is a requirement, not a hint: if the index is ever dropped from
// the schema the query fails outright rather than quietly walking the date
// index across the whole retention window, which is what this read cost
// before the index existed.
func TestCollateralUsesTheFingerprintIndex(t *testing.T) {
	d := newTestDB(t)
	var name string
	if err := d.QueryRow(`SELECT name FROM sqlite_master WHERE type='index' AND name='idx_unmask_event_ja4_date'`).Scan(&name); err != nil {
		t.Fatalf("migration 0032 must create the fingerprint index: %v", err)
	}
	insertEvent(t, d, "203.0.113.7", "t13d_idx", "serve", "curl/8", "")
	insertEvent(t, d, "203.0.113.7", "t13d_idx", "bv_pow_only", "curl/8", "")
	// Both readers must run against it -- the dialog's single read and the
	// consultation's grouped one.
	one, err := JA4Collateral(context.Background(), d, "t13d_idx")
	if err != nil {
		t.Fatal(err)
	}
	many, err := JA4CollateralMany(context.Background(), d, []string{"t13d_idx"})
	if err != nil {
		t.Fatal(err)
	}
	if one.PassIPs != 1 || many["t13d_idx"].PassIPs != 1 || one.IPs != many["t13d_idx"].IPs {
		t.Errorf("single %+v grouped %+v", one, many["t13d_idx"])
	}
	// The planner actually picks it: EXPLAIN QUERY PLAN names the index.
	var id, parent, notused int
	var detail string
	rows, err := d.Query(`EXPLAIN QUERY PLAN SELECT COUNT(*) FROM unmask_event INDEXED BY idx_unmask_event_ja4_date
	    WHERE date_created > datetime('now','-7 days') AND ja4 = 't13d_idx'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	seen := false
	for rows.Next() {
		if err := rows.Scan(&id, &parent, &notused, &detail); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(detail, "idx_unmask_event_ja4_date") {
			seen = true
		}
	}
	if !seen {
		t.Error("the plan does not use the fingerprint index")
	}
}
