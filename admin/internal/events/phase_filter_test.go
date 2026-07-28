package events

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestPhaseFilterAcceptsGroups: the hunt log's phase filter takes a
// comma-separated list, so the UI can offer the question an operator actually
// brings to it -- "show me everything that passed" -- instead of one concrete
// phase at a time, which means running the query once per phase and merging
// the pages by eye.
func TestPhaseFilterAcceptsGroups(t *testing.T) {
	tmp, _ := os.MkdirTemp("", "phf-*")
	defer os.RemoveAll(tmp)
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: filepath.Join(tmp, "t.db")})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(d); err != nil {
		t.Fatal(err)
	}
	for _, ph := range []string{"serve", "load", "bv_pow_only", "bv_captcha_only", "verify_ng", "abandon"} {
		if _, err := d.Exec(`INSERT INTO unmask_event
			(site,host,scheme,port,ip_address,user_agent,ja4,ja4_verdict,ja4_verdict_id,phase,flags,reload_count,cookie_bv,cookie_br,payload_json,date_created)
			VALUES ('','','',0,x'7f000001','UA','','',0,?,0,0,'','','{}',datetime('now'))`, ph); err != nil {
			t.Fatal(err)
		}
	}
	count := func(filter string) map[string]int {
		t.Helper()
		rows, err := FetchPaged(context.Background(), d, "", "", "", "", filter, "", "", nil, 0, 100, 0)
		if err != nil {
			t.Fatalf("filter %q: %v", filter, err)
		}
		got := map[string]int{}
		for _, r := range rows {
			got[r.Phase]++
		}
		return got
	}

	// A group returns exactly its members.
	passed := count("bv_pow_only,bv_captcha_only,bv_pow_then_captcha,bv_rebind")
	if len(passed) != 2 || passed["bv_pow_only"] != 1 || passed["bv_captcha_only"] != 1 {
		t.Errorf("passed group = %v, want only the two bv_* rows present", passed)
	}
	// A single name still behaves exactly as before.
	if one := count("verify_ng"); len(one) != 1 || one["verify_ng"] != 1 {
		t.Errorf("single phase = %v, want just verify_ng", one)
	}
	// Empty means no filter.
	if all := count(""); len(all) != 6 {
		t.Errorf("no filter returned %d distinct phases, want 6", len(all))
	}
	// An unknown name must narrow to nothing rather than widen to everything --
	// the value arrives from a query string.
	if bad := count("bogus"); len(bad) != 0 {
		t.Errorf("unknown phase returned %v, want no rows", bad)
	}
	// A list mixing valid and invalid keeps only the valid part.
	if mixed := count("bv_pow_only,bogus"); len(mixed) != 1 || mixed["bv_pow_only"] != 1 {
		t.Errorf("mixed list = %v, want just bv_pow_only", mixed)
	}
}
