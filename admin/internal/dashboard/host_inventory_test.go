package dashboard

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

func hiTestDB(t *testing.T) *db.DB {
	t.Helper()
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: filepath.Join(t.TempDir(), "t.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	if err := db.Migrate(d); err != nil {
		t.Fatal(err)
	}
	return d
}

func hiInsert(t *testing.T, d *db.DB, host, ageExpr string) {
	t.Helper()
	if _, err := d.Exec(`INSERT INTO unmask_event
		(site, host, scheme, port, ip_address, user_agent, ja4, ja4_verdict, ja4_verdict_id,
		 phase, flags, reload_count, cookie_bv, cookie_br, payload_json, date_created)
		VALUES ('',?,'',0,x'7f000001','UA','','',0,'serve',0,0,'','','{}',datetime('now',?))`, host, ageExpr); err != nil {
		t.Fatalf("insert: %v", err)
	}
}

// TestHostInventorySingleHostApprox: a single-host DB uses the O(1) id-range
// estimate (flagged approximate), with an accurate last-seen.
func TestHostInventorySingleHostApprox(t *testing.T) {
	d := hiTestDB(t)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		hiInsert(t, d, "h1", "-10 minutes")
	}
	inv, err := HostInventory(ctx, d)
	if err != nil {
		t.Fatal(err)
	}
	if len(inv) != 1 || inv[0].HostID != "h1" {
		t.Fatalf("inventory = %+v, want single host h1", inv)
	}
	if !inv[0].EventsApprox {
		t.Error("single-host count must be flagged approximate")
	}
	if inv[0].Events != 5 { // ids 1..5, MAX-MIN+1 = 5
		t.Errorf("estimate = %d, want 5", inv[0].Events)
	}
	if inv[0].LastSeenTS == 0 {
		t.Error("last-seen must be set")
	}
}

// TestHostInventoryMultiHostExact: multiple hosts get exact per-host counts and
// are ordered most-recently-active first; a retired host keeps its true (old)
// last-seen.
func TestHostInventoryMultiHostExact(t *testing.T) {
	d := hiTestDB(t)
	ctx := context.Background()
	hiInsert(t, d, "old-host", "-90 minutes")
	hiInsert(t, d, "old-host", "-88 minutes")
	hiInsert(t, d, "old-host", "-86 minutes")
	hiInsert(t, d, "live-host", "-1 minutes")

	inv, err := HostInventory(ctx, d)
	if err != nil {
		t.Fatal(err)
	}
	if len(inv) != 2 {
		t.Fatalf("inventory = %+v, want 2 hosts", inv)
	}
	// Most-recently-active first.
	if inv[0].HostID != "live-host" || inv[1].HostID != "old-host" {
		t.Errorf("order = [%s,%s], want [live-host, old-host]", inv[0].HostID, inv[1].HostID)
	}
	byID := map[string]HostInfo{inv[0].HostID: inv[0], inv[1].HostID: inv[1]}
	if byID["old-host"].Events != 3 || byID["old-host"].EventsApprox {
		t.Errorf("old-host = %d approx=%v, want exact 3", byID["old-host"].Events, byID["old-host"].EventsApprox)
	}
	if byID["live-host"].Events != 1 {
		t.Errorf("live-host events = %d, want 1", byID["live-host"].Events)
	}
}
