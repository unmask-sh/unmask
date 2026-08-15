package events

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestAbandonPassedAfterWindow: a departure row records whether the same
// address got IN inside the next 30 seconds -- not whether it made another
// request.
//
// The window was always right; the predicate was not.  Counting any later
// event marked a bot that was challenged again seconds later as having stayed
// on the site, which is the reassuring answer about the client type that
// abandons most.  Only a pass (bv_*) says the gate opened, and a rejected
// rebind is not one.
func TestAbandonPassedAfterWindow(t *testing.T) {
	tmp, _ := os.MkdirTemp("", "ret-*")
	defer os.RemoveAll(tmp)
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: filepath.Join(tmp, "t.db")})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(d); err != nil {
		t.Fatal(err)
	}
	ins := func(ip []byte, phase, when string) {
		t.Helper()
		if _, err := d.Exec(`INSERT INTO unmask_event
			(site,host,scheme,port,ip_address,user_agent,ja4,ja4_verdict,ja4_verdict_id,phase,flags,reload_count,cookie_bv,cookie_br,payload_json,date_created)
			VALUES ('','','',0,?,'UA','','',0,?,0,0,'','','{}',?)`, ip, phase, when); err != nil {
			t.Fatal(err)
		}
	}
	entered := []byte{10, 0, 0, 1}
	late := []byte{10, 0, 0, 2}
	other := []byte{10, 0, 0, 3}
	looper := []byte{10, 0, 0, 4}
	rejected := []byte{10, 0, 0, 5}
	ins(entered, "abandon", "2026-07-28 10:00:00.000")
	ins(entered, "bv_pow_only", "2026-07-28 10:00:12.000") // got in, inside the window
	ins(late, "abandon", "2026-07-28 10:00:00.000")
	ins(late, "bv_pow_only", "2026-07-28 10:05:00.000") // got in, but outside it
	// A different client's traffic in the window must not count for anyone else.
	ins(other, "bv_pow_only", "2026-07-28 10:00:05.000")
	// The production shape: challenged again seconds later, never let in.
	ins(looper, "abandon", "2026-07-28 10:00:00.000")
	ins(looper, "serve", "2026-07-28 10:00:03.000")
	ins(looper, "captcha", "2026-07-28 10:00:04.000")
	// A refused rebind is not entry.
	ins(rejected, "abandon", "2026-07-28 10:00:00.000")
	ins(rejected, "bv_rebind_reject", "2026-07-28 10:00:05.000")

	rows, err := FetchPaged(context.Background(), d, "", "", "", "", "", "", "", nil, 0, 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]int{}
	for _, r := range rows {
		if r.Phase == "abandon" {
			got[r.IP] = r.PassedAfter
		}
		if r.Phase != "abandon" && r.PassedAfter != 0 {
			t.Errorf("%s row (phase=%s) must not carry a PassedAfter count", r.IP, r.Phase)
		}
	}
	if got["10.0.0.1"] != 1 {
		t.Errorf("an address that passed within 30s: PassedAfter=%d, want 1", got["10.0.0.1"])
	}
	if got["10.0.0.2"] != 0 {
		t.Errorf("an address that passed minutes later: PassedAfter=%d, want 0", got["10.0.0.2"])
	}
	if got["10.0.0.4"] != 0 {
		t.Errorf("an address merely challenged again: PassedAfter=%d, want 0", got["10.0.0.4"])
	}
	if got["10.0.0.5"] != 0 {
		t.Errorf("a refused rebind counted as entry: PassedAfter=%d, want 0", got["10.0.0.5"])
	}
}
