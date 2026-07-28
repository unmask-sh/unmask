package events

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestAbandonReturnedWindow: a departure row records whether the same client
// came back with anything else inside 30 seconds.  That is the only way to
// separate "pressed Back" from "closed the tab" -- browsers do not expose the
// gesture, and the bfcache hint is structurally false on a no-store challenge
// page -- so the signal has to come from what the server sees next.
func TestAbandonReturnedWindow(t *testing.T) {
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
	stayed := []byte{10, 0, 0, 1}
	gone := []byte{10, 0, 0, 2}
	other := []byte{10, 0, 0, 3}
	ins(stayed, "abandon", "2026-07-28 10:00:00.000")
	ins(stayed, "serve", "2026-07-28 10:00:12.000") // back inside the window
	ins(gone, "abandon", "2026-07-28 10:00:00.000")
	ins(gone, "serve", "2026-07-28 10:05:00.000") // a later visit, outside it
	// A different client's traffic in the window must not count for anyone else.
	ins(other, "serve", "2026-07-28 10:00:05.000")

	rows, err := FetchPaged(context.Background(), d, "", "", "", "", "", "", "", nil, 0, 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]int{}
	for _, r := range rows {
		if r.Phase == "abandon" {
			got[r.IP] = r.Returned
		}
		if r.Phase != "abandon" && r.Returned != 0 {
			t.Errorf("%s row (phase=%s) must not carry a Returned count", r.IP, r.Phase)
		}
	}
	if got["10.0.0.1"] != 1 {
		t.Errorf("a client that came back within 30s: Returned=%d, want 1", got["10.0.0.1"])
	}
	if got["10.0.0.2"] != 0 {
		t.Errorf("a client whose next visit was minutes later: Returned=%d, want 0", got["10.0.0.2"])
	}
}
