package ban

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestCountIsTheSnapshotsLength: Count answers what the admin took from
// len(Snapshot()) -- the bans in force, all of them or one source's -- and
// keeps answering it during a hold, when a ban kept in memory and a row
// lifted change what Snapshot lists before the table does.
func TestCountIsTheSnapshotsLength(t *testing.T) {
	dir := t.TempDir()
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: filepath.Join(dir, "t.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	if err := db.Migrate(d); err != nil {
		t.Fatal(err)
	}
	mgr := New(d, filepath.Join(dir, "ban.list"), time.Hour)
	ctx := context.Background()
	now := time.Now().Unix()
	insert := func(ip, source string, expiresAt int64) int64 {
		t.Helper()
		res, err := d.Exec(`INSERT INTO unmask_ban (ip, ja4, source, reason, banned_at, expires_at, banned_by, action, scope)
			VALUES (?, '', ?, 'test', ?, ?, '', '', 'ip')`, ip, source, now-60, expiresAt)
		if err != nil {
			t.Fatal(err)
		}
		id, err := res.LastInsertId()
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	insert("203.0.113.1", SourceHoneypot, now+3600)
	lift := insert("203.0.113.2", "community_bans", now+3600)
	insert("203.0.113.3", "community_bans", 0) // no expiry
	insert("203.0.113.4", SourceHoneypot, now-10)
	insert("203.0.113.5", "community_bans", now-10)

	check := func(stage string, all, community int) {
		t.Helper()
		snap := mgr.Snapshot()
		fromSnap := 0
		for _, e := range snap {
			if e.Source == "community_bans" {
				fromSnap++
			}
		}
		if len(snap) != all || fromSnap != community {
			t.Fatalf("%s: the snapshot lists %d bans, %d from community_bans; the test expects %d and %d", stage, len(snap), fromSnap, all, community)
		}
		if got := mgr.Count(""); got != all {
			t.Errorf("%s: Count(\"\") = %d, the snapshot lists %d", stage, got, all)
		}
		if got := mgr.Count("community_bans"); got != community {
			t.Errorf("%s: Count(community_bans) = %d, the snapshot lists %d", stage, got, community)
		}
	}
	check("the table alone", 3, 2)

	d.HoldWrites(true)
	mgr.AddWithSourceAction(ctx, "203.0.113.6", "", SourceHoneypot, "trap /.env", "", "")
	if err := mgr.Remove(ctx, lift); err != nil {
		t.Fatal(err)
	}
	check("during a hold", 3, 1)

	d.HoldWrites(false)
	mgr.writeHeld()
	check("after the hold", 3, 1)
}
