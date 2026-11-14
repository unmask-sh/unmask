package ban

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
	"github.com/unmask-sh/unmask/admin/internal/spill"
)

// A run from the shell holds the database's writes, a ban is placed and
// another lifted meanwhile, and the daemon is stopped before the lock is
// free.  The stop carries both to the data directory, and the next start
// takes them back: the new ban is in force and written, the lifted one stays
// lifted and is deleted (review finding S5: the ban was gone after the
// restart, and a lift came undone).
func TestHeldBansCarriedAcrossAStop(t *testing.T) {
	dir := t.TempDir()
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: filepath.Join(dir, "t.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	if err := db.Migrate(d); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	banFile := filepath.Join(dir, "ban.list")
	count := func(where string, args ...any) int {
		var n int
		if err := d.QueryRow(`SELECT COUNT(*) FROM unmask_ban WHERE `+where, args...).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	mgr := New(d, banFile, time.Hour)
	// A ban written before the hold, to be lifted during it.
	mgr.AddWithSourceAction(ctx, "203.0.113.50", "", SourceManual, "before", "op", "deny")
	var liftID int64
	if err := d.QueryRow(`SELECT id FROM unmask_ban WHERE ip = ?`, "203.0.113.50").Scan(&liftID); err != nil {
		t.Fatalf("the ban to lift: %v", err)
	}

	d.HoldWrites(true)
	mgr.AddWithSourceAction(ctx, "203.0.113.51", "t13d_x", SourceHoneypot, "trap /wp-login.php", "", "deny")
	if err := mgr.Remove(ctx, liftID); err != nil {
		t.Fatalf("lift during the hold: %v", err)
	}
	spillDir := t.TempDir()
	n, err := mgr.SpillHeld(spillDir)
	if err != nil || n != 2 {
		t.Fatalf("SpillHeld = %d, %v; want the kept ban and the lift", n, err)
	}
	fi, err := os.Stat(filepath.Join(spillDir, HeldSpillFile))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("the spill file: %v (%v)", err, fi)
	}

	// The next start, the lock free.
	d.HoldWrites(false)
	mgr2 := New(d, banFile, time.Hour)
	got, err := mgr2.RestoreSpilled(spillDir)
	if err != nil || got != 2 {
		t.Fatalf("RestoreSpilled = %d, %v; want 2", got, err)
	}
	if _, err := os.Stat(filepath.Join(spillDir, HeldSpillFile)); !os.IsNotExist(err) {
		t.Errorf("the spill file is still there")
	}
	if action, _, ok := mgr2.heldMatch("203.0.113.51", "t13d_x"); !ok || action != "deny" {
		t.Errorf("the carried-over ban is not in force before it is written (ok=%v action=%q)", ok, action)
	}
	mgr2.writeHeld()
	if count("ip = ?", "203.0.113.51") != 1 {
		t.Errorf("the carried-over ban was not written")
	}
	if count("id = ?", liftID) != 0 {
		t.Errorf("the carried-over lift was not applied")
	}
}

// What expired while the daemon was down is not brought back.
func TestRestoreSpilledLeavesOutWhatExpired(t *testing.T) {
	dir := t.TempDir()
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: filepath.Join(dir, "t.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	if err := db.Migrate(d); err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	if err := spill.Save(dir, HeldSpillFile, spilledBans{Held: []spilledBan{
		{IP: "203.0.113.60", Source: SourceHoneypot, Action: "deny", Scope: DeriveScope("203.0.113.60", ""), BannedAt: now - 7200, ExpiresAt: now - 3600},
		{IP: "203.0.113.61", Source: SourceHoneypot, Action: "deny", Scope: DeriveScope("203.0.113.61", ""), BannedAt: now - 60, ExpiresAt: now + 3600},
	}}); err != nil {
		t.Fatal(err)
	}
	mgr := New(d, filepath.Join(dir, "ban.list"), time.Hour)
	got, err := mgr.RestoreSpilled(dir)
	if err != nil || got != 1 {
		t.Fatalf("RestoreSpilled = %d, %v; want only the ban still running", got, err)
	}
	if _, _, ok := mgr.heldMatch("203.0.113.60", ""); ok {
		t.Errorf("an expired ban came back")
	}
}
