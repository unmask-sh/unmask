package ban

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestKeptBanSurvivesAFailedWrite: a ban kept through a schema update's hold
// stays kept when its write fails once the hold is over, and is written at
// the next pass.
//
// After a hold the database is busy with what waited for it (the event
// flusher's backlog, the hourly fold), and the kept ban's write can run into
// SQLite's busy timeout.  writeHeld took every ban of the pass off the kept
// list, the failed ones included: the ban was then in neither the table nor
// the list, the next write of the ban file left it out, and nothing was
// going to bring it back.
func TestKeptBanSurvivesAFailedWrite(t *testing.T) {
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
	mgr := New(d, banFile, time.Hour)
	const ip = "203.0.113.77"
	inFile := func() bool {
		b, _ := os.ReadFile(banFile)
		return strings.Contains(string(b), ip+"|")
	}
	rows := func() (n int) {
		t.Helper()
		if err := d.QueryRow(`SELECT COUNT(*) FROM unmask_ban WHERE ip = ?`, ip).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	kept := func() int {
		mgr.mu.Lock()
		defer mgr.mu.Unlock()
		return len(mgr.held)
	}

	// An operator places a ban while a schema update holds the writes.
	d.HoldWrites(true)
	if err := mgr.AddManual(ctx, ip, "", "the operator's ban", "op", "deny", 0); err != nil {
		t.Fatalf("AddManual during the hold: %v", err)
	}
	mgr.settle()
	if !inFile() {
		t.Fatal("the kept ban is not in the file during the hold")
	}
	d.HoldWrites(false)

	// The hold is over, and another writer has SQLite's write lock when the
	// kept ban's turn comes, past the busy timeout.
	c, err := d.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.ExecContext(ctx, `BEGIN IMMEDIATE`); err != nil {
		t.Fatal(err)
	}
	mgr.writeHeld() // the loop's call, on its tick and on a wake
	if _, err := c.ExecContext(ctx, `COMMIT`); err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	if rows() != 0 {
		t.Fatal("the write went through with the lock taken: the test does not stage the failure")
	}
	if kept() != 1 {
		t.Fatalf("after the failed write the kept list holds %d ban(s), want the 1 that was not written", kept())
	}
	if !mgr.IsBanned(ctx, ip, "") {
		t.Error("after the failed write the ban is not enforced")
	}
	mgr.markDirty()
	mgr.settle()
	if !inFile() {
		t.Error("a write of the ban file after the failed write left the ban out")
	}

	// The lock is free again: the loop's next pass writes it.
	mgr.writeHeld()
	mgr.settle()
	if rows() != 1 || kept() != 0 {
		t.Errorf("after the next pass: %d row(s) and %d kept, want 1 and 0", rows(), kept())
	}
	if !inFile() || !mgr.IsBanned(ctx, ip, "") {
		t.Errorf("after the next pass: in the file %v, enforced %v; want both", inFile(), mgr.IsBanned(ctx, ip, ""))
	}
}
