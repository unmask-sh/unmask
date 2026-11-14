package user

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The audit rows and sign-in times kept through a hold are carried across a
// stop that comes before the lock is free, and written after the next start.
// A flush that meets the lock keeps them for the next try instead of
// dropping them, and stops trying at the first refusal.
func TestAuditCarriedAcrossAStop(t *testing.T) {
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: filepath.Join(t.TempDir(), "u.sqlite")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	if err := db.Migrate(d); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	r := New(d)
	u, err := r.CreateWithProfile(ctx, "mio", "test-password-mio", "admin", "", false)
	if err != nil {
		t.Fatal(err)
	}
	rows := func() int {
		var n int
		if err := d.QueryRow(`SELECT COUNT(*) FROM unmask_user_audit WHERE action = 'settings_save'`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	d.HoldWrites(true)
	r.Record(ctx, u.ID, "mio", "settings_save", "network", `{"diff":"a"}`)
	r.Record(ctx, u.ID, "mio", "settings_save", "geo", `{"diff":"b"}`)
	r.TouchLastLogin(ctx, u.ID)
	// A flush under the hold writes nothing and loses nothing.
	r.FlushHeld(ctx)
	if n := rows(); n != 0 {
		t.Fatalf("%d rows written under the hold", n)
	}
	dir := t.TempDir()
	n, err := r.SpillHeld(dir)
	if err != nil || n != 3 {
		t.Fatalf("SpillHeld = %d, %v; want the two rows and the sign-in time", n, err)
	}

	// The next start, the lock free.
	d.HoldWrites(false)
	r2 := New(d)
	got, err := r2.RestoreSpilled(dir)
	if err != nil || got != 3 {
		t.Fatalf("RestoreSpilled = %d, %v; want 3", got, err)
	}
	r2.FlushHeld(ctx)
	if n := rows(); n != 2 {
		t.Fatalf("%d of 2 carried-over rows written", n)
	}
	var last *string
	if err := d.QueryRow(`SELECT last_login FROM unmask_user WHERE id = ?`, u.ID).Scan(&last); err != nil || last == nil {
		t.Errorf("the carried-over sign-in time was not written (%v)", err)
	}
}

func TestIsTransientWriteErr(t *testing.T) {
	if !db.IsTransientWriteErr(db.ErrWritesHeld) {
		t.Error("ErrWritesHeld is the lock's")
	}
	if db.IsTransientWriteErr(nil) {
		t.Error("nil is no error")
	}
}
