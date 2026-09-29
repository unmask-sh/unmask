package user

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// While a schema update holds the database's writes, an audit row and a
// sign-in time wait in memory -- with the time they happened -- instead of
// waiting out the busy timeout on the request and then failing.  Written when
// the lock is free.
func TestAuditAndSignInWaitForTheLock(t *testing.T) {
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: filepath.Join(t.TempDir(), "u.sqlite")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	if err := db.Migrate(d); err != nil {
		t.Fatal(err)
	}
	r := New(d)
	ctx := context.Background()
	u, err := r.CreateWithProfile(ctx, "hana", "test-password-hana", "admin", "", false)
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
	when := time.Now().Add(-time.Minute)
	t0 := time.Now()
	r.Record(ctx, u.ID, "hana", "settings_save", "network", `{"diff":"x"}`)
	r.TouchLastLogin(ctx, u.ID)
	if took := time.Since(t0); took > 200*time.Millisecond {
		t.Errorf("recording took %v under the hold", took)
	}
	if n := rows(); n != 0 {
		t.Fatalf("%d audit rows written while writes were held", n)
	}
	d.HoldWrites(false)
	r.FlushHeld(ctx)
	if n := rows(); n != 1 {
		t.Fatalf("%d audit rows after the hold, want the one kept", n)
	}
	var at time.Time
	if err := d.QueryRow(`SELECT at FROM unmask_user_audit WHERE action = 'settings_save'`).Scan(&at); err != nil {
		t.Fatal(err)
	}
	if at.Before(when) || at.After(time.Now()) {
		t.Errorf("the row is dated %v; it happened just after %v", at, when)
	}
	var last *time.Time
	if err := d.QueryRow(`SELECT last_login FROM unmask_user WHERE id = ?`, u.ID).Scan(&last); err != nil || last == nil {
		t.Errorf("the sign-in time was not written (%v)", err)
	}
	// Written once.
	r.FlushHeld(ctx)
	if n := rows(); n != 1 {
		t.Errorf("a second flush wrote again: %d rows", n)
	}
}
