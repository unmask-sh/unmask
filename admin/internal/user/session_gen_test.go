package user

import (
	"context"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The session generation is what revokes a signed cookie: a password change
// and a suspension advance it, the transparent rehash a login does (same
// password, stronger cost) and re-enabling do not.
func TestSessionGenerationMoves(t *testing.T) {
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: t.TempDir() + "/g.sqlite"})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer d.Close()
	if err := db.Migrate(d); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	r := New(d)
	ctx := context.Background()

	u, err := r.Create(ctx, "alice", "first-password-1", RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if u.SessionGen != 0 {
		t.Fatalf("a new account starts at generation 0, got %d", u.SessionGen)
	}
	gen := func() int64 {
		t.Helper()
		cur, err := r.GetByID(ctx, u.ID)
		if err != nil {
			t.Fatal(err)
		}
		return cur.SessionGen
	}

	if err := r.SetPassword(ctx, u.ID, "second-password-2"); err != nil {
		t.Fatal(err)
	}
	if g := gen(); g != 1 {
		t.Fatalf("after SetPassword: generation %d, want 1", g)
	}
	if err := r.RehashPassword(ctx, u.ID, "second-password-2"); err != nil {
		t.Fatal(err)
	}
	if g := gen(); g != 1 {
		t.Fatalf("after RehashPassword: generation %d, want 1 (the password did not change)", g)
	}
	cur, _ := r.GetByID(ctx, u.ID)
	if err := CheckPassword(cur.PasswordHash, "second-password-2"); err != nil {
		t.Fatalf("the rehashed password no longer checks: %v", err)
	}

	if err := r.SetDisabled(ctx, u.ID, true); err != nil {
		t.Fatal(err)
	}
	if g := gen(); g != 2 {
		t.Fatalf("after a suspension: generation %d, want 2", g)
	}
	if err := r.SetDisabled(ctx, u.ID, false); err != nil {
		t.Fatal(err)
	}
	if g := gen(); g != 2 {
		t.Fatalf("after re-enabling: generation %d, want 2 (sessions from before stay ended)", g)
	}
	if cur, _ := r.GetByID(ctx, u.ID); cur.Disabled {
		t.Fatal("re-enabling did not clear the flag")
	}

	if err := r.SetPassword(ctx, 999999, "nobody-password-9"); err != ErrNotFound {
		t.Fatalf("SetPassword on a missing account: err=%v, want ErrNotFound", err)
	}
}
