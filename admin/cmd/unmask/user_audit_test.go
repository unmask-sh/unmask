package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// An account created, promoted, given a new password or deleted with
// `unmask user` is a change the admin's own page records when it is made
// there.  From the shell it wrote nothing; it writes the same actions under
// the name a shell is recorded as.
func TestUserCommandsAreAudited(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "unmask.sqlite")
	cfg := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(cfg, []byte("db:\n  driver: sqlite\n  sqlite_path: "+dbPath+"\nsecret:\n  bv_secret: 0123456789abcdef0123456789abcdef\n  admin_secret: 0123456789abcdef0123456789abcdef\n  captcha_secret_base: 0123456789abcdef0123456789abcdef\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	conn, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := db.Migrate(conn); err != nil {
		t.Fatal(err)
	}

	const pw = "correct-horse-battery-staple"
	steps := []struct {
		run    func() error
		action string
	}{
		{func() error {
			return cmdUserCreate([]string{"-config", cfg, "-role", "viewer", "-password", pw, "alice"})
		}, "user_create"},
		{func() error { return cmdUserSetRole([]string{"-config", cfg, "alice", "admin"}) }, "user_set_role"},
		{func() error { return cmdUserResetPassword([]string{"-config", cfg, "-password", pw + "-2", "alice"}) }, "user_reset_password"},
		{func() error { return cmdUserDelete([]string{"-config", cfg, "alice"}) }, "user_delete"},
	}
	for _, s := range steps {
		if err := s.run(); err != nil {
			t.Fatalf("%s: %v", s.action, err)
		}
	}
	rows, err := conn.Query(`SELECT action, username, COALESCE(target, ''), COALESCE(detail, '') FROM unmask_user_audit ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var got []string
	for rows.Next() {
		var action, username, target, detail string
		if err := rows.Scan(&action, &username, &target, &detail); err != nil {
			t.Fatal(err)
		}
		if username != db.SchemaUpdateByCLI || target != "alice" {
			t.Errorf("%s: recorded under %q for %q, want %q for alice", action, username, target, db.SchemaUpdateByCLI)
		}
		if strings.Contains(detail, pw) {
			t.Errorf("%s: the row carries a password", action)
		}
		got = append(got, action)
	}
	if strings.Join(got, ",") != "user_create,user_set_role,user_reset_password,user_delete" {
		t.Errorf("audit rows: %v", got)
	}
}
