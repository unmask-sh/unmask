package db

import (
	"path/filepath"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

func emailTestConn(t *testing.T) *DB {
	t.Helper()
	conn, err := Open(settings.DB{Driver: string(DriverSQLite), SQLitePath: filepath.Join(t.TempDir(), "e.sqlite")})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	if err := Migrate(conn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return conn
}

func insertUser(t *testing.T, conn *DB, username, email string, nullEmail bool) error {
	t.Helper()
	if nullEmail {
		_, err := conn.Exec(`INSERT INTO unmask_user (username, password_hash, role, email, created_at) VALUES (?, 'x', 'admin', NULL, 0)`, username)
		return err
	}
	_, err := conn.Exec(`INSERT INTO unmask_user (username, password_hash, role, email, created_at) VALUES (?, 'x', 'admin', ?, 0)`, username, email)
	return err
}

// TestEmailUniqueEnforced: a fresh Migrate creates uk_user_email; duplicate
// non-NULL emails then violate it while NULL emails stay exempt (DB-6).
func TestEmailUniqueEnforced(t *testing.T) {
	conn := emailTestConn(t)
	has, err := hasIndexNamed(conn, "unmask_user", "uk_user_email")
	if err != nil || !has {
		t.Fatalf("expected uk_user_email after fresh migrate (has=%v err=%v)", has, err)
	}
	if err := insertUser(t, conn, "u1", "a@b.com", false); err != nil {
		t.Fatalf("first insert: %v", err)
	}
	if err := insertUser(t, conn, "u2", "a@b.com", false); err == nil {
		t.Error("duplicate non-NULL email should violate UNIQUE")
	}
	// NULL emails are exempt: multiple allowed.
	if err := insertUser(t, conn, "n1", "", true); err != nil {
		t.Fatalf("first NULL-email insert: %v", err)
	}
	if err := insertUser(t, conn, "n2", "", true); err != nil {
		t.Errorf("second NULL-email insert should be allowed: %v", err)
	}
}

// TestEmailUniqueSkipsOnDuplicates: when duplicates already exist the guard must
// SKIP (no error, index not created) rather than fail startup (DB-6).
func TestEmailUniqueSkipsOnDuplicates(t *testing.T) {
	conn := emailTestConn(t)
	// Drop the index the fresh migrate created, seed duplicate emails, then
	// re-run the guard.
	if _, err := conn.Exec(`DROP INDEX uk_user_email`); err != nil {
		t.Fatalf("drop index: %v", err)
	}
	if err := insertUser(t, conn, "d1", "dup@x.com", false); err != nil {
		t.Fatalf("seed d1: %v", err)
	}
	if err := insertUser(t, conn, "d2", "dup@x.com", false); err != nil {
		t.Fatalf("seed d2 (no index now): %v", err)
	}
	if err := ensureUserEmailUnique(conn); err != nil {
		t.Fatalf("ensureUserEmailUnique should not error on dupes: %v", err)
	}
	has, err := hasIndexNamed(conn, "unmask_user", "uk_user_email")
	if err != nil {
		t.Fatalf("introspect: %v", err)
	}
	if has {
		t.Error("index should NOT be created while duplicates exist")
	}
}

// TestEmailUniqueNormalizesEmpty: empty-string emails are normalized to NULL so
// multiple "no email" accounts coexist and don't block the index (DB-6).
func TestEmailUniqueNormalizesEmpty(t *testing.T) {
	conn := emailTestConn(t)
	if _, err := conn.Exec(`DROP INDEX uk_user_email`); err != nil {
		t.Fatalf("drop index: %v", err)
	}
	// Two empty-string emails: without normalization these would collide.
	if err := insertUser(t, conn, "e1", "", false); err != nil {
		t.Fatalf("seed e1: %v", err)
	}
	if err := insertUser(t, conn, "e2", "", false); err != nil {
		t.Fatalf("seed e2: %v", err)
	}
	if err := ensureUserEmailUnique(conn); err != nil {
		t.Fatalf("guard should normalize '' -> NULL and succeed: %v", err)
	}
	has, err := hasIndexNamed(conn, "unmask_user", "uk_user_email")
	if err != nil || !has {
		t.Fatalf("index should be created after empties normalized to NULL (has=%v err=%v)", has, err)
	}
}
