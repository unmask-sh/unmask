package db

import "testing"

// TestMariaDB_EmailUnique verifies the DB-6 UNIQUE(email) behavior on a live
// MariaDB: a fresh Migrate creates uk_user_email, duplicate non-NULL emails are
// rejected, and NULL emails stay exempt (multiple allowed).  Skips unless
// UNMASK_TEST_MARIADB_HOST is set (= make test-mariadb).  Rows are namespaced
// with an mdb_eu_ prefix and cleaned up so the shared test DB stays tidy.
func TestMariaDB_EmailUnique(t *testing.T) {
	conn, err := Open(mariadbSettingsFromEnv(t))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer conn.Close()
	if err := Migrate(conn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	cleanup := func() { _, _ = conn.Exec(`DELETE FROM unmask_user WHERE username LIKE 'mdb_eu_%'`) }
	cleanup()
	defer cleanup()

	ins := func(username, email string, null bool) error {
		if null {
			_, e := conn.Exec(`INSERT INTO unmask_user (username, password_hash, role, email) VALUES (?, 'x', 'admin', NULL)`, username)
			return e
		}
		_, e := conn.Exec(`INSERT INTO unmask_user (username, password_hash, role, email) VALUES (?, 'x', 'admin', ?)`, username, email)
		return e
	}

	has, err := hasIndexNamed(conn, "unmask_user", "uk_user_email")
	if err != nil || !has {
		t.Fatalf("expected uk_user_email on MariaDB (has=%v err=%v)", has, err)
	}
	if err := ins("mdb_eu_1", "dup@x.com", false); err != nil {
		t.Fatalf("first insert: %v", err)
	}
	if err := ins("mdb_eu_2", "dup@x.com", false); err == nil {
		t.Error("MariaDB: duplicate non-NULL email should violate UNIQUE(email)")
	}
	// NULL emails are exempt: multiple allowed.
	if err := ins("mdb_eu_n1", "", true); err != nil {
		t.Fatalf("first NULL-email insert: %v", err)
	}
	if err := ins("mdb_eu_n2", "", true); err != nil {
		t.Errorf("MariaDB: second NULL-email insert should be allowed: %v", err)
	}
}
