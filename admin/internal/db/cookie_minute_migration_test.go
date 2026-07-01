package db

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestApplyCookieMinuteMigrationData_ReRunSafe proves the v1 -> kind/cnt data
// migration cannot double rows when it runs again with the v1 table still
// present.  That is the post-commit / pre-DROP crash window: the rename and the
// DROP are DDL that auto-commits OUTSIDE the copy's transaction on MariaDB, so a
// dropped connection between COMMIT and DROP leaves v1 in place -- and without
// the clear-before-copy guard a re-run would INSERT every row a second time,
// inflating the cookie_minute stats the dashboard aggregates.
func TestApplyCookieMinuteMigrationData_ReRunSafe(t *testing.T) {
	conn, err := Open(settings.DB{Driver: string(DriverSQLite), SQLitePath: filepath.Join(t.TempDir(), "m.sqlite")})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer conn.Close()
	ctx := context.Background()

	exec := func(q string) {
		t.Helper()
		if _, err := conn.ExecContext(ctx, q); err != nil {
			t.Fatalf("exec %q: %v", q, err)
		}
	}
	count := func() int {
		t.Helper()
		var n int
		if err := conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM unmask_cookie_minute`).Scan(&n); err != nil {
			t.Fatalf("count: %v", err)
		}
		return n
	}

	// destination = the new kind/cnt schema.
	exec(`CREATE TABLE unmask_cookie_minute (bucket_min INTEGER NOT NULL, site TEXT NOT NULL, kind TEXT NOT NULL, cnt INTEGER NOT NULL)`)
	mkV1 := func() {
		exec(`CREATE TABLE unmask_cookie_minute_v1 (bucket_min INTEGER, site TEXT, cnt_total INTEGER, cnt_bv INTEGER, cnt_bp INTEGER, cnt_fc INTEGER)`)
		exec(`INSERT INTO unmask_cookie_minute_v1 VALUES (100,'default',10,4,3,2),(101,'shop',5,0,5,0)`)
	}

	// First pass.  Row1 expands to total/captcha/pow/challenge_served (4);
	// row2 (cnt_bv=0, cnt_fc=0) to total/pow (2) -> 6 rows total.
	mkV1()
	if err := ApplyCookieMinuteMigrationData(conn); err != nil {
		t.Fatalf("first migrate: %v", err)
	}
	if got := count(); got != 6 {
		t.Fatalf("after first migrate: want 6 rows, got %d", got)
	}
	if has, _ := hasTable(conn, "unmask_cookie_minute_v1"); has {
		t.Fatal("v1 must be dropped after a successful migrate")
	}

	// Simulate the crash window: the INSERTs committed but v1 lingered (DROP
	// never ran).  Re-create v1 and re-run -- the count must stay at 6, not
	// double to 12.
	mkV1()
	if err := ApplyCookieMinuteMigrationData(conn); err != nil {
		t.Fatalf("re-run migrate: %v", err)
	}
	if got := count(); got != 6 {
		t.Fatalf("re-run doubled rows (idempotency guard failed): want 6, got %d", got)
	}
}
