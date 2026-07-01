package db

import (
	"context"
	"testing"
)

// The rebind cap is one conditional UPDATE with CASE arithmetic plus an
// upsert, written once with shared SQL and a per-dialect INSERT branch --
// exactly the raw-SQL class the sqlite unit tests can't vouch for on MariaDB
// (ON DUPLICATE KEY vs ON CONFLICT, backtick-quoted `count`).  Docker-gated
// like the other TestMariaDB_* smoke tests: `make test-mariadb` runs it,
// without UNMASK_TEST_MARIADB_HOST it skips.
func TestMariaDB_RebindAllow(t *testing.T) {
	conn, err := Open(mariadbSettingsFromEnv(t))
	if err != nil {
		t.Fatalf("open mariadb: %v", err)
	}
	defer conn.Close()
	if err := Migrate(conn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	ctx := context.Background()
	if _, err := conn.ExecContext(ctx,
		"DELETE FROM unmask_rebind_lineage WHERE lineage LIKE 'mdbt-%'"); err != nil {
		t.Fatalf("cleanup: %v", err)
	}

	now := int64(1_700_000_000)
	// Lifetime cap of 2: two pass, the third is refused.
	for i := 0; i < 2; i++ {
		ok, err := RebindAllow(ctx, conn, "mdbt-life", "example.com", 2, 10, now+int64(i))
		if err != nil || !ok {
			t.Fatalf("rebind #%d should pass (ok=%v err=%v)", i+1, ok, err)
		}
	}
	if ok, err := RebindAllow(ctx, conn, "mdbt-life", "example.com", 2, 10, now+5); ok || err != nil {
		t.Fatalf("rebind #3 past the lifetime cap should be refused (ok=%v err=%v)", ok, err)
	}

	// Hourly window of 1: one passes, the next in-window is refused, a fresh
	// window an hour later passes again (CASE branch on both drivers).
	if ok, _ := RebindAllow(ctx, conn, "mdbt-rate", "example.com", 10, 1, now); !ok {
		t.Fatal("first windowed rebind should pass")
	}
	if ok, _ := RebindAllow(ctx, conn, "mdbt-rate", "example.com", 10, 1, now+30); ok {
		t.Fatal("second rebind in the same window should be refused")
	}
	if ok, _ := RebindAllow(ctx, conn, "mdbt-rate", "example.com", 10, 1, now+3601); !ok {
		t.Fatal("first rebind of the next window should pass")
	}
}

// TestMariaDB_BanUniqueScopeMigration: DB-3 — verify on real MariaDB that an old
// unmask_ban with UNIQUE(ip,ja4) migrates to UNIQUE(ip,ja4,scope) with rows
// preserved and is idempotent.  Exercises the MariaDB information_schema
// detection + rename/copy path the sqlite unit test can't cover.  Docker-gated.
func TestMariaDB_BanUniqueScopeMigration(t *testing.T) {
	conn, err := Open(mariadbSettingsFromEnv(t))
	if err != nil {
		t.Fatalf("open mariadb: %v", err)
	}
	defer conn.Close()
	ctx := context.Background()
	for _, q := range []string{
		`DROP TABLE IF EXISTS unmask_ban_preuq`,
		`DROP TABLE IF EXISTS unmask_ban`,
		`CREATE TABLE unmask_ban (
			id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
			ip VARCHAR(64) NOT NULL, ja4 VARCHAR(40) NOT NULL,
			source VARCHAR(32) NOT NULL, reason VARCHAR(255),
			banned_at BIGINT NOT NULL, expires_at BIGINT NOT NULL DEFAULT 0,
			banned_by VARCHAR(64), action VARCHAR(32) NOT NULL DEFAULT '',
			scope VARCHAR(16) NOT NULL DEFAULT 'ip_ja4',
			PRIMARY KEY (id), UNIQUE KEY uk_ip_ja4 (ip, ja4),
			KEY idx_expires (expires_at), KEY idx_source (source)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
		`INSERT INTO unmask_ban (ip, ja4, source, banned_at, scope) VALUES ('1.2.3.4','jx','honeypot',1,'ip_ja4')`,
	} {
		if _, err := conn.ExecContext(ctx, q); err != nil {
			t.Fatalf("setup %q: %v", q, err)
		}
	}

	if has, err := banUniqueHasScope(conn); err != nil || has {
		t.Fatalf("pre-migration banUniqueHasScope = %v (err %v), want false", has, err)
	}
	if err := Migrate(conn); err != nil {
		t.Fatalf("migrate (old->new): %v", err)
	}
	if has, err := banUniqueHasScope(conn); err != nil || !has {
		t.Fatalf("post-migration banUniqueHasScope = %v (err %v), want true", has, err)
	}
	var n int
	if err := conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM unmask_ban`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("preserved rows = %d (err %v), want 1", n, err)
	}
	if _, err := conn.ExecContext(ctx,
		`INSERT INTO unmask_ban (ip, ja4, source, banned_at, scope) VALUES ('1.2.3.4','jx','manual',1,'ja4_only')`); err != nil {
		t.Fatalf("scope-aware insert after migration: %v", err)
	}
	if err := Migrate(conn); err != nil {
		t.Fatalf("migrate re-run: %v", err)
	}
	if err := conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM unmask_ban WHERE ip='1.2.3.4' AND ja4='jx'`).Scan(&n); err != nil || n != 2 {
		t.Fatalf("rows after re-run = %d (err %v), want 2", n, err)
	}
	_, _ = conn.ExecContext(ctx, `DROP TABLE IF EXISTS unmask_ban_preuq`)
}
