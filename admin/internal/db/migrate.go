// migration: apply the schema + idempotently ALTER existing DBs.
//
// Only one public API: Migrate().  Called by both cmdMigrate (= CLI) and
// the setup wizard handler.
package db

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"strings"
)

// Migrate: apply the schema to a connected DB.  Idempotent.
//
// Order:
//
//  1. legacy ensure* (= v0 -> v1 normalization, idempotent ALTERs)
//  2. schema SQL (= CREATE TABLE IF NOT EXISTS to set up the v1 baseline)
//  3. ApplyCookieMinuteMigrationData (= move data from the v1 old-column format to kind/cnt)
//  4. RunMigrations() (= numbered SQL framework.  v1 baseline marker + v2+ deltas)
//
// To change the schema for a new feature, just add migrations/<driver>/0002_xxx.sql.
// See migrator.go's package doc for details.
//
// Any returned error means at least one step failed.  Callers can return
// it directly without wrapping.
func Migrate(conn *DB) error {
	if err := ensureSiteColumn(conn); err != nil {
		return err
	}
	if err := ensureCookieMinuteFC(conn); err != nil {
		return err
	}
	if err := ensureVerdictIDColumn(conn); err != nil {
		return err
	}
	if err := ensureUserExtras(conn); err != nil {
		return fmt.Errorf("ensure user extras: %w", err)
	}
	if err := ensurePasswordHashWidth(conn); err != nil {
		return fmt.Errorf("ensure password_hash width: %w", err)
	}
	if err := ensureHostColumn(conn); err != nil {
		return err
	}
	if err := ensureCookieMinuteKind(conn); err != nil {
		return fmt.Errorf("ensure cookie_minute kind/cnt schema: %w", err)
	}
	if err := ensureBanScopeColumn(conn); err != nil {
		return err
	}
	if err := ensureBanActionColumn(conn); err != nil {
		return fmt.Errorf("ensure ban action column: %w", err)
	}
	if err := ensureBanUniqueScope(conn); err != nil {
		return fmt.Errorf("ensure ban unique scope: %w", err)
	}
	schema := schemaSQLite
	if conn.Driver == DriverMariaDB {
		schema = schemaMariaDB
	}
	for _, stmt := range splitStatements(schema) {
		s := strings.TrimSpace(stmt)
		if s == "" {
			continue
		}
		if _, err := conn.Exec(s); err != nil {
			return fmt.Errorf("apply schema: %w\n--- stmt ---\n%s", err, s)
		}
	}
	// Move data from the old schema (= already renamed to v1 by ensureCookieMinuteKind).
	if err := ApplyCookieMinuteMigrationData(conn); err != nil {
		return fmt.Errorf("apply cookie_minute v1 -> kind/cnt data migration: %w", err)
	}
	if err := ApplyBanUniqueScopeData(conn); err != nil {
		return fmt.Errorf("apply ban unique-scope data migration: %w", err)
	}
	// DB-6: enforce one account per email.  Runs AFTER the schema CREATE so the
	// table exists on a fresh install; guarded against pre-existing duplicates.
	if err := ensureUserEmailUnique(conn); err != nil {
		return fmt.Errorf("ensure user email unique: %w", err)
	}
	// numbered migration framework.  Apply the baseline marker + future deltas.
	if err := RunMigrations(conn); err != nil {
		return fmt.Errorf("run numbered migrations: %w", err)
	}
	return nil
}

// ensureBanActionColumn: ALTER an old-schema unmask_ban table (= no action
// column) to add the per-row action override.  Empty string = the source's
// default action resolved by settings.BansConfig.  Idempotent + no-op on a
// fresh install where the new schema already includes the column.
func ensureBanActionColumn(conn *DB) error {
	hasTbl, err := hasTable(conn, "unmask_ban")
	if err != nil {
		return fmt.Errorf("introspect table: %w", err)
	}
	if !hasTbl {
		return nil
	}
	hasCol, err := hasColumn(conn, "unmask_ban", "action")
	if err != nil {
		return fmt.Errorf("introspect action column: %w", err)
	}
	if hasCol {
		return nil
	}
	stmt := `ALTER TABLE unmask_ban ADD COLUMN action VARCHAR(32) NOT NULL DEFAULT ''`
	if _, err := conn.Exec(stmt); err != nil {
		return fmt.Errorf("add action column: %w", err)
	}
	return nil
}

// ensureBanScopeColumn: ALTER an old-schema unmask_ban table (= no scope
// column) to add the per-row match scope selector.  Existing rows are
// back-filled by inference: an empty IP becomes ja4_only, an empty JA4
// becomes ip_only, both non-empty stays ip_ja4 (= the legacy default).
// Idempotent + no-op on a fresh install.
func ensureBanScopeColumn(conn *DB) error {
	hasTbl, err := hasTable(conn, "unmask_ban")
	if err != nil {
		return fmt.Errorf("introspect table: %w", err)
	}
	if !hasTbl {
		return nil
	}
	hasCol, err := hasColumn(conn, "unmask_ban", "scope")
	if err != nil {
		return fmt.Errorf("introspect scope column: %w", err)
	}
	if hasCol {
		return nil
	}
	if _, err := conn.Exec(
		`ALTER TABLE unmask_ban ADD COLUMN scope VARCHAR(16) NOT NULL DEFAULT 'ip_ja4'`,
	); err != nil {
		return fmt.Errorf("add scope column: %w", err)
	}
	// Back-fill the inferred scope for legacy rows so the C plugin's
	// scope-aware lookup keeps catching them after the upgrade.  No-op when
	// the back-fill ran already (= subsequent operator edits set scope
	// explicitly via the modal).
	if _, err := conn.Exec(
		`UPDATE unmask_ban SET scope = 'ja4_only' WHERE ip = '' AND ja4 <> '' AND scope = 'ip_ja4'`,
	); err != nil {
		return fmt.Errorf("back-fill ja4_only scope: %w", err)
	}
	if _, err := conn.Exec(
		`UPDATE unmask_ban SET scope = 'ip_only' WHERE ja4 = '' AND ip <> '' AND scope = 'ip_ja4'`,
	); err != nil {
		return fmt.Errorf("back-fill ip_only scope: %w", err)
	}
	return nil
}

// ensureSiteColumn: ALTER an old-schema DB (no site column) to add site.
// Idempotent: no-op if the column is already there.  Also a no-op if the
// table itself doesn't exist (= fresh install).
func ensureSiteColumn(conn *DB) error {
	hasTbl, err := hasTable(conn, "unmask_event")
	if err != nil {
		return fmt.Errorf("introspect table: %w", err)
	}
	if !hasTbl {
		return nil
	}
	hasCol, err := hasColumn(conn, "unmask_event", "site")
	if err != nil {
		return fmt.Errorf("introspect site column: %w", err)
	}
	if hasCol {
		return nil
	}
	stmt := `ALTER TABLE unmask_event ADD COLUMN site VARCHAR(64) NOT NULL DEFAULT 'default'`
	if _, err := conn.Exec(stmt); err != nil {
		return fmt.Errorf("add site column: %w", err)
	}
	idx := `CREATE INDEX `
	if conn.Driver == DriverSQLite {
		idx += `IF NOT EXISTS idx_unmask_event_site ON unmask_event(site, date_created)`
	} else {
		idx += `idx_site ON unmask_event(site, date_created)`
	}
	if _, err := conn.Exec(idx); err != nil {
		// SQLite's IF NOT EXISTS swallows duplicate-index errors; MariaDB
		// does not, so just warn.
		fmt.Fprintf(os.Stderr, "warning: index create skipped: %v\n", err)
	}
	return nil
}

// ensureVerdictIDColumn: idempotently add the ja4_verdict_id column to
// the existing unmask_event table.  Core of ID-based linking (= rename-
// safe binding).
//
// Column: nullable INTEGER.  Holds the preset rule's ID (= 1-99 built-
// in / 100+ extra).  Verdicts that didn't match a preset on the nginx
// side (= ja4_verdict is 'ok' / ” / unknown) stay NULL.  The
// ja4_verdict (= name) column is still written in parallel.  Display
// layer prefers ID and falls back to name.
//
// No-op when the table itself doesn't exist (= it'll be created later
// with the column included).
func ensureVerdictIDColumn(conn *DB) error {
	hasTbl, err := hasTable(conn, "unmask_event")
	if err != nil {
		return fmt.Errorf("introspect unmask_event: %w", err)
	}
	if !hasTbl {
		return nil
	}
	hasCol, err := hasColumn(conn, "unmask_event", "ja4_verdict_id")
	if err != nil {
		return fmt.Errorf("introspect ja4_verdict_id: %w", err)
	}
	if hasCol {
		return nil
	}
	stmt := `ALTER TABLE unmask_event ADD COLUMN ja4_verdict_id INTEGER`
	if conn.Driver == DriverMariaDB {
		stmt = `ALTER TABLE unmask_event ADD COLUMN ja4_verdict_id INT NULL`
	}
	if _, err := conn.Exec(stmt); err != nil {
		return fmt.Errorf("add ja4_verdict_id column: %w", err)
	}
	idx := `CREATE INDEX `
	if conn.Driver == DriverSQLite {
		idx += `IF NOT EXISTS idx_unmask_event_verdict_id ON unmask_event(ja4_verdict_id, date_created)`
	} else {
		idx += `idx_verdict_id ON unmask_event(ja4_verdict_id, date_created)`
	}
	if _, err := conn.Exec(idx); err != nil {
		fmt.Fprintf(os.Stderr, "warning: idx_verdict_id create skipped: %v\n", err)
	}
	return nil
}

// ensureUserExtras: idempotently add four SMTP / auth-extension columns
// to the existing unmask_user table.
//   - email                  : for notifications / password reset.  NULL OK.
//   - alert_opt_out          : 1 means don't receive alert mail. default 0.
//   - reset_token            : password reset link token (= 64-byte hex).
//   - reset_token_expires_at : token expiry as unix sec.  Expired tokens are invalid.
//
// No-op when the table itself doesn't exist (= it'll be created later
// with every column included).
func ensureUserExtras(conn *DB) error {
	hasTbl, err := hasTable(conn, "unmask_user")
	if err != nil {
		return fmt.Errorf("introspect unmask_user: %w", err)
	}
	if !hasTbl {
		return nil
	}
	cols := []struct {
		name string
		ddl  string
	}{
		{"email", "ALTER TABLE unmask_user ADD COLUMN email VARCHAR(255)"},
		{"alert_opt_out", "ALTER TABLE unmask_user ADD COLUMN alert_opt_out INTEGER NOT NULL DEFAULT 0"},
		{"reset_token", "ALTER TABLE unmask_user ADD COLUMN reset_token VARCHAR(64)"},
		{"reset_token_expires_at", "ALTER TABLE unmask_user ADD COLUMN reset_token_expires_at INTEGER"},
	}
	for _, c := range cols {
		hasCol, err := hasColumn(conn, "unmask_user", c.name)
		if err != nil {
			return fmt.Errorf("introspect %s: %w", c.name, err)
		}
		if hasCol {
			continue
		}
		if _, err := conn.Exec(c.ddl); err != nil {
			return fmt.Errorf("add %s column: %w", c.name, err)
		}
	}
	return nil
}

// ensurePasswordHashWidth: widen unmask_user.password_hash to 128 chars on
// MariaDB.  The baseline shipped with VARCHAR(72) (= bcrypt era), but the
// admin hashes with argon2id which produces a 97-char PHC string -- on
// MariaDB STRICT_TRANS_TABLES the INSERT errored out (fresh install broken)
// and on relaxed mode the hash was silently truncated (every login failed).
// SQLite ignores VARCHAR length (= the declared type is informational, TEXT
// underneath), so no SQLite branch is needed.  Idempotent: MariaDB MODIFY
// COLUMN on a column already at the target width is a no-op.
func ensurePasswordHashWidth(conn *DB) error {
	if conn.Driver != DriverMariaDB {
		return nil
	}
	hasTbl, err := hasTable(conn, "unmask_user")
	if err != nil {
		return fmt.Errorf("introspect unmask_user: %w", err)
	}
	if !hasTbl {
		return nil
	}
	stmt := `ALTER TABLE unmask_user MODIFY COLUMN password_hash VARCHAR(128) NOT NULL`
	if _, err := conn.Exec(stmt); err != nil {
		return fmt.Errorf("widen password_hash: %w", err)
	}
	return nil
}

// ensureHostColumn: ALTER an old-schema DB (no host column) to add host.
// Idempotent: no-op if it's already there.  Also no-op if the table itself
// doesn't exist (= fresh install).
//
// Used to identify "which machine recorded this row" when multiple hosts
// share the same DB.  The default value 'default' covers two cases: a
// single-host setup (= existing installs, for compatibility), and the
// fallback when host_id is unset.  At startup `os.Hostname()` normally
// resolves and gets inserted.
func ensureHostColumn(conn *DB) error {
	hasTbl, err := hasTable(conn, "unmask_event")
	if err != nil {
		return fmt.Errorf("introspect unmask_event: %w", err)
	}
	if !hasTbl {
		return nil
	}
	hasCol, err := hasColumn(conn, "unmask_event", "host")
	if err != nil {
		return fmt.Errorf("introspect host column: %w", err)
	}
	if hasCol {
		return nil
	}
	stmt := `ALTER TABLE unmask_event ADD COLUMN host VARCHAR(64) NOT NULL DEFAULT 'default'`
	if _, err := conn.Exec(stmt); err != nil {
		return fmt.Errorf("add host column: %w", err)
	}
	idx := `CREATE INDEX `
	if conn.Driver == DriverSQLite {
		idx += `IF NOT EXISTS idx_unmask_event_host ON unmask_event(host, date_created)`
	} else {
		idx += `idx_host ON unmask_event(host, date_created)`
	}
	if _, err := conn.Exec(idx); err != nil {
		fmt.Fprintf(os.Stderr, "warning: idx_host create skipped: %v\n", err)
	}
	return nil
}

// ensureCookieMinuteFC: ADD the cnt_fc column to a table on the old v0.0
// schema (= only cnt_total / cnt_bv / cnt_bp).  For the v0.0 -> v0.1
// migration.
//
// No-op when the table already uses the new schema (= kind/cnt
// normalized) so we don't pollute a fresh table with an unnecessary
// ALTER.  Otherwise an ADD COLUMN against the new table would leave a
// vestigial cnt_fc that subsequent migrations can no longer remove.
func ensureCookieMinuteFC(conn *DB) error {
	hasTbl, err := hasTable(conn, "unmask_cookie_minute")
	if err != nil {
		return fmt.Errorf("introspect cookie_minute: %w", err)
	}
	if !hasTbl {
		return nil
	}
	// New schema (= kind column present) -> the old cnt_fc isn't needed.
	hasKind, err := hasColumn(conn, "unmask_cookie_minute", "kind")
	if err != nil {
		return fmt.Errorf("introspect kind column: %w", err)
	}
	if hasKind {
		return nil
	}
	hasCol, err := hasColumn(conn, "unmask_cookie_minute", "cnt_fc")
	if err != nil {
		return fmt.Errorf("introspect cnt_fc column: %w", err)
	}
	if hasCol {
		return nil
	}
	stmt := `ALTER TABLE unmask_cookie_minute ADD COLUMN cnt_fc INTEGER NOT NULL DEFAULT 0`
	if conn.Driver == DriverMariaDB {
		stmt = `ALTER TABLE unmask_cookie_minute ADD COLUMN cnt_fc INT NOT NULL DEFAULT 0`
	}
	if _, err := conn.Exec(stmt); err != nil {
		return fmt.Errorf("add cnt_fc column: %w", err)
	}
	return nil
}

// ensureCookieMinuteKind: move from the old schema (= 4 columns
// cnt_total / cnt_bv / cnt_bp / cnt_fc) to the normalized schema
// (= (bucket_min, site, kind, cnt)).
//
// Migration strategy:
//   - Rename the old table to unmask_cookie_minute_v1.
//   - The later CREATE TABLE IF NOT EXISTS creates the new schema.
//   - INSERT 4 kind-specific rows per old row (= total / captcha / pow / challenge_served).
//   - Drop the old table.
//
// Idempotent: no-op when the new schema (= kind column) is already present.
func ensureCookieMinuteKind(conn *DB) error {
	hasTbl, err := hasTable(conn, "unmask_cookie_minute")
	if err != nil {
		return fmt.Errorf("introspect: %w", err)
	}
	if !hasTbl {
		return nil
	}
	hasKind, err := hasColumn(conn, "unmask_cookie_minute", "kind")
	if err != nil {
		return fmt.Errorf("introspect kind column: %w", err)
	}
	if hasKind {
		return nil
	}
	// Old schema present -> rename, then migrate the data.
	if _, err := conn.Exec(`ALTER TABLE unmask_cookie_minute RENAME TO unmask_cookie_minute_v1`); err != nil {
		return fmt.Errorf("rename old table: %w", err)
	}
	// The new table is created later by schemaSQLite/schemaMariaDB's
	// CREATE TABLE IF NOT EXISTS.  Data migration happens as a separate
	// step in ApplyCookieMinuteMigrationData() (= after the new table
	// exists).
	return nil
}

// ApplyCookieMinuteMigrationData: split the old data renamed to v1 by
// ensureCookieMinuteKind() into the new schema (= kind/cnt) and INSERT.
// Call this after Migrate()'s schema application.
//
// Old row {bucket_min, site, cnt_total, cnt_bv, cnt_bp, cnt_fc} expands
// into 4 kind-specific rows:
//
//	kind="total"            cnt=cnt_total
//	kind="captcha"          cnt=cnt_bv
//	kind="pow"              cnt=cnt_bp
//	kind="challenge_served" cnt=cnt_fc
//
// Skip cnt=0 (= shrink row count).  After completion, drop the v1 table.
func ApplyCookieMinuteMigrationData(conn *DB) error {
	hasV1, err := hasTable(conn, "unmask_cookie_minute_v1")
	if err != nil || !hasV1 {
		return err
	}
	insertStmt := `INSERT INTO unmask_cookie_minute (bucket_min, site, kind, cnt) VALUES (?, ?, ?, ?)`
	rows, err := conn.Query(`SELECT bucket_min, site, cnt_total, cnt_bv, cnt_bp, cnt_fc FROM unmask_cookie_minute_v1`)
	if err != nil {
		return fmt.Errorf("scan v1: %w", err)
	}
	defer rows.Close()
	tx, err := conn.Begin()
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	// Idempotency guard.  The rename (in ensureCookieMinuteKind) and the DROP
	// below are DDL, which auto-commits OUTSIDE this transaction on MariaDB --
	// so rename/copy/drop can't be one atomic unit.  If a prior run committed
	// these INSERTs but was interrupted before DROP-ing v1 (e.g. a dropped
	// MariaDB connection in that gap), v1 still exists and re-running would
	// double every row.  This runs inside Migrate() at startup, before the
	// daemon serves, and Migrate aborts on any error here -- so a lingering v1
	// means the destination holds at most a partial/duplicate copy and nothing
	// else writes it.  Clear it before recopying so the migration is re-run safe.
	if _, err := tx.Exec(`DELETE FROM unmask_cookie_minute`); err != nil {
		return fmt.Errorf("clear destination before copy: %w", err)
	}
	for rows.Next() {
		var bucketMin int64
		var site string
		var cntTotal, cntBV, cntBP, cntFC int64
		if err := rows.Scan(&bucketMin, &site, &cntTotal, &cntBV, &cntBP, &cntFC); err != nil {
			return fmt.Errorf("scan row: %w", err)
		}
		for _, kv := range []struct {
			kind string
			cnt  int64
		}{
			{"total", cntTotal},
			{"captcha", cntBV},
			{"pow", cntBP},
			{"challenge_served", cntFC},
		} {
			if kv.cnt == 0 {
				continue
			}
			if _, err := tx.Exec(insertStmt, bucketMin, site, kv.kind, kv.cnt); err != nil {
				return fmt.Errorf("insert kind=%s: %w", kv.kind, err)
			}
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	committed = true
	if _, err := conn.Exec(`DROP TABLE unmask_cookie_minute_v1`); err != nil {
		return fmt.Errorf("drop v1: %w", err)
	}
	return nil
}

// banUniqueHasScope reports whether unmask_ban's UNIQUE key already covers the
// scope column (= the DB-3 migration has run).  Driver-specific introspection:
// the old key is UNIQUE(ip, ja4), the new one UNIQUE(ip, ja4, scope).
func banUniqueHasScope(conn *DB) (bool, error) {
	if conn.Driver == DriverMariaDB {
		var n int
		err := conn.QueryRow(`SELECT COUNT(*) FROM information_schema.STATISTICS
			WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'unmask_ban'
			  AND NON_UNIQUE = 0 AND COLUMN_NAME = 'scope'`).Scan(&n)
		return n > 0, err
	}
	// sqlite: scan every UNIQUE index for a scope column.
	rows, err := conn.Query(`PRAGMA index_list(unmask_ban)`)
	if err != nil {
		return false, err
	}
	var uniques []string
	for rows.Next() {
		// cols: seq, name, unique, origin, partial
		var seq, uniq, partial int
		var name, origin string
		if err := rows.Scan(&seq, &name, &uniq, &origin, &partial); err != nil {
			rows.Close()
			return false, err
		}
		if uniq == 1 {
			uniques = append(uniques, name)
		}
	}
	rows.Close()
	for _, name := range uniques {
		ir, err := conn.Query(`PRAGMA index_info("` + name + `")`)
		if err != nil {
			return false, err
		}
		for ir.Next() {
			// cols: seqno, cid, name
			var seqno, cid int
			var col sql.NullString
			if err := ir.Scan(&seqno, &cid, &col); err != nil {
				ir.Close()
				return false, err
			}
			if col.String == "scope" {
				ir.Close()
				return true, nil
			}
		}
		ir.Close()
	}
	return false, nil
}

// hasIndexNamed reports whether an index of the given name exists on table.
func hasIndexNamed(conn *DB, table, indexName string) (bool, error) {
	if conn.Driver == DriverMariaDB {
		var n int
		err := conn.QueryRow(`SELECT COUNT(*) FROM information_schema.STATISTICS
			WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND INDEX_NAME = ?`,
			table, indexName).Scan(&n)
		return n > 0, err
	}
	// sqlite: PRAGMA can't bind the table name, so build it (table is an internal
	// constant here, never user input).
	rows, err := conn.Query(`PRAGMA index_list("` + table + `")`)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		// cols: seq, name, unique, origin, partial
		var seq, uniq, partial int
		var name, origin string
		if err := rows.Scan(&seq, &name, &uniq, &origin, &partial); err != nil {
			return false, err
		}
		if name == indexName {
			return true, nil
		}
	}
	return false, rows.Err()
}

// ensureUserEmailUnique adds a UNIQUE index on unmask_user.email (DB-6) so two
// accounts can't share an address -- forgot-password would otherwise act on the
// lowest-id match.  GetByEmail already defends with ORDER BY id LIMIT 1; this
// closes it at the schema.  NULL emails are exempt (both SQLite and MariaDB
// allow multiple NULLs in a UNIQUE index) and empty strings are normalized to
// NULL first so "no email" accounts don't collide.  Called after the schema
// CREATE so the table exists on a fresh install (empty = no dupes = index made);
// on an existing table it is guarded -- real duplicates can't be indexed, so it
// logs them and SKIPS rather than failing startup.  Idempotent once the index
// exists.
func ensureUserEmailUnique(conn *DB) error {
	has, err := hasIndexNamed(conn, "unmask_user", "uk_user_email")
	if err != nil {
		return fmt.Errorf("introspect email index: %w", err)
	}
	if has {
		return nil
	}
	if _, err := conn.Exec(`UPDATE unmask_user SET email = NULL WHERE email = ''`); err != nil {
		return fmt.Errorf("normalize empty email: %w", err)
	}
	rows, err := conn.Query(`SELECT email, COUNT(*) FROM unmask_user WHERE email IS NOT NULL GROUP BY email HAVING COUNT(*) > 1`)
	if err != nil {
		return fmt.Errorf("scan duplicate emails: %w", err)
	}
	var dupes []string
	for rows.Next() {
		var email string
		var c int
		if err := rows.Scan(&email, &c); err != nil {
			rows.Close()
			return fmt.Errorf("scan dup row: %w", err)
		}
		dupes = append(dupes, fmt.Sprintf("%q(x%d)", email, c))
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate dup rows: %w", err)
	}
	if len(dupes) > 0 {
		log.Printf("unmask: WARNING: unmask_user has duplicate emails %s — skipping UNIQUE(email) (DB-6). De-duplicate these accounts and restart to enforce it; GetByEmail resolves to the lowest id meanwhile.", strings.Join(dupes, ", "))
		return nil
	}
	if _, err := conn.Exec(`CREATE UNIQUE INDEX uk_user_email ON unmask_user (email)`); err != nil {
		return fmt.Errorf("create unique email index: %w", err)
	}
	return nil
}

// ensureBanUniqueScope migrates an old unmask_ban (UNIQUE(ip, ja4)) to the
// scope-aware key (UNIQUE(ip, ja4, scope), DB-3).  Mirrors ensureCookieMinuteKind:
// rename the old table here; the schema CREATE makes the new one; the rows are
// copied afterward by ApplyBanUniqueScopeData.  No-op on a fresh install (the
// schema creates the new key directly) or when already migrated.  A prior
// interrupted run that left unmask_ban_preuq is handled by the data step.
func ensureBanUniqueScope(conn *DB) error {
	hasTbl, err := hasTable(conn, "unmask_ban")
	if err != nil {
		return fmt.Errorf("introspect: %w", err)
	}
	if !hasTbl {
		return nil
	}
	if pre, err := hasTable(conn, "unmask_ban_preuq"); err != nil {
		return err
	} else if pre {
		return nil // interrupted mid-migration; leave for the data step
	}
	hasScope, err := banUniqueHasScope(conn)
	if err != nil {
		return fmt.Errorf("introspect ban unique: %w", err)
	}
	if hasScope {
		return nil
	}
	if _, err := conn.Exec(`ALTER TABLE unmask_ban RENAME TO unmask_ban_preuq`); err != nil {
		return fmt.Errorf("rename old ban table: %w", err)
	}
	return nil
}

// ApplyBanUniqueScopeData copies rows from the renamed unmask_ban_preuq into the
// new scope-aware unmask_ban and drops the old table.  Re-run safe (clears the
// destination before copying): the rename + drop are DDL that auto-commit
// outside the copy tx on MariaDB, same caveat as ApplyCookieMinuteMigrationData.
// IDs are not preserved -- the BAN UI re-reads rows after startup migration, and
// nothing persists a ban id across a restart.
func ApplyBanUniqueScopeData(conn *DB) error {
	hasOld, err := hasTable(conn, "unmask_ban_preuq")
	if err != nil || !hasOld {
		return err
	}
	rows, err := conn.Query(`SELECT ip, ja4, source, reason, banned_at, expires_at, banned_by, action, scope FROM unmask_ban_preuq`)
	if err != nil {
		return fmt.Errorf("scan preuq: %w", err)
	}
	defer rows.Close()
	tx, err := conn.Begin()
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	if _, err := tx.Exec(`DELETE FROM unmask_ban`); err != nil {
		return fmt.Errorf("clear destination before copy: %w", err)
	}
	ins := `INSERT INTO unmask_ban (ip, ja4, source, reason, banned_at, expires_at, banned_by, action, scope) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
	for rows.Next() {
		var ip, ja4, source, action, scope string
		var reason, bannedBy sql.NullString
		var bannedAt, expiresAt int64
		if err := rows.Scan(&ip, &ja4, &source, &reason, &bannedAt, &expiresAt, &bannedBy, &action, &scope); err != nil {
			return fmt.Errorf("scan row: %w", err)
		}
		if _, err := tx.Exec(ins, ip, ja4, source, reason, bannedAt, expiresAt, bannedBy, action, scope); err != nil {
			return fmt.Errorf("insert: %w", err)
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	committed = true
	if _, err := conn.Exec(`DROP TABLE unmask_ban_preuq`); err != nil {
		return fmt.Errorf("drop preuq: %w", err)
	}
	return nil
}

// BackfillVerdictIDs: for the ID-based linking migration.  Bulk-UPDATE
// rows where unmask_event.ja4_verdict_id IS NULL but ja4_verdict matches
// a known name.  The caller (= main / setup) builds the name -> id map
// from the nginxconf registry and passes it in.
//
// Idempotent.  Rows that already have an id are ignored.  Names not in
// the preset (= ok / unknown etc.) are skipped (= not present in the
// map).  Returns the total number of rows updated.
func BackfillVerdictIDs(conn *DB, nameToID map[string]int) (int64, error) {
	if conn == nil || len(nameToID) == 0 {
		return 0, nil
	}
	hasTbl, err := hasTable(conn, "unmask_event")
	if err != nil {
		return 0, err
	}
	if !hasTbl {
		return 0, nil
	}
	hasCol, err := hasColumn(conn, "unmask_event", "ja4_verdict_id")
	if err != nil {
		return 0, err
	}
	if !hasCol {
		// Migration not yet run.  Migrate() is supposed to be called first, so no-op.
		return 0, nil
	}
	var total int64
	for name, id := range nameToID {
		if id <= 0 || name == "" {
			continue
		}
		res, err := conn.Exec(
			`UPDATE unmask_event SET ja4_verdict_id = ?
			 WHERE ja4_verdict_id IS NULL AND ja4_verdict = ?`, id, name)
		if err != nil {
			return total, fmt.Errorf("backfill %s->%d: %w", name, id, err)
		}
		if n, err := res.RowsAffected(); err == nil {
			total += n
		}
	}
	return total, nil
}

// hasTable: introspect via sqlite_master / INFORMATION_SCHEMA.
func hasTable(conn *DB, table string) (bool, error) {
	if conn.Driver == DriverSQLite {
		row := conn.QueryRow(
			`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name = ?`,
			table)
		var n int
		if err := row.Scan(&n); err != nil {
			return false, err
		}
		return n > 0, nil
	}
	row := conn.QueryRow(
		`SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES
		 WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ?`,
		table)
	var n int
	if err := row.Scan(&n); err != nil {
		return false, err
	}
	return n > 0, nil
}

func hasColumn(conn *DB, table, col string) (bool, error) {
	if conn.Driver == DriverSQLite {
		rows, err := conn.Query(fmt.Sprintf("PRAGMA table_info(%s)", table))
		if err != nil {
			return false, err
		}
		defer rows.Close()
		for rows.Next() {
			var cid int
			var name, typ string
			var notnull, pk int
			var dflt sql.NullString
			if err := rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk); err != nil {
				return false, err
			}
			if name == col {
				return true, nil
			}
		}
		return false, rows.Err()
	}
	row := conn.QueryRow(
		`SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
		 WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND COLUMN_NAME = ?`,
		table, col)
	var n int
	if err := row.Scan(&n); err != nil {
		return false, err
	}
	return n > 0, nil
}

// splitStatements: simple ; splitter.  Drops -- comment lines and blank lines.
func splitStatements(sql string) []string {
	var lines []string
	for _, l := range strings.Split(sql, "\n") {
		t := strings.TrimSpace(l)
		if t == "" || strings.HasPrefix(t, "--") {
			continue
		}
		lines = append(lines, l)
	}
	body := strings.Join(lines, "\n")
	parts := strings.Split(body, ";")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if strings.TrimSpace(p) != "" {
			out = append(out, p)
		}
	}
	return out
}

const schemaSQLite = `
CREATE TABLE IF NOT EXISTS unmask_event (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    site            VARCHAR(64) NOT NULL DEFAULT 'default',
    host            VARCHAR(64) NOT NULL DEFAULT 'default',
    ip_address      BLOB NOT NULL,
    user_agent      VARCHAR(255),
    ja4             VARCHAR(40),
    ja4_verdict     VARCHAR(40),
    ja4_verdict_id  INTEGER,
    phase           VARCHAR(32) NOT NULL,
    flags           INTEGER NOT NULL DEFAULT 0,
    reload_count    INTEGER NOT NULL DEFAULT 0,
    cookie_bv       VARCHAR(80),
    cookie_br       VARCHAR(8),
    payload_json    TEXT,
    date_created    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_unmask_event_date     ON unmask_event(date_created);
CREATE INDEX IF NOT EXISTS idx_unmask_event_ip_date  ON unmask_event(ip_address, date_created);
CREATE INDEX IF NOT EXISTS idx_unmask_event_phase    ON unmask_event(phase, date_created);
CREATE INDEX IF NOT EXISTS idx_unmask_event_verdict     ON unmask_event(ja4_verdict, date_created);
CREATE INDEX IF NOT EXISTS idx_unmask_event_verdict_id  ON unmask_event(ja4_verdict_id, date_created);
CREATE INDEX IF NOT EXISTS idx_unmask_event_site     ON unmask_event(site, date_created);
CREATE INDEX IF NOT EXISTS idx_unmask_event_host     ON unmask_event(host, date_created);

CREATE TABLE IF NOT EXISTS unmask_aggregate (
    bucket_date     DATE NOT NULL,
    bucket_kind     VARCHAR(16) NOT NULL,
    bucket_key      VARCHAR(64) NOT NULL,
    cnt             INTEGER NOT NULL,
    PRIMARY KEY (bucket_date, bucket_kind, bucket_key)
);
CREATE INDEX IF NOT EXISTS idx_unmask_aggregate_date ON unmask_aggregate(bucket_date);

CREATE TABLE IF NOT EXISTS unmask_aggregate_state (
    name        VARCHAR(32) PRIMARY KEY,
    last_id     INTEGER NOT NULL DEFAULT 0,
    updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- unmask_cookie_minute: per (minute, site, kind) aggregation bucket.
-- kind values (= any ASCII string):
--   "total"            : total request count
--   "captcha"          : repeater carrying a 3-seg _bv with HMAC OK
--   "pow"              : repeater carrying a 4-seg _bv with SHA-256 OK
--   "challenge_served" : the request was answered with challenge HTML
--   Any new kind the plugin emits later is recorded as additional rows with no schema change.
CREATE TABLE IF NOT EXISTS unmask_cookie_minute (
    bucket_min  INTEGER NOT NULL,
    site        VARCHAR(64) NOT NULL,
    kind        VARCHAR(32) NOT NULL,
    cnt         INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (bucket_min, site, kind)
);
CREATE INDEX IF NOT EXISTS idx_cookie_minute_site_min
    ON unmask_cookie_minute(site, bucket_min);
CREATE INDEX IF NOT EXISTS idx_cookie_minute_kind_min
    ON unmask_cookie_minute(kind, bucket_min);

CREATE TABLE IF NOT EXISTS unmask_user (
    id                       INTEGER PRIMARY KEY AUTOINCREMENT,
    username                 VARCHAR(64) NOT NULL UNIQUE,
    -- 128 chars holds the argon2id PHC string ($argon2id$v=19$m=65536,t=2,p=1$<22b64>$<43b64> = 97 chars)
    -- with headroom for future params bumps.  72 was a bcrypt-era leftover that
    -- truncated the argon2 hash on MariaDB STRICT installs (= login broken).
    password_hash            VARCHAR(128) NOT NULL,
    role                     VARCHAR(16) NOT NULL,
    email                    VARCHAR(255),
    alert_opt_out            INTEGER NOT NULL DEFAULT 0,
    reset_token              VARCHAR(64),
    reset_token_expires_at   INTEGER,
    created_at               DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_login               DATETIME
);

CREATE TABLE IF NOT EXISTS unmask_user_audit (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER,
    username    VARCHAR(64) NOT NULL,
    action      VARCHAR(64) NOT NULL,
    target      VARCHAR(128),
    detail      TEXT,
    at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_user_audit_at      ON unmask_user_audit(at);
CREATE INDEX IF NOT EXISTS idx_user_audit_user_at ON unmask_user_audit(user_id, at);

CREATE TABLE IF NOT EXISTS unmask_ban (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ip          VARCHAR(64) NOT NULL,
    ja4         VARCHAR(40) NOT NULL,
    source      VARCHAR(32) NOT NULL,
    reason      VARCHAR(255),
    banned_at   INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL DEFAULT 0,
    banned_by   VARCHAR(64),
    action      VARCHAR(32) NOT NULL DEFAULT '',
    scope       VARCHAR(16) NOT NULL DEFAULT 'ip_ja4',
    UNIQUE (ip, ja4, scope)
);
CREATE INDEX IF NOT EXISTS idx_ban_expires ON unmask_ban(expires_at);
CREATE INDEX IF NOT EXISTS idx_ban_source  ON unmask_ban(source);
`

const schemaMariaDB = `
CREATE TABLE IF NOT EXISTS unmask_event (
    id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    site            VARCHAR(64) NOT NULL DEFAULT 'default',
    host            VARCHAR(64) NOT NULL DEFAULT 'default',
    ip_address      VARBINARY(16) NOT NULL,
    user_agent      VARCHAR(255),
    ja4             VARCHAR(40),
    ja4_verdict     VARCHAR(40),
    ja4_verdict_id  INT NULL,
    phase           VARCHAR(32) NOT NULL,
    flags           INT NOT NULL DEFAULT 0,
    reload_count    INT NOT NULL DEFAULT 0,
    cookie_bv       VARCHAR(80),
    cookie_br       VARCHAR(8),
    payload_json    LONGTEXT,
    date_created    DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    PRIMARY KEY (id),
    KEY idx_date         (date_created),
    KEY idx_ip_date      (ip_address, date_created),
    KEY idx_phase        (phase, date_created),
    KEY idx_verdict      (ja4_verdict, date_created),
    KEY idx_verdict_id   (ja4_verdict_id, date_created),
    KEY idx_site         (site, date_created),
    KEY idx_host         (host, date_created)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS unmask_aggregate (
    bucket_date     DATE NOT NULL,
    bucket_kind     VARCHAR(16) NOT NULL,
    bucket_key      VARCHAR(64) NOT NULL,
    cnt             INT NOT NULL,
    PRIMARY KEY (bucket_date, bucket_kind, bucket_key),
    KEY idx_date (bucket_date)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS unmask_aggregate_state (
    name        VARCHAR(32) NOT NULL,
    last_id     BIGINT UNSIGNED NOT NULL DEFAULT 0,
    updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- unmask_cookie_minute: per (minute, site, kind) aggregation bucket.
-- kind values: "total" / "captcha" / "pow" / "challenge_served" / future additions.
-- The plugin can emit new kinds without a schema change (= normalized form).
CREATE TABLE IF NOT EXISTS unmask_cookie_minute (
    bucket_min  BIGINT NOT NULL,
    site        VARCHAR(64) NOT NULL,
    kind        VARCHAR(32) NOT NULL,
    cnt         INT NOT NULL DEFAULT 0,
    PRIMARY KEY (bucket_min, site, kind),
    KEY idx_site_min (site, bucket_min),
    KEY idx_kind_min (kind, bucket_min)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS unmask_user (
    id                       BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    username                 VARCHAR(64) NOT NULL,
    -- 128 chars holds the argon2id PHC string ($argon2id$v=19$m=65536,t=2,p=1$<22b64>$<43b64> = 97 chars)
    -- with headroom for future params bumps.  72 was a bcrypt-era leftover that
    -- truncated the argon2 hash on MariaDB STRICT installs (= login broken).
    password_hash            VARCHAR(128) NOT NULL,
    role                     VARCHAR(16) NOT NULL,
    email                    VARCHAR(255),
    alert_opt_out            TINYINT NOT NULL DEFAULT 0,
    reset_token              VARCHAR(64),
    reset_token_expires_at   BIGINT,
    created_at               DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_login               DATETIME,
    PRIMARY KEY (id),
    UNIQUE KEY uk_username (username)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS unmask_user_audit (
    id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id     BIGINT UNSIGNED,
    username    VARCHAR(64) NOT NULL,
    action      VARCHAR(64) NOT NULL,
    target      VARCHAR(128),
    detail      LONGTEXT,
    at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_at      (at),
    KEY idx_user_at (user_id, at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS unmask_ban (
    id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    ip          VARCHAR(64) NOT NULL,
    ja4         VARCHAR(40) NOT NULL,
    source      VARCHAR(32) NOT NULL,
    reason      VARCHAR(255),
    banned_at   BIGINT NOT NULL,
    expires_at  BIGINT NOT NULL DEFAULT 0,
    banned_by   VARCHAR(64),
    action      VARCHAR(32) NOT NULL DEFAULT '',
    scope       VARCHAR(16) NOT NULL DEFAULT 'ip_ja4',
    PRIMARY KEY (id),
    UNIQUE KEY uk_ip_ja4_scope (ip, ja4, scope),
    KEY idx_expires (expires_at),
    KEY idx_source  (source)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
`
