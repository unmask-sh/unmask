// migration: apply the schema + idempotently ALTER existing DBs.
//
// Only one public API: Migrate().  Called by both cmdMigrate (= CLI) and
// the setup wizard handler.
package db

import (
	"database/sql"
	"fmt"
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
	if err := ensureHostColumn(conn); err != nil {
		return err
	}
	if err := ensureCookieMinuteKind(conn); err != nil {
		return fmt.Errorf("ensure cookie_minute kind/cnt schema: %w", err)
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
	// numbered migration framework.  Apply the baseline marker + future deltas.
	if err := RunMigrations(conn); err != nil {
		return fmt.Errorf("run numbered migrations: %w", err)
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
--   "pow"              : repeater carrying a 4-seg _bv with djb2 OK
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
    password_hash            VARCHAR(72) NOT NULL,
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
    UNIQUE (ip, ja4)
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
    password_hash            VARCHAR(72) NOT NULL,
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
    PRIMARY KEY (id),
    UNIQUE KEY uk_ip_ja4 (ip, ja4),
    KEY idx_expires (expires_at),
    KEY idx_source  (source)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
`
