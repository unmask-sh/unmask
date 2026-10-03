// migrator: numbered embedded migration runner.
//
// Design (= minimal version inspired by zabbix / cacti / golang-migrate):
//
//  1. Numbered SQL files like `0001_xxx.sql` / `0002_xxx.sql` ... live in
//     per-driver dirs (= migrations/sqlite/ / migrations/mariadb/).
//  2. At startup (= via Migrate()), create the schema_migrations table and
//     read the applied versions.
//  3. Existing v0.1 DBs were already legacy-normalized by ensure*, so if
//     schema_migrations is empty AND unmask_event exists, INSERT version=1
//     as the baseline (= run nothing).
//  4. Apply pending SQL by ascending version.  Stop on failure (= don't
//     proceed to subsequent migrations).
//  5. Forward-only.  Downgrade is handled via backup → restore.
//
// Operating procedure when a feature requires a schema change:
//
//	Just add migrations/sqlite/0002_xxx.sql + migrations/mariadb/0002_xxx.sql.
//	Use the same version number on both drivers (= prevents version drift).
//
// # Deferrable migrations
//
// Building an index takes time in proportion to the table, and the daemon
// applies migrations before it listens: on a large events table an upgrade
// used to mean minutes with no daemon (nginx serving fail-open, no challenge,
// no events) that nobody had been told about.  A migration that ONLY creates
// or drops indexes can carry
//
//	-- unmask:deferrable table=unmask_event
//
// and the daemon then leaves it unapplied at startup when building it is
// expected to take longer than MigrateOptions.DeferOver.  The operator applies
// it when it suits them (the admin UI's notice, or `unmask migrate`), and the
// daemon runs without the index in the meantime.
//
// Index-only is what makes leaving it out safe: an index changes how fast a
// read is, never what it returns, so no later migration and no query can
// depend on one being there (see DB.HasIndex for the one place code names an
// index).  TestDeferrableMigrationsAreIndexOnly holds every marked file to it.
//
// Because a deferred migration leaves a gap below later versions, "applied"
// is the SET of recorded versions, not everything up to the highest one.
package db

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"embed"
	"fmt"
	"io/fs"
	"log"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

//go:embed migrations/sqlite/*.sql migrations/mariadb/*.sql
var embeddedMigrations embed.FS

// migrationFS is where the migrations are read from: the embedded files.  A
// variable so a test can put a migration of its own next to them.
var migrationFS fs.FS = embeddedMigrations

// migrationFileRE: extract the version number from the filename.  Fixed 4 digits (= 0001 to 9999).
var migrationFileRE = regexp.MustCompile(`^(\d{4})_.*\.sql$`)

// DefaultDeferOver is how long an index build may be expected to take before
// the daemon leaves it for the operator instead of running it at startup.
const DefaultDeferOver = 20 * time.Second

// Expected index build time per row of the table, as a range.  The build reads
// the table, sorts the keys and writes the index, so it follows the disk far
// more than the CPU.  A database that is small next to the host's memory is
// read from the page cache and builds at the "cached" rates; one that is not
// is read from the disk, where the low figure is a local SSD and the high one
// a slow or busy disk.  A host that has built one records its own rate
// (MaintSchemaRate) and is estimated from that instead.
const (
	indexBuildCachedFast = 5 * time.Microsecond
	indexBuildCachedSlow = 30 * time.Microsecond
	indexBuildDiskFast   = 60 * time.Microsecond
	indexBuildDiskSlow   = 180 * time.Microsecond
)

// indexBuildRates picks the built-in range for this database.
func indexBuildRates(conn *DB) (fast, slow time.Duration) {
	if conn.Driver == DriverSQLite {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		// "Small" is a quarter of the memory this process may use: the
		// table's pages stay cached with room for everything else.
		if sp, err := conn.Space(ctx); err == nil && sp.LiveBytes > 0 {
			if mem := memLimitBytes(); mem > 0 && sp.LiveBytes*4 <= mem {
				return indexBuildCachedFast, indexBuildCachedSlow
			}
		}
	}
	return indexBuildDiskFast, indexBuildDiskSlow
}

// MigrateOptions tunes one pass of the numbered migrations.
type MigrateOptions struct {
	// Defer leaves a deferrable (index-only) migration unapplied when its
	// build is expected to take longer than DeferOver.  The daemon sets it;
	// `unmask migrate` does not, and applies everything.
	Defer bool
	// DeferOver is the threshold for Defer.  0 means DefaultDeferOver; a
	// negative value defers nothing.
	DeferOver time.Duration
	// Logf receives one line per migration applied, a line when a slow one
	// starts and one every 30 seconds while it runs.  nil discards them.
	Logf func(format string, args ...any)
	// ColdCache estimates builds as reads from disk (the slow band), whatever
	// the size of the database and this host's measured rate: for a start
	// that may follow a reboot, when nothing is cached yet.  The container
	// runs its startup pass this way -- its supervisor restarts a daemon that
	// has not come up within 90 seconds, and a build underestimated past that
	// would be killed and begun again at every start.
	ColdCache bool

	// ctx cancels the statements of a schema update (ApplySchemaUpdate); the
	// passes that run at startup are not cancellable and leave it nil.
	ctx context.Context
}

func (o MigrateOptions) context() context.Context {
	if o.ctx != nil {
		return o.ctx
	}
	return context.Background()
}

func (o MigrateOptions) logf(format string, args ...any) {
	if o.Logf != nil {
		o.Logf(format, args...)
	}
}

func (o MigrateOptions) deferOver() time.Duration {
	if o.DeferOver == 0 {
		return DefaultDeferOver
	}
	return o.DeferOver
}

// PendingMigration is a migration this binary carries that the database has
// not applied.
type PendingMigration struct {
	Version int
	Name    string
	// Deferrable: the migration only creates or drops indexes, so the daemon
	// may run without it (see the package doc).
	Deferrable bool
	// Table is the table those indexes are on; Rows its approximate row count
	// (the span of its ids -- a seek, where a COUNT reads the table) and
	// Indexes the ones that are not there yet.  Deferrable migrations only.
	Table   string
	Rows    int64
	Indexes []string
	// EstLow / EstHigh bound the expected build time.  Both zero when there
	// is nothing to build (every index exists, or the table is empty).
	EstLow, EstHigh time.Duration
	// Deferred: this pass left it unapplied (MigrateOptions.Defer).
	Deferred bool
}

// AppliedMigration is one migration a pass applied.
type AppliedMigration struct {
	Name    string
	Elapsed time.Duration
}

// MigrateResult is what one pass of the numbered migrations did.
type MigrateResult struct {
	Applied  []AppliedMigration
	Deferred []PendingMigration
}

// RunMigrations: apply pending SQL migrations in order.  Idempotent.
//
// Intended to be called after Migrate() (= the legacy ensure* path).  Order:
//
//	Migrate()
//	├─ ensure* (= v0 → v1 normalize, idempotent ALTER family)
//	├─ schema SQL (= CREATE TABLE IF NOT EXISTS)
//	├─ ApplyCookieMinuteMigrationData
//	└─ RunMigrations()                     ← new framework.  v1 baseline + v2+ deltas
func RunMigrations(conn *DB) error {
	_, err := RunMigrationsOpts(conn, MigrateOptions{})
	return err
}

// RunMigrationsOpts is RunMigrations with options and a report of what it did.
func RunMigrationsOpts(conn *DB, opt MigrateOptions) (MigrateResult, error) {
	var res MigrateResult
	pending, err := pendingMigrations(conn, opt.ColdCache)
	if err != nil {
		return res, err
	}
	for _, m := range pending {
		if m.estimateErr != nil {
			// An estimate that cannot be made must not stop an upgrade:
			// the migration is then applied where it always was.
			opt.logf("db: %s: cannot estimate the index build (%v); applying it now", m.Name, m.estimateErr)
		}
	}
	plain := make([]PendingMigration, 0, len(pending))
	for _, m := range pending {
		plain = append(plain, m.PendingMigration)
	}
	left := map[int]bool{}
	if opt.Defer {
		for _, m := range LeftForTheOperator(plain, opt.DeferOver) {
			left[m.Version] = true
		}
	}
	for _, m := range pending {
		if left[m.Version] {
			m.Deferred = true
			res.Deferred = append(res.Deferred, m.PendingMigration)
			opt.logf("db: %s left for the operator: %s", m.Name, m.describe())
			continue
		}
		elapsed, err := applyMigration(conn, m, opt)
		if err != nil {
			return res, err
		}
		res.Applied = append(res.Applied, AppliedMigration{Name: m.Name, Elapsed: elapsed})
	}
	return res, nil
}

// LeftForTheOperator picks, out of what is pending, the migrations a daemon
// start with this threshold does not apply (0 = DefaultDeferOver, negative =
// none).  One definition, so that the daemon, `unmask migrate -status` and the
// notice a package install prints cannot disagree about what is waiting.
//
// Once one index migration is left out, the ones behind it wait too: they may
// drop or replace what it builds (0033 does), and running them first would
// apply the pair in the wrong order.  Everything else still runs -- by rule it
// cannot depend on an index.
func LeftForTheOperator(pending []PendingMigration, deferOver time.Duration) []PendingMigration {
	over := MigrateOptions{DeferOver: deferOver}.deferOver()
	var out []PendingMigration
	holding := false
	for _, m := range pending {
		if m.Deferrable && (holding || (over > 0 && m.EstHigh >= over)) {
			holding = true
			out = append(out, m)
		}
	}
	return out
}

// HasSchema reports whether the database holds the base schema at all -- false
// for one that has been created and never migrated.
func HasSchema(conn *DB) (bool, error) { return hasTable(conn, "unmask_event") }

// PendingMigrations lists what this binary would apply to the database, with
// the estimates for the deferrable ones, and changes nothing.  A database that
// does not have the base schema yet reports everything.
//
// Read-only on purpose: the daemon asks every few seconds while an update
// waits, and `unmask migrate -status` / `-notice` and doctor promise to change
// nothing.  It used to create the version table and its baseline row first,
// the way a pass that applies does -- a DDL statement every two seconds on
// MariaDB, for as long as the update waited.
func PendingMigrations(conn *DB) ([]PendingMigration, error) {
	applied, err := appliedVersionsReadOnly(conn)
	if err != nil {
		return nil, err
	}
	pending, err := pendingFrom(conn, applied, false)
	if err != nil {
		return nil, err
	}
	out := make([]PendingMigration, 0, len(pending))
	for _, m := range pending {
		out = append(out, m.PendingMigration)
	}
	return out, nil
}

// pendingEntry pairs what is reported about a pending migration with the file
// it is applied from.
type pendingEntry struct {
	PendingMigration
	path string
	// estimateErr: the build could not be estimated, so the migration is
	// not treated as deferrable (see pendingFrom).
	estimateErr error
}

// describe says what applying the migration involves, for a log line or a
// terminal: "index on unmask_event, about 1200000 rows, estimated 1-4 min".
func (m PendingMigration) describe() string {
	if !m.Deferrable {
		return "schema change"
	}
	if len(m.Indexes) == 0 {
		return "index on " + m.Table + ", nothing left to build"
	}
	return fmt.Sprintf("index on %s, about %d rows, estimated %s", m.Table, m.Rows, EstimateRange(m.EstLow, m.EstHigh))
}

// Describe is describe for callers outside the package.
func (m PendingMigration) Describe() string { return m.describe() }

// EstimateRange words a build-time estimate the way an operator plans by:
// "under 10 s", "20-50 s", "4-10 min".  A range, because the same table builds
// several times slower on a slow disk and a single figure reads as a promise.
func EstimateRange(low, high time.Duration) string {
	if high <= 0 {
		return "no time"
	}
	if high < 10*time.Second {
		return "under 10 s"
	}
	if high < 90*time.Second {
		lo, hi := roundUp(low, 10*time.Second), roundUp(high, 10*time.Second)
		if lo >= hi {
			return fmt.Sprintf("about %d s", int(hi.Seconds()))
		}
		return fmt.Sprintf("%d-%d s", int(lo.Seconds()), int(hi.Seconds()))
	}
	lo, hi := roundUp(low, time.Minute), roundUp(high, time.Minute)
	if lo >= hi {
		return fmt.Sprintf("about %d min", int(hi.Minutes()))
	}
	return fmt.Sprintf("%d-%d min", int(lo.Minutes()), int(hi.Minutes()))
}

func roundUp(d, unit time.Duration) time.Duration {
	if d <= 0 {
		return unit
	}
	return ((d + unit - 1) / unit) * unit
}

// pendingMigrations reads the applied set and returns what is left, estimated.
func pendingMigrations(conn *DB, cold bool) ([]pendingEntry, error) {
	if err := ensureSchemaMigrationsTable(conn); err != nil {
		return nil, fmt.Errorf("ensure schema_migrations: %w", err)
	}
	if err := markBaselineIfNeeded(conn); err != nil {
		return nil, fmt.Errorf("mark baseline: %w", err)
	}
	applied, err := appliedMigrationVersions(conn)
	if err != nil {
		return nil, fmt.Errorf("read applied versions: %w", err)
	}
	return pendingFrom(conn, applied, cold)
}

// appliedVersionsReadOnly is appliedMigrationVersions for a reader that must
// not write: what a pass would find after creating the version table and its
// baseline row (see markBaselineIfNeeded), worked out without doing either.
func appliedVersionsReadOnly(conn *DB) (map[int]bool, error) {
	has, err := hasTable(conn, "schema_migrations")
	if err != nil {
		return nil, fmt.Errorf("read applied versions: %w", err)
	}
	applied := map[int]bool{}
	if has {
		if applied, err = appliedMigrationVersions(conn); err != nil {
			return nil, fmt.Errorf("read applied versions: %w", err)
		}
	}
	if len(applied) == 0 {
		base, err := hasTable(conn, "unmask_event")
		if err != nil {
			return nil, fmt.Errorf("read applied versions: %w", err)
		}
		if base {
			applied[1] = true // the baseline a pass would record
		}
	}
	return applied, nil
}

// pendingFrom lists the migrations not in applied, with their estimates
// (cold: see MigrateOptions.ColdCache).
func pendingFrom(conn *DB, applied map[int]bool, cold bool) ([]pendingEntry, error) {
	all, err := listMigrations(string(conn.Driver))
	if err != nil {
		return nil, fmt.Errorf("list migrations: %w", err)
	}
	var out []pendingEntry
	// An index an earlier pending migration builds is not built again by a
	// later one naming it (0033 repeats 0032's CREATE INDEX IF NOT EXISTS).
	planned := map[string]bool{}
	var rates buildRates
	switch {
	case cold:
		rates.fast, rates.slow = indexBuildDiskFast, indexBuildDiskSlow
	default:
		if rates.host = hostIndexRate(conn); rates.host == 0 {
			rates.fast, rates.slow = indexBuildRates(conn)
		}
	}
	for _, m := range all {
		if applied[m.version] {
			continue
		}
		p := pendingEntry{path: m.path, PendingMigration: PendingMigration{
			Version: m.version, Name: m.name, Deferrable: m.deferrable, Table: m.table,
		}}
		if m.deferrable {
			if err := estimateIndexMigration(conn, m, &p.PendingMigration, planned, rates); err != nil {
				p.Deferrable, p.estimateErr = false, err
			}
		}
		out = append(out, p)
	}
	return out, nil
}

// createIndexRE / dropIndexRE pick the index name out of a statement in a
// deferrable migration (the only two statements one may hold).
var (
	createIndexRE = regexp.MustCompile("(?is)^\\s*CREATE\\s+INDEX\\s+(?:IF\\s+NOT\\s+EXISTS\\s+)?[`\"]?([A-Za-z0-9_]+)[`\"]?\\s+ON\\s+[`\"]?([A-Za-z0-9_]+)")
	dropIndexRE   = regexp.MustCompile("(?is)^\\s*DROP\\s+INDEX\\s+(?:IF\\s+EXISTS\\s+)?[`\"]?([A-Za-z0-9_]+)")
)

// indexOnly reports whether every statement of a migration creates or drops
// an index.  CREATE UNIQUE INDEX does not count: it fails on rows that break
// the constraint, so it changes what the table may hold, not how fast it reads.
func indexOnly(body string) bool {
	n := 0
	for _, stmt := range splitStatements(body) {
		if strings.TrimSpace(stmt) == "" {
			continue
		}
		if !createIndexRE.MatchString(stmt) && !dropIndexRE.MatchString(stmt) {
			return false
		}
		n++
	}
	return n > 0
}

// buildRates is what an estimate is made from: this host's measured rate
// (microseconds per row) when it has one, the built-in range otherwise.
type buildRates struct {
	host       float64
	fast, slow time.Duration
}

// estimateIndexMigration fills in what a deferrable migration would build and
// how long that is expected to take.
func estimateIndexMigration(conn *DB, m migrationEntry, p *PendingMigration, planned map[string]bool, rates buildRates) error {
	body, err := fs.ReadFile(migrationFS, m.path)
	if err != nil {
		return err
	}
	// No table yet (a database being created): its indexes are built over
	// nothing, in no time.
	if has, err := hasTable(conn, m.table); err != nil {
		return err
	} else if !has {
		return nil
	}
	for _, stmt := range splitStatements(string(body)) {
		sm := createIndexRE.FindStringSubmatch(stmt)
		if sm == nil {
			continue
		}
		name := sm[1]
		if planned[name] {
			continue
		}
		has, err := hasIndexNamed(conn, m.table, name)
		if err != nil {
			return err
		}
		if has {
			continue
		}
		planned[name] = true
		p.Indexes = append(p.Indexes, name)
	}
	if len(p.Indexes) == 0 {
		return nil
	}
	rows, err := approxRows(conn, m.table)
	if err != nil {
		return err
	}
	p.Rows = rows
	n := time.Duration(rows) * time.Duration(len(p.Indexes))
	if rates.host > 0 {
		// This host has built one: its own rate, with room either side.
		per := time.Duration(rates.host * float64(time.Microsecond))
		p.EstLow, p.EstHigh = n*per*7/10, n*per*3/2
		return nil
	}
	p.EstLow, p.EstHigh = n*rates.fast, n*rates.slow
	return nil
}

// approxRows is the span of a table's ids: what AUTOINCREMENT leaves behind a
// retention prune is a contiguous run, so the span is the row count to within
// the gaps, and reading it is two seeks where COUNT(*) walks the table.
//
// A table keyed by something else (the rollups: hour, kind, key) has no id.
// SQLite numbers its rows all the same, and a table filled forward and pruned
// from its old end leaves the same kind of run in rowid.  MariaDB has no such
// number; its own row count is approximate and costs one catalog read.
func approxRows(conn *DB, table string) (int64, error) {
	has, err := hasColumn(conn, table, "id")
	if err != nil {
		return 0, err
	}
	col := "id"
	if !has {
		if conn.Driver != DriverSQLite {
			var n *int64
			if err := conn.QueryRow(`SELECT TABLE_ROWS FROM INFORMATION_SCHEMA.TABLES
				WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ?`, table).Scan(&n); err != nil {
				return 0, err
			}
			if n == nil {
				return 0, nil
			}
			return *n, nil
		}
		col = "rowid" // a WITHOUT ROWID table has none: the query fails and the caller applies the migration now
	}
	var lo, hi *int64
	if err := conn.QueryRow("SELECT MIN("+col+"), MAX("+col+") FROM "+table).Scan(&lo, &hi); err != nil {
		return 0, err
	}
	if lo == nil || hi == nil {
		return 0, nil
	}
	return *hi - *lo + 1, nil
}

// hostIndexRate is the index build rate this host measured last (microseconds
// per row), or 0 when it has not built one worth measuring.
func hostIndexRate(conn *DB) float64 {
	has, err := hasTable(conn, "unmask_maint_state")
	if err != nil || !has {
		return 0
	}
	if conn.Gorm == nil {
		return 0
	}
	var rec SchemaRateRecord
	ok, err := conn.LoadMaintState(context.Background(), MaintSchemaRate, &rec)
	if err != nil || !ok {
		return 0
	}
	return rec.MicrosPerRow
}

// applyMigration runs one migration file and records it.
func applyMigration(conn *DB, m pendingEntry, opt MigrateOptions) (time.Duration, error) {
	body, err := fs.ReadFile(migrationFS, m.path)
	if err != nil {
		return 0, fmt.Errorf("read %s: %w", m.path, err)
	}
	t0 := time.Now()
	slow := m.EstHigh >= 5*time.Second
	if slow {
		opt.logf("db: applying %s: %s", m.Name, m.describe())
	}
	// A migration that runs long says so while it runs: with nothing in the
	// log for minutes, "building" and "stuck" look the same from outside.
	done := make(chan struct{})
	defer close(done)
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				opt.logf("db: still applying %s (%s so far)", m.Name, time.Since(t0).Round(time.Second))
			}
		}
	}()

	ctx := opt.context()
	exec := func(query string, args ...any) (sql.Result, error) {
		return conn.ExecContext(ctx, query, args...)
	}
	if m.Deferrable && conn.Driver == DriverSQLite && conn.SQLitePath != "" {
		// An index build sorts every key of the table.  The daemon's
		// connections keep SQLite's temporary storage in memory, where that
		// sort is the size of the index in RAM; one connection with the
		// temporary files next to the database (the place known to have room
		// for them) runs this migration instead.  See OpenMaintenance.
		c, err := conn.Conn(ctx)
		if err != nil {
			return 0, fmt.Errorf("apply %s: %w", m.Name, err)
		}
		// Not handed back to the pool: the pragmas below are the
		// connection's, and the next borrower would inherit them.  A bad
		// connection is what database/sql discards instead of reusing.
		defer func() {
			_ = c.Raw(func(any) error { return driver.ErrBadConn })
			_ = c.Close()
		}()
		dir := strings.ReplaceAll(filepath.Dir(conn.SQLitePath), "'", "''")
		for _, p := range []string{"PRAGMA temp_store=FILE", "PRAGMA temp_store_directory='" + dir + "'"} {
			if _, err := c.ExecContext(ctx, p); err != nil {
				return 0, fmt.Errorf("apply %s: %s: %w", m.Name, p, err)
			}
		}
		exec = func(query string, args ...any) (sql.Result, error) {
			return c.ExecContext(ctx, query, args...)
		}
	}
	if m.Deferrable && conn.Driver == DriverMariaDB && ctx.Done() != nil {
		// A cancel has to reach the server.  The driver answers a cancelled
		// context by closing its connection, and the server does not look at
		// the connection while it builds an index: the build ran on to the
		// end, long after the run had said it was stopped (a minute on a
		// table of 1.5 million rows).  So the statements run on one
		// connection whose id is known, and a cancel kills that connection
		// from another; InnoDB then rolls the unfinished index back.
		c, err := conn.Conn(ctx)
		if err != nil {
			return 0, fmt.Errorf("apply %s: %w", m.Name, err)
		}
		defer func() { _ = c.Close() }()
		var id int64
		if err := c.QueryRowContext(ctx, "SELECT CONNECTION_ID()").Scan(&id); err != nil {
			return 0, fmt.Errorf("apply %s: connection id: %w", m.Name, err)
		}
		exec = func(query string, args ...any) (sql.Result, error) {
			return c.ExecContext(ctx, query, args...)
		}
		stop := context.AfterFunc(ctx, func() { killOnServer(conn, id, m.Name, opt) })
		// Not before the kill has been sent, when there is one: the run must
		// not report itself stopped while the server builds on.
		defer func() {
			if !stop() {
				waitGoneFromServer(conn, id, m.Name, opt)
			}
		}()
	}

	for _, stmt := range splitStatements(string(body)) {
		s := strings.TrimSpace(stmt)
		if s == "" {
			continue
		}
		if _, err := exec(s); err != nil {
			if isAlreadyAppliedErr(err) {
				// The statement's end state is already in place -- a column
				// or index this migration adds exists, usually because a
				// development binary ran an earlier form of the change.
				// Stopping here is what wedges an install forever: the
				// failure aborts the file, the version is never recorded,
				// and every restart retries the same ALTER against the
				// same column.  Three fleet nodes sat in that loop with
				// the ref_id column present and its index missing.  The
				// remaining statements still run, so the parts that are
				// genuinely absent get created.
				log.Printf("db: %s: statement already in effect, continuing: %v", m.Name, err)
				continue
			}
			return 0, fmt.Errorf("apply %s: %w\n--- stmt ---\n%s", m.Name, err, s)
		}
	}
	// Recorded outside ctx: once the statements have run, a cancel that
	// arrives now must not leave them applied and unrecorded.
	if _, err := conn.Exec("INSERT INTO schema_migrations (version, name) VALUES (?, ?)", m.Version, m.Name); err != nil {
		return 0, fmt.Errorf("record %s: %w", m.Name, err)
	}
	elapsed := time.Since(t0)
	if slow || elapsed >= time.Second {
		opt.logf("db: applied %s in %s", m.Name, elapsed.Round(10*time.Millisecond))
	}
	return elapsed, nil
}

// serverStopWait is how long a cancelled run waits for the server to have
// let go of its statement.  Rolling back a part-built index is quick; the
// limit is for a server that does not answer.
const serverStopWait = 30 * time.Second

// killOnServer ends the connection with this id on a MariaDB server, and the
// statement it is running with it.  A user may always kill its own threads.
func killOnServer(conn *DB, id int64, name string, opt MigrateOptions) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := conn.ExecContext(ctx, "KILL "+strconv.FormatInt(id, 10)); err != nil && !isNoSuchThreadErr(err) {
		opt.logf("db: %s: could not stop the statement on the server (connection %d): %v -- it may run to its end there; running the update again afterwards is safe", name, id, err)
	}
}

// waitGoneFromServer returns when the connection with this id is no longer
// on the server, which is when the statement it ran has been rolled back.
func waitGoneFromServer(conn *DB, id int64, name string, opt MigrateOptions) {
	deadline := time.Now().Add(serverStopWait)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		var n int
		err := conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM information_schema.processlist WHERE id = ?", id).Scan(&n)
		cancel()
		if err == nil && n == 0 {
			return
		}
		if time.Now().After(deadline) {
			opt.logf("db: %s: the server still holds the cancelled statement after %s (connection %d); running the update again afterwards is safe", name, serverStopWait, id)
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// isNoSuchThreadErr: the connection to kill is already gone (MariaDB 1094,
// "Unknown thread id").
func isNoSuchThreadErr(err error) bool {
	return strings.Contains(strings.ToLower(err.Error()), "unknown thread id")
}

// isAlreadyAppliedErr: does this error mean "the schema element this statement
// creates is already there"?  Recognized narrowly -- a duplicate column or a
// duplicate index/key name -- because those are the only errors whose presence
// PROVES the end state exists.  Anything else (syntax, locks, constraint
// violations) still aborts the migration.
//
//	sqlite:  "duplicate column name: X" / "index X already exists"
//	mariadb: 1060 "Duplicate column name" / 1061 "Duplicate key name"
func isAlreadyAppliedErr(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "duplicate column name") ||
		strings.Contains(msg, "duplicate key name") ||
		(strings.Contains(msg, "index") && strings.Contains(msg, "already exists"))
}

// ensureSchemaMigrationsTable: create the version-history table (= CREATE TABLE IF NOT EXISTS).
func ensureSchemaMigrationsTable(conn *DB) error {
	var stmt string
	if conn.Driver == DriverMariaDB {
		stmt = `CREATE TABLE IF NOT EXISTS schema_migrations (
            version    INT NOT NULL COMMENT 'numbered migration version applied',
            name       VARCHAR(128) NOT NULL COMMENT 'migration file name (e.g. 0006_aggregate_hourly)',
            applied_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT 'when this migration was applied (UTC)',
            PRIMARY KEY (version)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Applied-migration version history for the numbered migration framework'`
	} else {
		stmt = `CREATE TABLE IF NOT EXISTS schema_migrations (
            version    INTEGER PRIMARY KEY,                                  -- numbered migration version applied
            name       TEXT NOT NULL,                                        -- migration file name (e.g. 0006_aggregate_hourly)
            applied_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP           -- when this migration was applied (UTC)
        )`
	}
	_, err := conn.Exec(stmt)
	return err
}

// markBaselineIfNeeded: mark an existing v0.1 DB as having v1 applied.
//
// If schema_migrations is empty AND the unmask_event table exists → INSERT version=1.
// (= assumes we're right after ensure* + schema SQL ran the v1 baseline)
//
// On a fresh install (= no unmask_event), do nothing.  The v1 baseline.sql
// does not exist as a migration file, so until a new migration is added,
// nothing else runs either.
func markBaselineIfNeeded(conn *DB) error {
	var n int
	if err := conn.QueryRow("SELECT COUNT(*) FROM schema_migrations").Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	has, err := hasTable(conn, "unmask_event")
	if err != nil {
		return err
	}
	if !has {
		return nil
	}
	_, err = conn.Exec("INSERT INTO schema_migrations (version, name) VALUES (?, ?)", 1, "0001_baseline")
	return err
}

// appliedMigrationVersions: the versions recorded as applied.  A set, not a
// high-water mark: a deferred migration is a gap below later versions.
func appliedMigrationVersions(conn *DB) (map[int]bool, error) {
	rows, err := conn.Query("SELECT version FROM schema_migrations")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int]bool{}
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out[v] = true
	}
	return out, rows.Err()
}

// migrationEntry: one detected migration file.
type migrationEntry struct {
	version int
	name    string
	path    string
	// deferrable / table: the file's "-- unmask:deferrable table=<t>" marker.
	deferrable bool
	table      string
}

// deferMarkerRE matches the marker line of a deferrable migration.
var deferMarkerRE = regexp.MustCompile(`(?m)^--\s*unmask:deferrable\s+table=([a-z_][a-z0-9_]*)\s*$`)

// listMigrations: every migration in the driver's embed FS, in ascending
// version order.
func listMigrations(driver string) ([]migrationEntry, error) {
	dir := "migrations/" + driver
	entries, err := fs.ReadDir(migrationFS, dir)
	if err != nil {
		// If the per-driver dir does not exist, no-op (= don't throw).  Also
		// covers the fresh-install case where no migration files have been
		// placed yet.
		return nil, nil
	}
	var migs []migrationEntry
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		m := migrationFileRE.FindStringSubmatch(e.Name())
		if m == nil {
			continue
		}
		v, _ := strconv.Atoi(m[1])
		ent := migrationEntry{
			version: v,
			name:    strings.TrimSuffix(e.Name(), ".sql"),
			path:    dir + "/" + e.Name(),
		}
		body, err := fs.ReadFile(migrationFS, ent.path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", ent.path, err)
		}
		// The marker only counts on a file that keeps to the rule; one that
		// does not is applied in place like any other (and fails the test
		// that holds marked files to it).
		if dm := deferMarkerRE.FindSubmatch(body); dm != nil && indexOnly(string(body)) {
			ent.deferrable, ent.table = true, string(dm[1])
		}
		migs = append(migs, ent)
	}
	sort.Slice(migs, func(i, j int) bool { return migs[i].version < migs[j].version })
	return migs, nil
}
