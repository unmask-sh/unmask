// Package db: SQLite / MariaDB layer with a GORM handle for CRUD.
//
// Hybrid by design: aggregation reads stay raw SQL via the embedded *sql.DB
// (the dashboard queries read more clearly that way), while CRUD increasingly
// goes through GORM models on the Gorm handle (parameterized + type-safe).
// Both share one connection pool -- Gorm.DB() is the embedded *sql.DB.
//
// Pure-Go static binary is preserved: the SQLite driver is glebarez/sqlite
// (modernc-based), NOT the CGO gorm.io/driver/sqlite.
//
// Driver differences:
//   - placeholder: SQLite uses ?, MariaDB also takes ? (database/sql standard),
//     so we use ? for both.
//   - "N minutes ago" SQL fragments differ per driver; generate via NowMinusMinutes().
package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	glsqlite "github.com/glebarez/sqlite"
	mysql "github.com/go-sql-driver/mysql"
	gormmysql "gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

type Driver string

const (
	DriverSQLite  Driver = "sqlite"
	DriverMariaDB Driver = "mariadb"
)

type DB struct {
	*sql.DB
	Gorm   *gorm.DB
	Driver Driver
}

// SQLite memory sizing.
//
// cache_size and mmap_size are PER CONNECTION, and the pool opens one per CPU
// (up to sqliteMaxConnsCeil) -- so a flat "128MB cache" is really up to
// 8 x 128MB of page cache plus 8 x mmap once the dashboard runs a few queries
// in parallel.  Measured on a 2.2GB / 6.9M-row event DB with the production
// query mix (hunt page, 30-day aggregate, funnel counts) at 8 concurrent
// workers: 128MB cache + 256MB mmap peaked at 3.7GB RSS, while 4MB + 8MB
// peaked at 99MB and finished in the same wall-clock time (71.9s vs 71.6s).
// Page cache barely matters once the range queries ride their index, so the
// large values bought nothing and could OOM a small host outright -- unmask is
// meant to run on a 1GB VPS.
//
// So: derive a budget from the memory this process may actually use (cgroup
// limit under a container / systemd slice, else physical RAM) and split it
// across the pool, instead of handing each connection an unbounded-in-
// aggregate allowance.  The pool itself is CPU-sized (sqliteMaxOpen), which
// also concentrates the budget: fewer CPUs means fewer, fatter connections
// rather than eight thin ones that cannot run in parallel anyway.
//
// The budget below applies to EACH of the two knobs, so the pool-wide worst
// case is roughly 2x it: page cache (anonymous, not reclaimable -- this is the
// part that can OOM a box) plus mmap (file-backed clean pages the kernel can
// drop under pressure).  On a 1GB VPS that is 64MB + 64MB.
const (
	sqliteMaxConnsCeil = 8
	sqliteMinConns     = 2
	// Profile divisors: the share of usable memory allowed per knob.
	// Standard is the default; the others move the resource dial, not speed.
	sqliteBudgetDivisor             = 16        // ~6%  (standard)
	sqliteBudgetDivisorConservative = 32        // ~3%  (small VPS)
	sqliteBudgetDivisorGenerous     = 8         // ~12% (large box)
	sqliteBudgetFloor               = 16 << 20  // never go below 16MB per knob, however small the box
	sqliteBudgetCeil                = 192 << 20 // standard profile's cap (also the fallback when memory is unknown)
	// Per-profile caps.  Without these, every profile collapses onto the same
	// ceiling on a large host and the picker becomes meaningless -- the three
	// choices have to differ on big boxes as well as small ones.
	sqliteBudgetCeilConservative = 64 << 20
	sqliteBudgetCeilGenerous     = 512 << 20
	// A hand-pinned custom budget may exceed the automatic ceiling (the operator
	// asked for it), but not without bound -- this caps the damage of a typo.
	sqliteBudgetCustomCeil = 2048 << 20
	// Custom pools may exceed the CPU count (an operator may know their I/O
	// profile), but not absurdly: past this the connections only thin the cache.
	sqliteMaxConnsCustomCeil = 32
)

// budgetDivisorFor maps a profile to its share of usable memory.
func budgetDivisorFor(profile string) int64 {
	switch profile {
	case settings.PerfProfileConservative:
		return sqliteBudgetDivisorConservative
	case settings.PerfProfileGenerous:
		return sqliteBudgetDivisorGenerous
	default:
		return sqliteBudgetDivisor
	}
}

// budgetCeilFor is the profile's upper bound.  Distinct per profile so the
// choices stay distinguishable on a large host, where a single shared ceiling
// would flatten all three into the same number.
func budgetCeilFor(profile string) int64 {
	switch profile {
	case settings.PerfProfileConservative:
		return sqliteBudgetCeilConservative
	case settings.PerfProfileGenerous:
		return sqliteBudgetCeilGenerous
	default:
		return sqliteBudgetCeil
	}
}

// sqliteMaxOpen sizes the read pool to the CPUs this process may actually use.
// WAL lets readers run in parallel, but opening 8 of them on a 1-vCPU VPS buys
// no parallelism (the work is CPU-bound once pages are cached) and costs twice:
// the connections sit idle AND each holds its own slice of the memory budget,
// thinning the per-connection page cache by the same factor.  Sizing to the CPU
// count keeps the budget concentrated where it helps -- a 1-vCPU box gets 2 fat
// connections instead of 8 thin ones.  GOMAXPROCS (not NumCPU) so a container
// CPU limit is respected.
func sqliteMaxOpen() int { return sqliteMaxOpenFor(settings.DB{}) }

// sqliteMaxOpenFor is sqliteMaxOpen with the operator's custom override applied.
func sqliteMaxOpenFor(s settings.DB) int {
	if s.ResolvedPerfProfile() == settings.PerfProfileCustom && s.MaxConns > 0 {
		n := s.MaxConns
		if n < 1 {
			n = 1
		}
		if n > sqliteMaxConnsCustomCeil {
			n = sqliteMaxConnsCustomCeil
		}
		return n
	}
	n := runtime.GOMAXPROCS(0)
	if n < sqliteMinConns {
		n = sqliteMinConns
	}
	if n > sqliteMaxConnsCeil {
		n = sqliteMaxConnsCeil
	}
	return n
}

// memLimitBytes reports how much memory this process may actually use: the
// cgroup limit when running under one (container / k8s / systemd MemoryMax),
// else the machine's physical RAM.  0 when nothing can be determined, which
// makes the caller fall back to the ceiling.
func memLimitBytes() int64 {
	v, _ := memLimitDetail()
	return v
}

// memLimitDetail is memLimitBytes plus whether the value came from a cgroup
// limit (container / systemd slice) rather than the machine's total RAM.
//
// Three sources, in order of specificity.  The last one exists because /proc
// may not be there to read: unmask's own unit ships hardened, and systemd's
// ProcSubset=pid leaves only the PID directories in /proc -- /proc/meminfo
// disappears entirely, which silently turned the detected limit into "unknown".
func memLimitDetail() (int64, bool) {
	if v := cgroupLimit(); v > 0 {
		return v, true
	}
	if b, err := os.ReadFile("/proc/meminfo"); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if !strings.HasPrefix(line, "MemTotal:") {
				continue
			}
			if f := strings.Fields(line); len(f) >= 2 {
				if kb, err := strconv.ParseInt(f[1], 10, 64); err == nil && kb > 0 {
					return kb * 1024, false
				}
			}
		}
	}
	// sysinfo(2) needs no filesystem at all, so it survives a /proc that has
	// been pared down (and an empty ProtectSystem sandbox).
	var si syscall.Sysinfo_t
	if err := syscall.Sysinfo(&si); err == nil && si.Totalram > 0 {
		unit := int64(si.Unit)
		if unit <= 0 {
			unit = 1 // pre-2.3.23 kernels report bytes with a zero unit
		}
		return int64(si.Totalram) * unit, false
	}
	return 0, false
}

// cgroupLimit returns the memory limit of the cgroup this process belongs to,
// or 0 when there is none.  Both layouts are checked:
//
//   - "/sys/fs/cgroup/memory.max" -- inside a container, the namespace root IS
//     this process's cgroup, so the limit sits right there;
//   - "/sys/fs/cgroup/<own path>/memory.max" -- on a host, the root cgroup has
//     no memory.max at all and the limit (systemd MemoryMax=) lives under the
//     service's own path, e.g. /system.slice/unmask.service.
//
// Reading only the first is why a systemd MemoryMax= went unnoticed.
func cgroupLimit() int64 {
	paths := []string{"/sys/fs/cgroup/memory.max"}
	// /proc/self survives ProcSubset=pid (it is a PID directory), so the own-path
	// lookup keeps working where /proc/meminfo does not.
	if b, err := os.ReadFile("/proc/self/cgroup"); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			rel, ok := strings.CutPrefix(strings.TrimSpace(line), "0::")
			if !ok || rel == "" || rel == "/" {
				continue
			}
			paths = append(paths, filepath.Join("/sys/fs/cgroup", rel, "memory.max"))
		}
	}
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		// "max" = no limit; fall through to the next source rather than
		// reporting the machine as unbounded-but-known.
		if v := strings.TrimSpace(string(b)); v != "max" {
			if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
				return n
			}
		}
	}
	// cgroup v1: an "unlimited" limit is a huge sentinel (PAGE_COUNTER_MAX),
	// so ignore anything absurd rather than trusting it as a real limit.
	if b, err := os.ReadFile("/sys/fs/cgroup/memory/memory.limit_in_bytes"); err == nil {
		if v, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64); err == nil && v > 0 && v < (1<<52) {
			return v
		}
	}
	return 0
}

// sqlitePerConnBytes is the per-connection page-cache / mmap allowance: the
// budget split across the CPU-sized pool.  overrideMB (settings
// sqlite_cache_mb, 0 = automatic) pins the pool-wide budget, for operators who
// know their box better than this heuristic does.
func sqlitePerConnBytes(overrideMB int) int64 {
	return sqlitePerConnBytesFor(settings.DB{PerfProfile: settings.PerfProfileCustom, SQLiteCacheMB: overrideMB})
}

// sqlitePerConnBytesFor resolves the per-connection allowance for a config.
func sqlitePerConnBytesFor(s settings.DB) int64 {
	profile := s.ResolvedPerfProfile()
	var budget int64
	if profile == settings.PerfProfileCustom && s.SQLiteCacheMB > 0 {
		budget = min(int64(s.SQLiteCacheMB)<<20, sqliteBudgetCustomCeil)
	} else {
		ceil := budgetCeilFor(profile)
		if limit := memLimitBytes(); limit > 0 {
			budget = limit / budgetDivisorFor(profile)
		} else {
			budget = ceil // unknown box: the profile ceiling is already modest
		}
		budget = min(max(budget, sqliteBudgetFloor), ceil)
	}
	per := budget / int64(sqliteMaxOpenFor(s))
	if per < 1<<20 { // keep at least 1MB/conn so tiny boxes still cache something
		per = 1 << 20
	}
	return per
}

// SQLiteMemPlan describes the sizing this process resolved, for the admin UI
// and doctor: operators cannot reason about "is this too much memory" without
// seeing the numbers their own box produced, and the numbers differ per box.
type SQLiteMemPlan struct {
	Conns      int   // pooled connections actually used (custom override or CPU-derived)
	CPUs       int   // CPUs the automatic sizing derives from
	PerConn    int64 // page cache AND mmap allowance, per connection, in bytes
	TotalCache int64 // PerConn * Conns -- the anonymous part (OOM-relevant)
	TotalMmap  int64 // PerConn * Conns -- file-backed, reclaimable
	Automatic  bool  // false when pinned via db.sqlite_cache_mb
	// SharePercent is the profile's share of usable memory (the setting's real
	// content -- the byte figures are just what that share works out to here).
	SharePercent int
	// Capped is true when the share hit the profile's ceiling, so the bytes
	// below are the cap rather than the percentage.  Saying so keeps the UI
	// honest on a large host, where every share would otherwise look wrong.
	Capped     bool
	MemLimit   int64 // the memory limit the budget was derived from (0 = unknown)
	FromCgroup bool  // MemLimit came from a cgroup limit rather than total RAM
}

// SQLiteMemPlanFor resolves the plan without opening a database.
func SQLiteMemPlanFor(s settings.DB) SQLiteMemPlan {
	per := sqlitePerConnBytesFor(s)
	conns := sqliteMaxOpenFor(s)
	limit, fromCgroup := memLimitDetail()
	profile := s.ResolvedPerfProfile()
	share, capped := 0, false
	if profile != settings.PerfProfileCustom {
		div := budgetDivisorFor(profile)
		share = int(100 / div)
		if limit > 0 {
			capped = limit/div > budgetCeilFor(profile)
		}
	}
	return SQLiteMemPlan{
		SharePercent: share,
		Capped:       capped,
		Conns:        conns,
		CPUs:         runtime.GOMAXPROCS(0),
		PerConn:      per,
		TotalCache:   per * int64(conns),
		TotalMmap:    per * int64(conns),
		Automatic:    s.ResolvedPerfProfile() != settings.PerfProfileCustom,
		MemLimit:     limit,
		FromCgroup:   fromCgroup,
	}
}

// Open returns a configured *DB. SQLite path's parent directory is created if
// missing (so first-run "just works").
func Open(s settings.DB) (*DB, error) {
	var (
		dialector gorm.Dialector
		driver    Driver
		maxIdle   = 4
		maxLife   = time.Hour
	)

	switch s.Driver {
	case "", string(DriverSQLite):
		if err := os.MkdirAll(filepath.Dir(s.SQLitePath), 0o755); err != nil {
			return nil, fmt.Errorf("mkdir sqlite parent: %w", err)
		}
		// _pragma=... = WAL + busy timeout.  Prevents challenge-write vs dashboard-read contention.
		//
		// cache_size / mmap_size are per connection and the pool holds up to
		// sqliteMaxOpenConns, so both are sized from a pool-wide budget (see
		// sqlitePerConnBytes) rather than fixed per-connection constants that
		// multiply into gigabytes on a busy dashboard.
		perConn := sqlitePerConnBytesFor(s)
		dsn := s.SQLitePath +
			"?_pragma=journal_mode(WAL)" +
			"&_pragma=synchronous(NORMAL)" +
			"&_pragma=busy_timeout(5000)" +
			// negative cache_size = KiB of page cache (positive would be a page count)
			fmt.Sprintf("&_pragma=cache_size(-%d)", perConn/1024) +
			"&_pragma=temp_store(MEMORY)" + // keep temp tables in memory
			fmt.Sprintf("&_pragma=mmap_size(%d)", perConn)
		dialector = glsqlite.Open(dsn)
		driver = DriverSQLite

	case string(DriverMariaDB):
		cfg := mysql.NewConfig()
		cfg.User = s.MariaDB.User
		cfg.Passwd = s.MariaDB.Password
		cfg.Net = "tcp"
		cfg.Addr = fmt.Sprintf("%s:%d", s.MariaDB.Host, s.MariaDB.Port)
		cfg.DBName = s.MariaDB.Database
		cfg.ParseTime = true
		// Force everything timestamp-related to UTC: the driver-side parse
		// location AND the session time_zone.  With this, NOW() / CURRENT_TIMESTAMP
		// / DATE(col) / DATE_FORMAT(col,…) / DATE_SUB(NOW(),…) all evaluate in
		// UTC, matching SQLite's UTC-by-default behaviour.  The application
		// (= dashboard.Daily*) then converts UTC unix sec to the operator's
		// cookie TZ on read, so the storage is timezone-agnostic.
		cfg.Loc = time.UTC
		cfg.Params = map[string]string{
			"charset":   "utf8mb4",
			"time_zone": "'+00:00'",
		}
		dialector = gormmysql.Open(cfg.FormatDSN())
		driver = DriverMariaDB
		maxIdle = 2
		maxLife = 30 * time.Minute

	default:
		return nil, errors.New("unknown db driver: " + s.Driver)
	}

	gdb, err := gorm.Open(dialector, &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return nil, err
	}
	conn, err := gdb.DB()
	if err != nil {
		return nil, err
	}
	// WAL mode allows multiple parallel readers; writes are serial (SQLite).
	// Parallelising reads keeps the dashboard from contending with auth_request
	// writes and hitting the busy timeout.
	conn.SetMaxOpenConns(sqliteMaxOpenFor(s))
	conn.SetMaxIdleConns(maxIdle)
	conn.SetConnMaxLifetime(maxLife)
	if err := conn.PingContext(context.Background()); err != nil {
		conn.Close()
		return nil, err
	}
	return &DB{DB: conn, Gorm: gdb, Driver: driver}, nil
}

// NowMinusMinutes returns a SQL fragment representing "now - n minutes" for
// the active driver.  Use it inline (= cannot be parameterised client-side).
func (d *DB) NowMinusMinutes(n int) string {
	if d.Driver == DriverSQLite {
		return fmt.Sprintf("datetime('now', '-%d minutes')", n)
	}
	return fmt.Sprintf("DATE_SUB(NOW(), INTERVAL %d MINUTE)", n)
}

// RefreshPlannerStats rebuilds the query planner's index statistics.
//
// SQLite ships NO statistics until ANALYZE runs, and a fresh unmask database
// never runs it.  With no sqlite_stat1 the planner cannot estimate how selective
// `date_created > ?` is, so for a GROUP BY / DISTINCT on a column that has a
// composite (col, date_created) index -- ja4_verdict, site, host, phase -- it
// prefers scanning that whole covering index (avoiding a temp b-tree) over
// seeking the date range.  The query then costs O(all events) rather than
// O(events in the window), which is why the stats and bot-hunt pages get slower
// as events accumulate rather than staying flat.  A sampled ANALYZE flips those
// plans (measured: DISTINCT host 0.22s -> 0.002s, verdict distribution 0.72s ->
// 0.10s on a 1M-row table).
//
// THIS IS A MAINTENANCE OPERATION, NOT A BACKGROUND TASK.  ANALYZE holds a write
// transaction for its whole run, and its run is proportional to the size of the
// indexes: `PRAGMA analysis_limit` only lets it skip runs of DUPLICATE keys, and
// every unmask_event index carries date_created, so they are all near-unique and
// nothing gets skipped.  Measured on tool1-us (3.4GB database, 3.9M events, 1.1GB
// of event indexes): 60-70s, during which every event insert failed with
// SQLITE_BUSY and the challenge beacon's writes took 5s.  On a freshly installed
// database it is instant.  Call it from `unmask db-analyze` or from migrate (the
// service is stopped there) -- never from serve.
//
// analysis_limit is still worth setting: it bounds the per-key sampling and is a
// per-connection setting, so it must run on the SAME connection as ANALYZE --
// hence the explicit Conn.  `PRAGMA optimize` would be lighter, but it only
// considers tables the current connection has already queried, which on a freshly
// checked-out pool connection is none: it would silently do nothing.
//
// MariaDB is a no-op (InnoDB maintains live index statistics itself, and
// estimates the range correctly).
func (d *DB) RefreshPlannerStats(ctx context.Context) error {
	if d.Driver != DriverSQLite {
		return nil
	}
	conn, err := d.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, `PRAGMA analysis_limit=400`); err != nil {
		return err
	}
	_, err = conn.ExecContext(ctx, `ANALYZE`)
	return err
}

// HasPlannerStats reports whether the query planner has index statistics.  A
// SQLite database that has never been ANALYZEd has no sqlite_stat1 table at all,
// which is the state that makes the stats and bot-hunt pages scan whole covering
// indexes.  MariaDB always reports true: InnoDB maintains its own.
func (d *DB) HasPlannerStats(ctx context.Context) (bool, error) {
	if d.Driver != DriverSQLite {
		return true, nil
	}
	var n int
	err := d.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM sqlite_master WHERE name='sqlite_stat1'`).Scan(&n)
	return n > 0, err
}

// EventDateIndexHint returns the driver's hint that pins an unmask_event query
// to the date_created index, or "" when the driver needs none.
//
// RefreshPlannerStats fixes the bad plan for low-cardinality GROUP BY columns
// (the planner can skip-scan them once it has statistics), but NOT for
// ip_address: with roughly one distinct IP per three rows a skip-scan is
// worthless, so even a fully analysed SQLite keeps scanning the whole
// (ip_address, date_created) covering index.  Measured on the tool1-us database
// (3.9M events): `GROUP BY ip_address` over a 1-hour window took 1.4s warm /
// 10.3s cold and did NOT get faster with a narrower window -- pinned to the date
// index it is 0.005s.
//
// Only append this to a query that actually constrains date_created: INDEXED BY
// makes SQLite reject a plan that cannot use the named index.  MariaDB names its
// indexes differently (idx_date) and its optimizer estimates the range from live
// InnoDB statistics, so it is deliberately left unhinted.
func (d *DB) EventDateIndexHint() string {
	if d.Driver == DriverSQLite {
		return " INDEXED BY idx_unmask_event_date"
	}
	return ""
}
