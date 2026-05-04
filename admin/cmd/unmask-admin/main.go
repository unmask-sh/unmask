// unmask-admin: HTTP server + CLI sub-commands.
//
// usage:
//
//	unmask-admin serve          # FastAPI 風の HTTP server を起動
//	unmask-admin migrate        # schema を作成
//	unmask-admin aggregate      # incremental 集計 (cron 用)
//	unmask-admin config-init    # ランダム secret 入りの config.yml を出す
//	unmask-admin version
//
// すべてのサブコマンドは -config <path> で config を上書きできる.
package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/geoip"
	"github.com/unmask-sh/unmask/admin/internal/handlers"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

const Version = "0.1.0"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	cmd := os.Args[1]
	args := os.Args[2:]
	var err error
	switch cmd {
	case "serve":
		err = cmdServe(args)
	case "migrate":
		err = cmdMigrate(args)
	case "aggregate":
		err = cmdAggregate(args)
	case "config-init":
		err = cmdConfigInit(args)
	case "build-google-ip":
		err = cmdBuildGoogleIP(args)
	case "update-crawler-list":
		err = cmdUpdateCrawlerList(args)
	case "version", "-v", "--version":
		fmt.Println("unmask-admin", Version)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown sub-command: %s\n\n", cmd)
		usage()
		os.Exit(2)
	}
	if err != nil {
		log.Fatalf("%s: %v", cmd, err)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `unmask-admin — JA4 bot challenge admin server

usage:
  unmask-admin serve [-config PATH]
  unmask-admin migrate [-config PATH]
  unmask-admin aggregate [-config PATH] [-days N]
  unmask-admin config-init [-out PATH]
  unmask-admin build-google-ip [-out PATH] [-ipv6=true]
  unmask-admin update-crawler-list [-out PATH]
  unmask-admin version

env:
  UNMASK_CONFIG   default config path (overridden by -config)
`)
}

func loadSettings(configPath string) (settings.Settings, error) {
	return settings.Load(configPath)
}

// ----------------------------------------------------------------
// serve
// ----------------------------------------------------------------

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	configPath := fs.String("config", "", "path to config.yml")
	_ = fs.Parse(args)

	s, err := loadSettings(*configPath)
	if err != nil {
		return err
	}
	conn, err := db.Open(s.DB)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer conn.Close()

	gip := geoip.Open(s.GeoIP.MMDBPath)
	defer gip.Close()
	if s.GeoIP.MMDBPath != "" {
		if gip.Loaded() {
			log.Printf("geoip: loaded %s", s.GeoIP.MMDBPath)
		} else {
			log.Printf("geoip: failed to load %s (= 国別 chart は表示されない)", s.GeoIP.MMDBPath)
		}
	}
	h := &handlers.Handler{DB: conn, Settings: s, GeoIP: gip}
	mux := buildRouter(s, h)

	addr := fmt.Sprintf("%s:%d", s.Server.Bind, s.Server.Port)
	srv := &http.Server{
		Addr:              addr,
		Handler:           withAccessLog(mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Printf("shutdown signal received")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()

	log.Printf("unmask-admin %s listening on %s base=%s driver=%s",
		Version, addr, s.Server.BasePath, conn.Driver)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func buildRouter(s settings.Settings, h *handlers.Handler) *http.ServeMux {
	mux := http.NewServeMux()
	base := strings.TrimRight(s.Server.BasePath, "/")

	// Go 1.22 enhanced ServeMux. {site} は per-site path param. literal pattern が
	// より specific として優先されるので、 default site 用の literal と {site} 用の
	// wildcard を併存させても routing は明確.

	// challenge HTML
	mux.HandleFunc("GET "+base+"/challenge/{$}", h.ServeChallenge)
	mux.HandleFunc("GET "+base+"/challenge/{site}/{$}", h.ServeChallenge)
	// legacy URL: /unmask/challenge.html → 同 handler (= リダイレクトは nginx 側で)
	mux.HandleFunc("GET "+base+"/challenge.html", h.ServeChallenge)

	// API endpoints (default + per-site)
	mux.HandleFunc("POST "+base+"/api/verify", h.VerifyJSON)
	mux.HandleFunc("POST "+base+"/api/{site}/verify", h.VerifyJSON)
	mux.HandleFunc("GET "+base+"/api/captcha/new", h.CaptchaNew)
	mux.HandleFunc("GET "+base+"/api/{site}/captcha/new", h.CaptchaNew)
	mux.HandleFunc("POST "+base+"/api/debug", h.DebugBeacon)
	mux.HandleFunc("POST "+base+"/api/{site}/debug", h.DebugBeacon)
	mux.HandleFunc("GET "+base+"/api/bv-check", h.BVCheck)
	mux.HandleFunc("GET "+base+"/api/{site}/bv-check", h.BVCheck)

	// admin: /admin/ で site 一覧, /admin/{site}/ で per-site dashboard
	mux.HandleFunc("GET "+base+"/admin/{$}",
		h.AuthMiddleware(h.AdminSiteList))
	mux.HandleFunc("GET "+base+"/admin/{site}/{$}",
		h.AuthMiddleware(h.AdminDashboard))
	mux.HandleFunc("GET "+base+"/admin/api/funnel",
		h.AuthMiddleware(h.AdminFunnelJSON))
	mux.HandleFunc("GET "+base+"/admin/api/myip",
		h.AuthMiddleware(h.AdminMyIP))

	// health
	mux.HandleFunc("GET "+base+"/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("ok\n"))
	})

	// metrics (Prometheus text format).  bind=127.0.0.1 default なので
	// 通常は scrape 元 (= prometheus exporter / agent) もループバックから読む.
	mux.HandleFunc("GET "+base+"/metrics", h.Metrics)

	return mux
}

func withAccessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, code: 200}
		next.ServeHTTP(rec, r)
		log.Printf("%s %s %d %s", r.Method, r.URL.Path, rec.code, time.Since(start))
	})
}

type statusRecorder struct {
	http.ResponseWriter
	code int
}

func (s *statusRecorder) WriteHeader(c int) {
	s.code = c
	s.ResponseWriter.WriteHeader(c)
}

// ----------------------------------------------------------------
// migrate
// ----------------------------------------------------------------

func cmdMigrate(args []string) error {
	fs := flag.NewFlagSet("migrate", flag.ExitOnError)
	configPath := fs.String("config", "", "path to config.yml")
	_ = fs.Parse(args)

	s, err := loadSettings(*configPath)
	if err != nil {
		return err
	}
	conn, err := db.Open(s.DB)
	if err != nil {
		return err
	}
	defer conn.Close()

	// 既存 DB に site 列が無ければ ALTER で追加 (= 0.1 → 0.2 migration).
	// 注意: schema を流す前に ALTER を走らせる必要がある. site 列を参照する index
	// 生成 (= "CREATE INDEX ... ON unmask_event(site,...)") が前提とする列を
	// 無いまま実行すると失敗するため.
	if err := ensureSiteColumn(conn); err != nil {
		return err
	}

	schema := schemaSQLite
	if conn.Driver == db.DriverMariaDB {
		schema = schemaMariaDB
	}
	// driver ごとに statement を分けて execute (multi-statement 非対応の driver 配慮).
	for _, stmt := range splitStatements(schema) {
		s := strings.TrimSpace(stmt)
		if s == "" {
			continue
		}
		if _, err := conn.Exec(s); err != nil {
			return fmt.Errorf("apply schema: %w\n--- stmt ---\n%s", err, s)
		}
	}
	fmt.Println("schema applied")
	return nil
}

// ensureSiteColumn: 旧 schema (site 列が無い) の DB に ALTER で site を追加する.
// idempotent: 既にある場合は no-op. テーブル自体が無い場合 (= 新規 install) も no-op
// (= 後から走る CREATE TABLE で site 列込みで作られる).
func ensureSiteColumn(conn *db.DB) error {
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
	if conn.Driver == db.DriverSQLite {
		idx += `IF NOT EXISTS idx_unmask_event_site ON unmask_event(site, date_created)`
	} else {
		idx += `idx_site ON unmask_event(site, date_created)`
	}
	if _, err := conn.Exec(idx); err != nil {
		// duplicate index は SQLite の IF NOT EXISTS で潰れるが MariaDB は素通し
		// しないので warning 出すだけ.
		fmt.Fprintf(os.Stderr, "warning: index create skipped: %v\n", err)
	}
	fmt.Println("schema applied: added site column")
	return nil
}

// hasTable returns true if `table` exists in the current DB.
func hasTable(conn *db.DB, table string) (bool, error) {
	if conn.Driver == db.DriverSQLite {
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

// hasColumn returns true if `table.column` exists.
func hasColumn(conn *db.DB, table, col string) (bool, error) {
	if conn.Driver == db.DriverSQLite {
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
	// MariaDB / MySQL
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

func splitStatements(sql string) []string {
	// `--` で始まる行と空行を捨てて、 `;` で分割する素朴な splitter.
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

// ----------------------------------------------------------------
// aggregate (= cron 用. 現時点では event テーブルから日次集計を unmask_aggregate に書く)
// ----------------------------------------------------------------

func cmdAggregate(args []string) error {
	fs := flag.NewFlagSet("aggregate", flag.ExitOnError)
	configPath := fs.String("config", "", "path to config.yml")
	days := fs.Int("days", 30, "how many days back to (re)aggregate")
	_ = fs.Parse(args)

	s, err := loadSettings(*configPath)
	if err != nil {
		return err
	}
	conn, err := db.Open(s.DB)
	if err != nil {
		return err
	}
	defer conn.Close()

	since := conn.NowMinusMinutes(*days * 24 * 60)
	stmt := fmt.Sprintf(`
        SELECT DATE(date_created), 'phase', phase, COUNT(*)
        FROM unmask_event
        WHERE date_created > %s
        GROUP BY DATE(date_created), phase
    `, since)
	rows, err := conn.Query(stmt)
	if err != nil {
		return err
	}
	defer rows.Close()

	upsert := `INSERT INTO unmask_aggregate (bucket_date, bucket_kind, bucket_key, cnt) VALUES (?, ?, ?, ?)`
	if conn.Driver == db.DriverSQLite {
		upsert += ` ON CONFLICT(bucket_date, bucket_kind, bucket_key) DO UPDATE SET cnt = excluded.cnt`
	} else {
		upsert += ` ON DUPLICATE KEY UPDATE cnt = VALUES(cnt)`
	}

	n := 0
	for rows.Next() {
		var dateRaw any
		var kind, key string
		var cnt int
		if err := rows.Scan(&dateRaw, &kind, &key, &cnt); err != nil {
			return err
		}
		var dateStr string
		switch v := dateRaw.(type) {
		case string:
			dateStr = v
		case []byte:
			dateStr = string(v)
		case time.Time:
			dateStr = v.Format("2006-01-02")
		default:
			dateStr = fmt.Sprintf("%v", v)
		}
		if _, err := conn.Exec(upsert, dateStr, kind, key, cnt); err != nil {
			return err
		}
		n++
	}
	if err := rows.Err(); err != nil {
		return err
	}
	fmt.Printf("aggregate: wrote %d rows (last %d days)\n", n, *days)
	return nil
}

// ----------------------------------------------------------------
// config-init
// ----------------------------------------------------------------

func cmdConfigInit(args []string) error {
	fs := flag.NewFlagSet("config-init", flag.ExitOnError)
	out := fs.String("out", "-", "output path (- = stdout)")
	_ = fs.Parse(args)

	bv := randHex(24)
	cb := randHex(24)
	body := fmt.Sprintf(`# unmask config (generated by unmask-admin config-init)
db:
  driver: sqlite
  sqlite_path: /var/lib/unmask/unmask.sqlite
  # mariadb:
  #   host: 127.0.0.1
  #   port: 3306
  #   user: unmask
  #   password: ""
  #   database: unmask

secret:
  # _bv cookie HMAC-SHA1 key. 漏洩時はこの値を変えて nginx の bv-check も再 sync.
  bv_secret: %q
  # math captcha token HMAC-SHA256 base
  captcha_secret_base: %q

challenge:
  cookie_days: 3
  captcha_score_threshold: 0.5
  debug_rate_limit_per_5min: 20
  challenge_html_path: ""   # 空なら binary 内の embed 版を使う

server:
  bind: 127.0.0.1
  port: 8765
  base_path: /unmask
  admin_token: ""           # 空なら無認証 (= bind 127.0.0.1 前提)
`, bv, cb)

	if *out == "-" {
		fmt.Print(body)
		return nil
	}
	return os.WriteFile(*out, []byte(body), 0o600)
}

func randHex(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return hex.EncodeToString(buf)
}

// ----------------------------------------------------------------
// embedded schema (= sql/ から ldflags/embed で取り込みたいが、 ここでは直書き).
// sql/schema-*.sql を編集したら同期すること.
// ----------------------------------------------------------------

const schemaSQLite = `
CREATE TABLE IF NOT EXISTS unmask_event (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    site            VARCHAR(64) NOT NULL DEFAULT 'default',
    ip_address      BLOB NOT NULL,
    user_agent      VARCHAR(255),
    ja4             VARCHAR(40),
    ja4_verdict     VARCHAR(40),
    phase           VARCHAR(16) NOT NULL,
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
CREATE INDEX IF NOT EXISTS idx_unmask_event_verdict  ON unmask_event(ja4_verdict, date_created);
CREATE INDEX IF NOT EXISTS idx_unmask_event_site     ON unmask_event(site, date_created);

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
`

const schemaMariaDB = `
CREATE TABLE IF NOT EXISTS unmask_event (
    id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    site            VARCHAR(64) NOT NULL DEFAULT 'default',
    ip_address      VARBINARY(16) NOT NULL,
    user_agent      VARCHAR(255),
    ja4             VARCHAR(40),
    ja4_verdict     VARCHAR(40),
    phase           VARCHAR(16) NOT NULL,
    flags           INT NOT NULL DEFAULT 0,
    reload_count    INT NOT NULL DEFAULT 0,
    cookie_bv       VARCHAR(80),
    cookie_br       VARCHAR(8),
    payload_json    LONGTEXT,
    date_created    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_date     (date_created),
    KEY idx_ip_date  (ip_address, date_created),
    KEY idx_phase    (phase, date_created),
    KEY idx_verdict  (ja4_verdict, date_created),
    KEY idx_site     (site, date_created)
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
`
