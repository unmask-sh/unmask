package main

import (
	"database/sql"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "github.com/glebarez/sqlite"

	"github.com/unmask-sh/unmask/admin/internal/db"
)

// captureStdout runs fn and returns what it printed.
func captureStdout(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	done := make(chan string)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	ferr := fn()
	w.Close()
	os.Stdout = old
	return <-done, ferr
}

// migrateConfig writes a config for a database in a temporary directory.
// deferSeconds is the daemon's threshold for leaving an index build to the
// operator.
func migrateConfig(t *testing.T, deferSeconds string) (config, database string) {
	t.Helper()
	dir := t.TempDir()
	database = filepath.Join(dir, "unmask.sqlite")
	config = filepath.Join(dir, "config.yml")
	body := "server:\n  bind: 127.0.0.1\n  port: 19478\n" +
		"db:\n  driver: sqlite\n  sqlite_path: " + database + "\n"
	if deferSeconds != "" {
		body += "  schema_update_defer_seconds: " + deferSeconds + "\n"
	}
	body += "secret:\n  bv_secret: 0123456789abcdef0123456789abcdef\n"
	if err := os.WriteFile(config, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return config, database
}

// asBeforeTheIndex undoes the fingerprint index migrations on a migrated
// database and gives it n events: an install upgraded across them.
func asBeforeTheIndex(t *testing.T, database string, n int) {
	t.Helper()
	c, err := sql.Open("sqlite", database)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	tx, err := c.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		if _, err := tx.Exec(`INSERT INTO unmask_event (site, host, ip_address, ja4, phase, date_created)
			VALUES ('s','h', X'0A000001', 't13d', 'serve', CURRENT_TIMESTAMP)`); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`DROP INDEX idx_unmask_event_ja4_phase`,
		`DELETE FROM schema_migrations WHERE version IN (32, 33)`,
	} {
		if _, err := c.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
}

// `unmask migrate` creates a database, reports on one, and applies what the
// daemon left for the operator.  -notice is what a package upgrade prints:
// nothing at all unless an update waits.
func TestMigrateCommand(t *testing.T) {
	t.Setenv("UNMASK_NO_PRIVDROP", "1")
	config, database := migrateConfig(t, "0.001")

	out, err := captureStdout(t, func() error { return cmdMigrate([]string{"-config", config, "-status"}) })
	if err != nil || !strings.Contains(out, "not created yet") {
		t.Fatalf("status of a new database = %q, %v", out, err)
	}
	if out, err := captureStdout(t, func() error { return cmdMigrate([]string{"-config", config, "-notice"}) }); err != nil || out != "" {
		t.Fatalf("notice on a new database = %q, %v; a new install has nothing to be told", out, err)
	}

	out, err = captureStdout(t, func() error { return cmdMigrate([]string{"-config", config}) })
	if err != nil || !strings.Contains(out, "schema applied") {
		t.Fatalf("migrate on a new database = %q, %v", out, err)
	}
	// A new install applies every migration there is, and says so in a word.
	if strings.Contains(out, "0032") || strings.Contains(out, "estimated") {
		t.Errorf("creating a database printed a plan: %q", out)
	}
	out, err = captureStdout(t, func() error { return cmdMigrate([]string{"-config", config, "-status"}) })
	if err != nil || strings.TrimSpace(out) != "schema: up to date" {
		t.Fatalf("status after creating = %q, %v", out, err)
	}

	// The install is upgraded across the index, with a table the daemon
	// will not build an index over at startup.
	asBeforeTheIndex(t, database, 500)
	out, err = captureStdout(t, func() error { return cmdMigrate([]string{"-config", config, "-status"}) })
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"2 update(s) pending", "0032_event_ja4_index", "index on unmask_event, about 500 rows", "waits for you", "unmask migrate"} {
		if !strings.Contains(out, want) {
			t.Errorf("status does not say %q:\n%s", want, out)
		}
	}
	out, err = captureStdout(t, func() error { return cmdMigrate([]string{"-config", config, "-notice"}) })
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"a database update is waiting and was NOT applied automatically", "0032_event_ja4_index", "unmask migrate", "the notice at the top of every page", "The challenge is served while it runs"} {
		if !strings.Contains(out, want) {
			t.Errorf("notice does not say %q:\n%s", want, out)
		}
	}
	// 0033 builds nothing once 0032 has: naming it would read as two builds.
	if strings.Contains(out, "0033") {
		t.Errorf("the notice names 0033, which has nothing to build:\n%s", out)
	}

	out, err = captureStdout(t, func() error { return cmdMigrate([]string{"-config", config, "-by", "alice"}) })
	if err != nil || !strings.Contains(out, "schema applied") {
		t.Fatalf("applying the update = %q, %v", out, err)
	}
	if out, err := captureStdout(t, func() error { return cmdMigrate([]string{"-config", config, "-status"}) }); err != nil || strings.TrimSpace(out) != "schema: up to date" {
		t.Fatalf("status after applying = %q, %v", out, err)
	}
	if out, err := captureStdout(t, func() error { return cmdMigrate([]string{"-config", config, "-notice"}) }); err != nil || out != "" {
		t.Fatalf("notice after applying = %q, %v", out, err)
	}

	c, err := sql.Open("sqlite", database)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	var n int
	if err := c.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_unmask_event_ja4_phase'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("the index is not there after `unmask migrate` (%d, %v)", n, err)
	}
	var value string
	if err := c.QueryRow(`SELECT value FROM unmask_maint_state WHERE name = 'schema_update'`).Scan(&value); err != nil {
		t.Fatalf("no record of the run: %v", err)
	}
	if !strings.Contains(value, `"state":"done"`) || !strings.Contains(value, `"by":"alice"`) {
		t.Errorf("record = %s", value)
	}
}

// With the default threshold a small install's index is one the daemon
// builds at startup: nothing waits for the operator, and the upgrade prints
// no notice.
func TestMigrateNoticeSilentOnASmallInstall(t *testing.T) {
	t.Setenv("UNMASK_NO_PRIVDROP", "1")
	config, database := migrateConfig(t, "")
	if _, err := captureStdout(t, func() error { return cmdMigrate([]string{"-config", config}) }); err != nil {
		t.Fatal(err)
	}
	asBeforeTheIndex(t, database, 500)
	out, err := captureStdout(t, func() error { return cmdMigrate([]string{"-config", config, "-notice"}) })
	if err != nil || out != "" {
		t.Fatalf("notice = %q, %v; the daemon applies this one by itself", out, err)
	}
	out, err = captureStdout(t, func() error { return cmdMigrate([]string{"-config", config, "-status"}) })
	if err != nil || !strings.Contains(out, "applied when the daemon starts") || strings.Contains(out, "waits for you") {
		t.Fatalf("status = %q, %v", out, err)
	}
}

// `unmask migrate -startup` is the daemon's own pass, run ahead of it by the
// container entrypoint.  It creates the schema on a new database, and on an
// upgrade leaves the long index build where the daemon would leave it --
// announced, not built: a build run in the entrypoint would use up the time
// the container's supervisor gives the daemon to come up.
func TestMigrateStartup(t *testing.T) {
	t.Setenv("UNMASK_NO_PRIVDROP", "1")
	config, database := migrateConfig(t, "0.001")

	out, err := captureStdout(t, func() error { return cmdMigrate([]string{"-config", config, "-startup"}) })
	if err != nil || !strings.Contains(out, "schema applied") {
		t.Fatalf("-startup on a new database = %q, %v", out, err)
	}
	if strings.Contains(out, "NOT applied automatically") {
		t.Fatalf("a new database has nothing to leave for the operator:\n%s", out)
	}
	hasIndex := func() bool {
		c, err := sql.Open("sqlite", database)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		var n int
		if err := c.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_unmask_event_ja4_phase'`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n > 0
	}
	if !hasIndex() {
		t.Fatal("a new database must come out of -startup complete, index included")
	}

	asBeforeTheIndex(t, database, 500)
	out, err = captureStdout(t, func() error { return cmdMigrate([]string{"-config", config, "-startup"}) })
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"schema applied", "left for the operator", "a database update is waiting and was NOT applied automatically", "unmask migrate"} {
		if !strings.Contains(out, want) {
			t.Errorf("-startup on an upgrade does not say %q:\n%s", want, out)
		}
	}
	if hasIndex() {
		t.Fatal("-startup built the index it was to leave for the operator")
	}
	// The operator's command builds it.
	if _, err := captureStdout(t, func() error { return cmdMigrate([]string{"-config", config}) }); err != nil {
		t.Fatal(err)
	}
	if !hasIndex() {
		t.Fatal("`unmask migrate` did not build the index")
	}
	// And the next start has nothing to say.
	out, err = captureStdout(t, func() error { return cmdMigrate([]string{"-config", config, "-startup"}) })
	if err != nil || strings.Contains(out, "NOT applied automatically") || strings.Contains(out, "left for the operator") {
		t.Fatalf("-startup after the update = %q, %v", out, err)
	}
}

// TestSchemaNoticeFollowsTheDatabase: the notice promises what the database
// does.  Where the run holds the write lock (SQLite) the events of that time
// are written afterwards, and the notice says so; where the index is built
// online (MariaDB) nothing waits, and a line saying otherwise would send the
// operator looking for a maintenance window they do not need.
func TestSchemaNoticeFollowsTheDatabase(t *testing.T) {
	left := []db.PendingMigration{{
		Version: 32, Name: "0032_event_ja4_index", Deferrable: true, Table: "unmask_event",
		Rows: 5000000, Indexes: []string{"idx_unmask_event_ja4_phase"},
		EstLow: 5 * time.Minute, EstHigh: 15 * time.Minute, Deferred: true,
	}}
	held := schemaNotice(left, true)
	online := schemaNotice(left, false)
	for name, out := range map[string]string{"held": held, "online": online} {
		for _, want := range []string{"NOT applied automatically", "0032_event_ja4_index", "unmask migrate", "The challenge is served while it runs"} {
			if !strings.Contains(out, want) {
				t.Errorf("%s: the notice lacks %q:\n%s", name, want, out)
			}
		}
	}
	if !strings.Contains(held, "written afterwards") {
		t.Errorf("held: the notice must say what happens to the events of that time:\n%s", held)
	}
	if strings.Contains(online, "written afterwards") {
		t.Errorf("online: nothing waits on a database that builds online, and the notice says it does:\n%s", online)
	}
}
