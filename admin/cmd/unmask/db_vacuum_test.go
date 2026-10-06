package main

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// vacuumConfig is a config over a migrated database holding n events, every
// other one deleted.
func vacuumConfig(t *testing.T, n int) (config, database string) {
	t.Helper()
	config, database = migrateConfig(t, "")
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: database})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := db.Migrate(d); err != nil {
		t.Fatal(err)
	}
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
		if _, err := tx.Exec(`INSERT INTO unmask_event (site, host, ip_address, ja4, phase, payload_json, date_created)
			VALUES ('s','h', ?, ?, 'serve', ?, CURRENT_TIMESTAMP)`, []byte{10, byte(i >> 16), byte(i >> 8), byte(i)},
			fmt.Sprintf("t13d%06x", i), fmt.Sprintf(`{"bt":"tok.%08x","orig_path":"/p/%d"}`, i, i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Exec(`DELETE FROM unmask_event WHERE id % 2 = 0`); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		t.Fatal(err)
	}
	return config, database
}

// -plan says what a run gives back and needs, and changes nothing.  A run over
// a database with little to give back is refused unless forced; forced, it
// compacts and says by how much.
func TestDBVacuumCommand(t *testing.T) {
	config, database := vacuumConfig(t, 3000)
	st0, _ := os.Stat(database)

	out, err := captureStdout(t, func() error { return cmdDBVacuum([]string{"-config", config, "-plan"}) })
	if err != nil {
		t.Fatal(err)
	}
	// The database has no planner statistics (nothing has analysed it): the
	// run builds them, and the plan says so.
	for _, want := range []string{"after compaction", "needs about", "expected to take", "holds its writes",
		"there are no query planner statistics yet"} {
		if !strings.Contains(out, want) {
			t.Errorf("-plan output lacks %q:\n%s", want, out)
		}
	}
	if st, _ := os.Stat(database); st.Size() != st0.Size() {
		t.Error("-plan changed the database")
	}

	// A few hundred KB free: not worth holding the daemon's writes for.
	_, err = captureStdout(t, func() error { return cmdDBVacuum([]string{"-config", config}) })
	if err == nil || !strings.Contains(err.Error(), "-force") {
		t.Fatalf("err = %v, want a refusal that names -force", err)
	}

	out, err = captureStdout(t, func() error { return cmdDBVacuum([]string{"-config", config, "-force"}) })
	if err != nil {
		t.Fatalf("forced run: %v\n%s", err, out)
	}
	if !strings.Contains(out, "done: the file went from") || !strings.Contains(out, "the query planner's statistics built in") {
		t.Errorf("output lacks the result:\n%s", out)
	}
	out, err = captureStdout(t, func() error { return cmdDBVacuum([]string{"-config", config, "-plan"}) })
	if err != nil || strings.Contains(out, "query planner statistics") {
		t.Errorf("-plan after the run still offers the statistics (%v):\n%s", err, out)
	}
	if st, _ := os.Stat(database); st.Size() >= st0.Size() {
		t.Errorf("file %d -> %d: nothing given back", st0.Size(), st.Size())
	}
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: database})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	rec, ok, err := d.LoadVacuum(context.Background())
	if err != nil || !ok || rec.State != db.VacuumDone || rec.By != db.VacuumByCLI {
		t.Errorf("record = %+v ok=%v err=%v", rec, ok, err)
	}
}

// With a daemon answering that does not hand over -- one older than the
// command -- the run gives up before it takes the write lock, and says why.
func TestDBVacuumWaitsForTheDaemon(t *testing.T) {
	config, database := vacuumConfig(t, 200)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	port := l.Addr().(*net.TCPAddr).Port
	body, err := os.ReadFile(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config, []byte(strings.Replace(string(body), "port: 19478", "port: "+strconv.Itoa(port), 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	st0, _ := os.Stat(database)
	_, err = captureStdout(t, func() error {
		return cmdDBVacuum([]string{"-config", config, "-force", "-wait-held", "300ms"})
	})
	if err == nil || !strings.Contains(err.Error(), "did not stop writing") {
		t.Fatalf("err = %v, want the daemon's missing hand-over", err)
	}
	if st, _ := os.Stat(database); st.Size() != st0.Size() {
		t.Error("the database changed although the daemon never stopped writing")
	}
}
