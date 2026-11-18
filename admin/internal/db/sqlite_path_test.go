package db

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// db.sqlite_path names a file.  It goes into the connection string ahead of
// the daemon's own parameters, and the driver reads from the first '?' on as
// parameters: a path with one chose its own.  Open refuses it, whoever wrote
// it -- the setup wizard's form, config.yml.
func TestOpenTakesAPathForSQLite(t *testing.T) {
	dir := t.TempDir()
	for _, c := range []struct{ path, want string }{
		{filepath.Join(dir, "a.sqlite") + "?_pragma=journal_mode(DELETE)", "connection parameters"},
		{filepath.Join(dir, "b.sqlite") + "?", "connection parameters"},
		{"file:" + filepath.Join(dir, "c.sqlite"), "not a file: URI"},
		{" File:" + filepath.Join(dir, "d.sqlite"), "not a file: URI"},
		{filepath.Join(dir, "e\x00.sqlite"), "control character"},
	} {
		d, err := Open(settings.DB{Driver: "sqlite", SQLitePath: c.path})
		if err == nil {
			d.Close()
			t.Errorf("%q: opened", c.path)
			continue
		}
		if !strings.Contains(err.Error(), c.want) || !strings.Contains(err.Error(), "db.sqlite_path") {
			t.Errorf("%q: %v, want an error about db.sqlite_path naming %q", c.path, err, c.want)
		}
	}
	if es, _ := os.ReadDir(dir); len(es) != 0 {
		t.Errorf("the refused paths left %d entries in the directory", len(es))
	}
	// What a path may be: spaces, a '#', an '&', a '%' -- characters of a
	// file's name, which the driver takes as such.
	for _, name := range []string{"plain.sqlite", "with space.sqlite", "hash#1.sqlite", "amp&x=y.sqlite", "pct%20.sqlite", "café.sqlite"} {
		p := filepath.Join(dir, name)
		d, err := Open(settings.DB{Driver: "sqlite", SQLitePath: p})
		if err != nil {
			t.Errorf("%q: %v", name, err)
			continue
		}
		if _, err := d.Exec(`CREATE TABLE t (x INTEGER)`); err != nil {
			t.Errorf("%q: %v", name, err)
		}
		d.Close()
		if _, err := os.Stat(p); err != nil {
			t.Errorf("%q: the database is not at the path it was given: %v", name, err)
		}
	}
	// And the daemon's own parameters are the ones in force.
	d, err := Open(settings.DB{Driver: "sqlite", SQLitePath: filepath.Join(dir, "mode.sqlite")})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	var mode string
	if err := d.QueryRow(`PRAGMA journal_mode`).Scan(&mode); err != nil || !strings.EqualFold(mode, "wal") {
		t.Errorf("journal_mode = %q (err %v), want wal", mode, err)
	}
}
