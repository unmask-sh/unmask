package db

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// schemaOf: what the database's schema is, by name, with the white space of
// each definition folded so that a table reached by a rename reads like one
// created in place.
func schemaOf(t *testing.T, d *DB) map[string]string {
	t.Helper()
	rows, err := d.Query(`SELECT type, name, COALESCE(sql,'') FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var typ, name, sql string
		if err := rows.Scan(&typ, &name, &sql); err != nil {
			t.Fatal(err)
		}
		out[typ+" "+name] = strings.Join(strings.Fields(sql), " ")
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// The migrator runs a file one statement at a time and records the version
// after the last, so a process that dies part-way leaves the first
// statements applied and the file to run again from its top at the next
// start.  Every file therefore has to finish from every such state -- and
// two did not: 0023 and 0045 rebuild a table (create _v2, copy, drop the
// old, rename), and a run that died between the DROP and the RENAME left no
// table of the old name for the copy to read.  The next start, and every one
// after, stopped on "no such table" with that migration and all the later
// ones unapplied.
//
// For every SQLite migration: on a database as it is when that migration's
// turn comes (the base schema and every migration before it), run its first
// k statements (k from none to all of them), and let the migrator take over
// as the next start does.  It has to finish, and leave the schema a database
// that was never interrupted has.
func TestEveryMigrationFinishesAfterACrashBetweenItsStatements(t *testing.T) {
	open := func(name string) *DB {
		t.Helper()
		d, err := Open(settings.DB{Driver: "sqlite", SQLitePath: filepath.Join(t.TempDir(), name)})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { d.Close() })
		return d
	}
	// before: the database when the migration numbered `version` is next.
	before := func(name string, version int) *DB {
		t.Helper()
		d := open(name)
		if err := migrateBase(d); err != nil {
			t.Fatal(err)
		}
		pending, err := pendingMigrations(d, false)
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range pending {
			if p.Version >= version {
				break
			}
			if _, err := applyMigration(d, p, MigrateOptions{}); err != nil {
				t.Fatalf("%s: %v", p.Name, err)
			}
		}
		return d
	}
	ref := open("reference.sqlite")
	if err := Migrate(ref); err != nil {
		t.Fatal(err)
	}
	want := schemaOf(t, ref)

	migs, err := listMigrations("sqlite")
	if err != nil || len(migs) < 40 {
		t.Fatalf("listMigrations: %d files, err %v", len(migs), err)
	}
	rebuilds, cases := 0, 0
	for _, m := range migs {
		body, err := fs.ReadFile(migrationFS, m.path)
		if err != nil {
			t.Fatal(err)
		}
		var stmts []string
		for _, s := range splitStatements(string(body)) {
			if s = strings.TrimSpace(s); s != "" {
				stmts = append(stmts, s)
			}
		}
		if strings.Contains(strings.ToUpper(string(body)), "DROP TABLE") {
			rebuilds++
		}
		if m.version == 1 {
			continue // the baseline marker: nothing to run
		}
		for k := 0; k <= len(stmts); k++ {
			cases++
			d := before(fmt.Sprintf("m%04d-k%d.sqlite", m.version, k), m.version)
			died := ""
			for i := 0; i < k; i++ {
				// What the migrator itself lets pass (a column or an index
				// that is there already) is not a failure of the setup.
				if _, err := d.Exec(stmts[i]); err != nil && !isAlreadyAppliedErr(err) {
					t.Fatalf("%s: statement %d of the setup: %v\n%s", m.name, i+1, err, stmts[i])
				}
				died = stmts[i]
			}
			if _, err := RunMigrationsOpts(d, MigrateOptions{}); err != nil {
				after := "before its first statement"
				if died != "" {
					after = "after: " + strings.Join(strings.Fields(died), " ")
					if len(after) > 110 {
						after = after[:110] + "..."
					}
				}
				t.Errorf("%s, a run that died %s (%d of %d statements): the next run stops: %v", m.name, after, k, len(stmts), firstLine(err))
				continue
			}
			var recorded int
			if err := d.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE version = ?`, m.version).Scan(&recorded); err != nil || recorded != 1 {
				t.Errorf("%s after %d statements: the next run did not record it (count %d, err %v)", m.name, k, recorded, err)
			}
			got := schemaOf(t, d)
			for name, sql := range want {
				if got[name] != sql {
					t.Errorf("%s after %d of %d statements: %s differs from an uninterrupted database's:\n  got  %s\n  want %s", m.name, k, len(stmts), name, got[name], sql)
				}
			}
			for name := range got {
				if _, ok := want[name]; !ok {
					t.Errorf("%s after %d of %d statements: %s is left over", m.name, k, len(stmts), name)
				}
			}
			d.Close()
		}
	}
	// The premise: the files that rebuild a table are among those tried.
	if rebuilds < 2 || cases < 100 {
		t.Errorf("%d files rebuild a table and %d interruptions were tried: the test does not test what it says", rebuilds, cases)
	}
}

func firstLine(err error) string {
	s := err.Error()
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
