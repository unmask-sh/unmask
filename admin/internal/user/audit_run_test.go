package user

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The daemon's own entries: a new database's first start is an install, a
// start as another version an update (from → to), a start as the same
// version nothing, and the migrations a start applied a schema update.  A
// database from before the record, with accounts, is an update from an
// unknown version, not an install.
func TestRecordStart(t *testing.T) {
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: t.TempDir() + "/a.sqlite"})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := db.Migrate(d); err != nil {
		t.Fatal(err)
	}
	r := New(d)
	ctx := context.Background()
	actions := func() []string {
		rows, err := r.ListAudit(ctx, 100, 0, 0)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for i := len(rows) - 1; i >= 0; i-- { // oldest first
			out = append(out, rows[i].Username+":"+rows[i].Action+":"+rows[i].Target.String)
		}
		return out
	}

	applied := []db.AppliedMigration{{Name: "0037_event_card_indexes", Elapsed: 83 * time.Second}}
	// A new database's first start builds the whole schema: the install
	// is the entry, not the list of every migration.
	r.RecordStart(ctx, "0.1.52", "abc1234", applied)
	if got := strings.Join(actions(), " | "); got != "system:install:0.1.52" {
		t.Fatalf("first start: %s", got)
	}
	// The same version again: a restart, not an entry.
	r.RecordStart(ctx, "0.1.52", "abc1234", nil)
	if n := len(actions()); n != 1 {
		t.Fatalf("a restart wrote %d entries", n-1)
	}
	// A start that applied a migration: a schema update, timed.
	r.RecordStart(ctx, "0.1.52", "abc1234", applied)
	rows, _ := r.ListAudit(ctx, 1, 0, 0)
	if len(rows) != 1 || rows[0].Action != "schema_update" || rows[0].Target.String != "0037_event_card_indexes" ||
		!strings.Contains(rows[0].Detail.String, `"seconds":83`) {
		t.Fatalf("schema update at a start: %+v", rows)
	}
	r.RecordStart(ctx, "0.1.53", "def5678", nil)
	rows, _ = r.ListAudit(ctx, 1, 0, 0)
	if len(rows) != 1 || rows[0].Action != "update" || rows[0].Target.String != "0.1.53" || rows[0].UserID.Valid ||
		!strings.Contains(rows[0].Detail.String, `"from":"0.1.52"`) || !strings.Contains(rows[0].Detail.String, `"commit":"def5678"`) {
		t.Fatalf("update entry: %+v", rows)
	}
	// Back to the earlier version: an update too, read by its from and to.
	r.RecordStart(ctx, "0.1.52", "abc1234", nil)
	rows, _ = r.ListAudit(ctx, 1, 0, 0)
	if rows[0].Action != "update" || !strings.Contains(rows[0].Detail.String, `"from":"0.1.53"`) {
		t.Fatalf("downgrade entry: %+v", rows[0])
	}

	// A run typed at a shell, and one the admin UI started under a name.
	r.RecordSchemaUpdate(ctx, "", applied)
	r.RecordSchemaUpdate(ctx, "alice", applied)
	r.RecordSchemaUpdate(ctx, "alice", nil) // nothing applied, nothing written
	got := actions()
	if len(got) != 6 || got[4] != "cli:schema_update:0037_event_card_indexes" || got[5] != "alice:schema_update:0037_event_card_indexes" {
		t.Fatalf("schema update entries: %v", got)
	}
	if !IsSystemActor("system") || !IsSystemActor("cli") || IsSystemActor("alice") {
		t.Error("IsSystemActor")
	}
}

func TestRecordStartOnAnExistingDatabase(t *testing.T) {
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: t.TempDir() + "/a.sqlite"})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := db.Migrate(d); err != nil {
		t.Fatal(err)
	}
	r := New(d)
	ctx := context.Background()
	if _, err := r.Create(ctx, "admin", "Passw0rd-long-enough", RoleSuperadmin); err != nil {
		t.Fatal(err)
	}
	r.RecordStart(ctx, "0.1.52", "", nil)
	rows, _ := r.ListAudit(ctx, 1, 0, 0)
	if len(rows) != 1 || rows[0].Action != "update" || rows[0].Username != SystemActor || strings.Contains(rows[0].Detail.String, "from") {
		t.Fatalf("an existing database's first recorded start: %+v", rows)
	}
}
