package user

import (
	"context"
	"encoding/json"
	"log"
	"strings"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
)

// The audit log's entries for what the software did to itself: an install,
// an update, a schema update.  They sit in the same log as the operator's
// actions, since an update is one -- and it is the one that explains a
// change in the figures that no setting accounts for.  The daemon's log
// says the same, and journals are rotated; this log keeps its retention.
//
// The daemon tells an update at its start, by the version it last ran as
// (maint state lastRun): a restart with the same version writes nothing, so
// the log is not restarts.  No package script writes here -- the daemon's
// start follows every way of installing, and the database is the daemon's.

// SystemActor is the username of an entry the daemon wrote on its own,
// with no account behind it.  db.SchemaUpdateByCLI names the one typed at a
// shell.
const SystemActor = "system"

// maintLastRun is the maint-state record of the version the daemon last
// started as.
const maintLastRun = "last_run"

type lastRunRecord struct {
	Version string `json:"version"`
	Commit  string `json:"commit,omitempty"`
	At      int64  `json:"at"`
}

// RecordStart writes what a start of the daemon changed: "install" on the
// first start of a new database, "update" when the version differs from the
// one that last ran (from → to), and "schema_update" for the migrations the
// start applied -- except on the install, where every migration there is
// runs over an empty database and the entry would list them all for
// nothing.  Best-effort, like every audit write.
func (r *Repository) RecordStart(ctx context.Context, version, commit string, applied []db.AppliedMigration) {
	if r == nil || r.DB == nil || version == "" {
		return
	}
	var last lastRunRecord
	known, err := r.DB.LoadMaintState(ctx, maintLastRun, &last)
	if err != nil {
		log.Printf("audit: last run: %v", err)
		return
	}
	install := false
	switch {
	case !known:
		// A database from before this record: an existing install (it has
		// accounts) updated to the first version that keeps one, or a new
		// one that the setup wizard has not been run on yet.
		if n, err := r.Count(ctx); err == nil && n == 0 {
			install = true
			r.Record(ctx, 0, SystemActor, "install", version, runDetail("", version, commit))
		} else {
			r.Record(ctx, 0, SystemActor, "update", version, runDetail("", version, commit))
		}
	case last.Version != version:
		r.Record(ctx, 0, SystemActor, "update", version, runDetail(last.Version, version, commit))
	}
	if len(applied) > 0 && !install {
		r.Record(ctx, 0, SystemActor, "schema_update", schemaTarget(applied), schemaDetail(applied))
	}
	if !known || last.Version != version || last.Commit != commit {
		if err := r.DB.SaveMaintState(ctx, maintLastRun, lastRunRecord{Version: version, Commit: commit, At: time.Now().Unix()}); err != nil {
			log.Printf("audit: last run: %v", err)
		}
	}
}

// RecordSchemaUpdate writes the migrations a run of `unmask migrate`
// applied, under the name the run was started by: db.SchemaUpdateByCLI at a
// shell, the administrator's when the admin UI started it (which logged the
// start under their account).
func (r *Repository) RecordSchemaUpdate(ctx context.Context, by string, applied []db.AppliedMigration) {
	if r == nil || len(applied) == 0 {
		return
	}
	if by == "" {
		by = db.SchemaUpdateByCLI
	}
	r.Record(ctx, 0, by, "schema_update", schemaTarget(applied), schemaDetail(applied))
}

// IsSystemActor reports whether an audit entry's username is the daemon's
// or the shell's rather than an account's.
func IsSystemActor(username string) bool {
	return username == SystemActor || username == db.SchemaUpdateByCLI
}

func runDetail(from, to, commit string) string {
	d := map[string]string{"to": to}
	if from != "" {
		d["from"] = from
	}
	if commit != "" {
		d["commit"] = commit
	}
	b, _ := json.Marshal(d)
	return string(b)
}

// schemaTarget names the migrations in the target column (128 characters),
// the detail carrying each one in full with how long it took.
func schemaTarget(applied []db.AppliedMigration) string {
	names := make([]string, 0, len(applied))
	for _, a := range applied {
		names = append(names, a.Name)
	}
	t := strings.Join(names, ", ")
	if len(t) > 128 {
		t = t[:125] + "..."
	}
	return t
}

func schemaDetail(applied []db.AppliedMigration) string {
	type one struct {
		Name    string  `json:"name"`
		Seconds float64 `json:"seconds"`
	}
	out := make([]one, 0, len(applied))
	for _, a := range applied {
		out = append(out, one{Name: a.Name, Seconds: float64(a.Elapsed.Round(10*time.Millisecond)) / float64(time.Second)})
	}
	b, _ := json.Marshal(map[string]any{"applied": out})
	return string(b)
}
