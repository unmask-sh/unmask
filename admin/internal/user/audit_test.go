package user

import (
	"context"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestPruneOldAudit checks the retention sweep deletes rows past the window and
// leaves fresh ones -- a DELETE, so the guard is against a wrong cutoff sign
// over-deleting the whole log.
func TestPruneOldAudit(t *testing.T) {
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: t.TempDir() + "/a.sqlite"})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer d.Close()
	if err := db.Migrate(d); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	r := New(d)
	ctx := context.Background()

	// One fresh row (now, via Record) and one stale row (100 days old).
	r.Record(ctx, 1, "alice", "login", "", "")
	stale := db.UserAudit{Username: "bob", Action: "login", At: time.Now().Add(-100 * 24 * time.Hour)}
	if err := d.Gorm.Create(&stale).Error; err != nil {
		t.Fatalf("insert stale row: %v", err)
	}

	// 90-day retention: the 100-day row goes, the fresh one stays.
	n, err := r.PruneOldAudit(ctx, 90)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 row pruned, got %d", n)
	}
	rows, err := r.ListAudit(ctx, 100, 0, 0)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 1 || rows[0].Username != "alice" {
		t.Fatalf("expected only the fresh 'alice' row to remain, got %d rows", len(rows))
	}

	// retention <= 0 is a no-op (= keep forever), not "prune everything".
	if n, _ := r.PruneOldAudit(ctx, 0); n != 0 {
		t.Fatalf("retention=0 should prune nothing, pruned %d", n)
	}
}
