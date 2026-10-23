package events

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestWindowRowsSeeksTheIdEnds: the whole-table estimate reads MIN(id) and
// MAX(id) in two statements.  SQLite seeks an index end for a lone aggregate
// only; the two together in one statement walk the whole covering index.
func TestWindowRowsSeeksTheIdEnds(t *testing.T) {
	tmp, _ := os.MkdirTemp("", "wrows-*")
	t.Cleanup(func() { os.RemoveAll(tmp) })
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: filepath.Join(tmp, "t.db")})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer d.Close()
	if err := db.Migrate(d); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	ctx := context.Background()
	explain := func(stmt string) string {
		rows, err := d.QueryContext(ctx, "EXPLAIN QUERY PLAN "+stmt)
		if err != nil {
			t.Fatalf("explain: %v", err)
		}
		defer rows.Close()
		var sb strings.Builder
		for rows.Next() {
			var id, parent, notused int
			var detail string
			if err := rows.Scan(&id, &parent, &notused, &detail); err != nil {
				t.Fatal(err)
			}
			sb.WriteString(detail + " | ")
		}
		return sb.String()
	}
	for _, stmt := range []string{"SELECT MIN(id) FROM unmask_event", "SELECT MAX(id) FROM unmask_event"} {
		if plan := explain(stmt); strings.Contains(plan, "SCAN") {
			t.Fatalf("%s: %s", stmt, plan)
		}
	}
	if n, err := WindowRows(ctx, d, 0); err != nil || n != 0 {
		t.Fatalf("WindowRows on an empty table: %d, %v", n, err)
	}
}
