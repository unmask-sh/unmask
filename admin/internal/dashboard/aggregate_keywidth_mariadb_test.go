package dashboard

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/events"
)

// TestMariaDB_FoldTakesAnEntryOfAnyLength: the hourly fold writes the count
// of a rule whose name is long, and goes on to the events behind it.
//
// The stats card breaks a force reason down by the entry behind it, in a
// rollup row keyed '<force_reason>|<entry>'.  The beacon keeps an entry of up
// to 200 characters (an operator's own UA pattern, a trap's title, a
// protected path), and bucket_key was VARCHAR(128).  Under MariaDB's default
// sql_mode a longer key is an error (1406) that rolls back the chunk's
// transaction, the cursor with it: every pass folded the same chunk into the
// same error, and no event after it reached the rollups until the row left
// the events table by retention.  Migration 0055 widens the column to 255,
// and the fold cuts a key to it.
// Skips unless UNMASK_TEST_MARIADB_HOST is set (= make test-mariadb).
func TestMariaDB_FoldTakesAnEntryOfAnyLength(t *testing.T) {
	cfg := mariadbSettingsFromEnv(t)
	d, err := db.Open(cfg)
	if err != nil {
		t.Fatalf("open mariadb: %v", err)
	}
	defer d.Close()
	if err := db.Migrate(d); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	ctx := context.Background()
	for _, q := range []string{
		`DELETE FROM unmask_event`,
		`DELETE FROM unmask_aggregate_hourly`,
		`DELETE FROM unmask_aggregate_hll`,
		`DELETE FROM unmask_aggregate_state WHERE name = '` + hourlyState + `'`,
	} {
		if _, err := d.ExecContext(ctx, q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	defer hourlyReady.Store(false)
	settleNothing(t)

	// An operator's own UA pattern of 150 characters, ordinary for a list of
	// client libraries; the entry is "own:<pattern>".  And one no beacon
	// keeps today, as a row written by other means could carry.
	entry := "own:" + strings.Repeat("python-requests|", 9) + "curl/x"
	if len(entry) != 154 {
		t.Fatalf("the entry is %d characters", len(entry))
	}
	tooLong := "own:" + strings.Repeat("あ", 400)
	n := 0
	insert := func(phase string, payload map[string]any) {
		t.Helper()
		n++
		if err := events.Insert(ctx, d, &events.Event{
			Site: "keywidth.example", Phase: phase, Payload: payload,
			IPPacked: events.PackIP(fmt.Sprintf("203.0.113.%d", n%250+1)),
		}); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}
	insert("load", map[string]any{"force_reason": "ua_target", "force_rule": entry})
	insert("load", map[string]any{"force_reason": "ua_target", "force_rule": tooLong})
	for i := 0; i < 50; i++ {
		insert("serve", map[string]any{"force_reason": "none"})
	}

	for pass := 1; pass <= 2; pass++ {
		if err := AggregateHourly(ctx, d, nil); err != nil {
			t.Fatalf("pass %d: the fold was refused: %v", pass, err)
		}
	}
	var serves int
	if err := d.QueryRowContext(ctx,
		`SELECT COALESCE(SUM(cnt), 0) FROM unmask_aggregate_hourly WHERE bucket_kind = ? AND bucket_key = 'serve'`,
		hkPhase).Scan(&serves); err != nil {
		t.Fatal(err)
	}
	if serves != 50 {
		t.Errorf("%d of the 50 serve events behind the long entry were folded", serves)
	}
	for _, table := range []string{"unmask_aggregate_hourly", "unmask_aggregate_hll"} {
		kind := hkCaptchaForceRule
		if table == "unmask_aggregate_hll" {
			kind = hkCaptchaForceRuleIP
		}
		rows, err := d.QueryContext(ctx, `SELECT bucket_key FROM `+table+` WHERE bucket_kind = ?`, kind)
		if err != nil {
			t.Fatal(err)
		}
		whole, cut := false, false
		for rows.Next() {
			var k string
			if err := rows.Scan(&k); err != nil {
				t.Fatal(err)
			}
			switch {
			case k == "ua_target|"+entry:
				whole = true
			case strings.HasPrefix(k, "ua_target|own:ああ") && utf8.RuneCountInString(k) == bucketKeyWidth:
				cut = true
			default:
				t.Errorf("%s: an unexpected key of %d characters: %.60s...", table, utf8.RuneCountInString(k), k)
			}
		}
		rows.Close()
		if !whole {
			t.Errorf("%s: the entry of %d characters is not there whole", table, len(entry))
		}
		if !cut {
			t.Errorf("%s: the entry past the column's width is not there cut to %d characters", table, bucketKeyWidth)
		}
	}
}
