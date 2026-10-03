package dashboard

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

// TestRollupReadsSeekTheirKind: every card that reads the hourly rollup asks
// for one kind over a window.  The table's primary key leads with the hour,
// so the read used to walk every kind's entries in the window and keep the
// few that matched -- over the 30-day cards' window, the whole table, once
// per card.  On a large database on a slow disk three of them ran past their
// deadline (DailyPassByDay, DailyServeByKind, DailyPassByCountry).  Migration
// 0034's index leads with the kind and carries the key and the count, and the
// planner must pick it for the shapes those cards send, with planner
// statistics and without.
func TestRollupReadsSeekTheirKind(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()

	// A rollup as the aggregator leaves it: hour by hour, a small kind (the
	// 30-day cards' own) among large ones.
	tx, err := d.Begin()
	if err != nil {
		t.Fatal(err)
	}
	stmt, err := tx.Prepare(`INSERT INTO unmask_aggregate_hourly (bucket_hour, bucket_kind, bucket_key, cnt) VALUES (?, ?, ?, 1)`)
	if err != nil {
		t.Fatal(err)
	}
	perHour := map[string]int{hkCookiePass: 4, hkServeKind: 9, hkCountryPass: 30, hkFunnel: 20, "fnls": 60, hkCountry: 10}
	now := time.Now().UTC()
	for h := 0; h < 32*24; h++ {
		hour := now.Add(-time.Duration(h) * time.Hour).Format("2006-01-02 15")
		for kind, n := range perHour {
			for i := 0; i < n; i++ {
				if _, err := stmt.Exec(hour, kind, fmt.Sprintf("k%d", i)); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	from := now.Add(-30 * 24 * time.Hour).Format("2006-01-02 15")
	upTo := now.Format("2006-01-02 15")
	shapes := []struct {
		card, sql string
		args      []any
	}{
		{"DailyPassByDay", `SELECT bucket_hour, bucket_key, cnt FROM unmask_aggregate_hourly
			WHERE bucket_kind = ? AND bucket_hour >= ? AND bucket_hour <= ?`, []any{hkCookiePass, from, upTo}},
		{"DailyPassByCountry", `SELECT bucket_hour, bucket_key, cnt FROM unmask_aggregate_hourly
			WHERE bucket_kind = ? AND bucket_hour >= ? AND bucket_hour <= ?`, []any{hkCountryPass, from, upTo}},
		{"DailyServeByKind", fmt.Sprintf(`SELECT bucket_hour, bucket_key, cnt FROM unmask_aggregate_hourly
			WHERE bucket_kind = '%s' AND %s AND bucket_hour < '%s'`, hkServeKind, hourWindow(ctx, 30*24, "bucket_hour"), upTo), nil},
	}
	check := func(when string) {
		t.Helper()
		for _, s := range shapes {
			rows, err := d.QueryContext(ctx, "EXPLAIN QUERY PLAN "+s.sql, s.args...)
			if err != nil {
				t.Fatalf("%s (%s): %v", s.card, when, err)
			}
			var plan []string
			for rows.Next() {
				var id, parent, notused int
				var detail string
				if err := rows.Scan(&id, &parent, &notused, &detail); err != nil {
					rows.Close()
					t.Fatal(err)
				}
				plan = append(plan, detail)
			}
			rows.Close()
			got := strings.Join(plan, " / ")
			if !strings.Contains(got, "COVERING INDEX idx_unmask_aggregate_hourly_kind") || !strings.Contains(got, "bucket_kind=?") {
				t.Errorf("%s (%s): the read does not seek its kind in the covering index:\n  %s", s.card, when, got)
			}
		}
	}
	check("no planner statistics")
	if err := d.RefreshPlannerStats(ctx); err != nil {
		t.Fatal(err)
	}
	check("with planner statistics")
}
