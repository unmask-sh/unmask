package dashboard

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
)

// AggregateStatus is where the hourly aggregate stands against the event
// table: what doctor reports, and what the stats page asks before choosing a
// raw 30-day scan over an "aggregating" notice.
//
// The daemon's own readiness flag (HourlyAggReady) is process-local and set
// when a pass finds nothing left to fold; a separate process -- doctor --
// reads the same state from the database: the cursor's position against the
// newest event.
type AggregateStatus struct {
	HasCursor bool      // a pass has recorded a cursor at all
	Cursor    int64     // highest unmask_event.id folded in
	MaxID     int64     // newest unmask_event.id
	Backlog   int64     // MaxID - Cursor: rows the rollup has not folded yet
	UpdatedAt time.Time // when the cursor last advanced (zero when HasCursor is false)
	Events    int64     // MAX(id)-MIN(id)+1 -- the O(1) size estimate the pickers use
}

// aggregateCaughtUpRows is the backlog under which the hourly aggregate counts
// as current: one chunk (hourlyBatch) is what a single 60 s tick folds, so a
// backlog inside it is the normal lag of a live install, not a rollup that is
// not keeping up.
const aggregateCaughtUpRows = hourlyBatch

// CaughtUp: the rollup is within one tick of the newest event.
func (a AggregateStatus) CaughtUp() bool { return a.HasCursor && a.Backlog <= aggregateCaughtUpRows }

// ReadAggregateStatus reads the hourly cursor and the event table's id span.
func ReadAggregateStatus(ctx context.Context, d *db.DB) (AggregateStatus, error) {
	var a AggregateStatus
	var updated sql.NullString
	err := d.QueryRowContext(ctx,
		`SELECT last_id, updated_at FROM unmask_aggregate_state WHERE name = ?`, hourlyState).Scan(&a.Cursor, &updated)
	switch {
	case err == sql.ErrNoRows:
	case err != nil:
		return a, err
	default:
		a.HasCursor = true
		if updated.Valid {
			for _, layout := range []string{"2006-01-02 15:04:05", "2006-01-02T15:04:05Z", time.RFC3339, "2006-01-02 15:04:05.000"} {
				if t, perr := time.Parse(layout, updated.String); perr == nil {
					a.UpdatedAt = t
					break
				}
			}
		}
	}
	var minID, maxID sql.NullInt64
	if err := d.QueryRowContext(ctx, `SELECT MIN(id), MAX(id) FROM unmask_event`).Scan(&minID, &maxID); err != nil {
		return a, err
	}
	if maxID.Valid {
		a.MaxID = maxID.Int64
		a.Events = maxID.Int64 - minID.Int64 + 1
		if a.HasCursor && a.MaxID > a.Cursor {
			a.Backlog = a.MaxID - a.Cursor
		} else if !a.HasCursor {
			a.Backlog = a.Events
		}
	}
	return a, nil
}

// RawScanCeiling is the event-table size past which the 30-day serve cards
// do not attempt their raw fallback while the hourly aggregate is not ready.
// The fallback reads 30 days of unmask_event; measured 2026-09-10 it took
// about 1.3 s per 300k rows, which puts the card's 15 s budget at roughly
// 3.5M rows -- and the install this exists for (kanagawa, 25M rows on a slow
// disk) was several times past it.  Below the ceiling the scan finishes and
// the page shows real numbers from the first second after a start; above it
// the card says "aggregating" at once instead of timing out and saying
// nothing.  A variable so a test can lower it.
var RawScanCeiling int64 = 2_000_000

// RawScanHopeless: the hourly aggregate has not completed a pass in this
// process, and the event table is past the size at which a raw 30-day scan
// finishes inside a card's budget.  Two rowid seeks; safe to ask per request.
func RawScanHopeless(ctx context.Context, d *db.DB) (bool, int64) {
	if HourlyAggReady() {
		return false, 0
	}
	n := int64(tableRowEstimate(ctx, d))
	return n > RawScanCeiling, n
}

// AggregateWindow is one aggregate table against the retention window
// PruneHourly enforces.
type AggregateWindow struct {
	Table     string
	OldestAge time.Duration // age of the oldest row; 0 when the table is empty
	Empty     bool
	Over      bool // oldest row is older than the window plus two days of slack
}

// AuditAggregateWindows measures the oldest row of every minute- and
// hour-grained aggregate against the shared window (hourlyKeep days).  A
// table past it is one the hourly prune is not trimming -- unmask_cookie_minute
// sat at 102 days on tool1-jp before anyone looked (2026-09-10), and was the
// slowest thing on the stats page.  Two days of slack: the prune runs hourly
// and the cutoff moves daily.
func AuditAggregateWindows(ctx context.Context, d *db.DB) ([]AggregateWindow, error) {
	now := time.Now().UTC()
	limit := time.Duration(hourlyKeep+2) * 24 * time.Hour
	type probe struct {
		table, col string
		unit       string // "min" (unix/60), "hour" (unix/3600), "text" ('YYYY-MM-DD HH' or 'YYYY-MM-DD')
	}
	probes := []probe{
		{"unmask_aggregate_hourly", "bucket_hour", "text"},
		{"unmask_aggregate_hll", "bucket", "text"},
		{"unmask_traffic_hll", "bucket_min", "min"},
		{"unmask_crawler_minute", "bucket_min", "min"},
		{"unmask_cookie_minute", "bucket_min", "min"},
		{"unmask_cookie_ip_minute", "bucket_min", "min"},
		{"unmask_crawler_detail_hourly", "bucket_hour", "hour"},
		{"unmask_traffic_country_hourly", "bucket_hour", "hour"},
	}
	out := make([]AggregateWindow, 0, len(probes))
	for _, p := range probes {
		w := AggregateWindow{Table: p.table}
		var oldest sql.NullString
		if err := d.QueryRowContext(ctx, `SELECT MIN(`+p.col+`) FROM `+p.table).Scan(&oldest); err != nil {
			// A table this binary knows but this database does not have yet
			// (an older schema mid-upgrade) is not a finding.
			if strings.Contains(strings.ToLower(err.Error()), "no such table") || strings.Contains(err.Error(), "1146") {
				continue
			}
			return out, fmt.Errorf("aggregate window %s: %w", p.table, err)
		}
		if !oldest.Valid || oldest.String == "" {
			w.Empty = true
			out = append(out, w)
			continue
		}
		var t time.Time
		switch p.unit {
		case "min", "hour":
			// An integer bucket read through NullString: the column is
			// numeric, so anything else is a schema this code does not know.
			v, err := strconv.ParseInt(strings.TrimSpace(oldest.String), 10, 64)
			if err != nil {
				return out, fmt.Errorf("aggregate window %s: oldest %s %q: %w", p.table, p.col, oldest.String, err)
			}
			if p.unit == "min" {
				t = time.Unix(v*60, 0).UTC()
			} else {
				t = time.Unix(v*3600, 0).UTC()
			}
		default:
			s := oldest.String
			if len(s) >= 13 {
				t, _ = time.Parse("2006-01-02 15", s[:13])
			} else if len(s) >= 10 {
				t, _ = time.Parse("2006-01-02", s[:10])
			}
		}
		if t.IsZero() {
			w.Empty = true
			out = append(out, w)
			continue
		}
		w.OldestAge = now.Sub(t)
		w.Over = w.OldestAge > limit
		out = append(out, w)
	}
	return out, nil
}

// AggregateKeepDays is the window PruneHourly enforces, for callers that
// name it in a message.
const AggregateKeepDays = hourlyKeep
