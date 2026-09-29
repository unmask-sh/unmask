package events

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
)

// JA4ChainRow is one step of a challenge session's fingerprint history: the
// phase, the JA4 the connection carrying it actually presented, and the
// verdict recorded at the time (historical truth, not a re-resolution).
//
// Referer is where the visitor came from, and it is on the row of the request
// that was challenged -- the serve -- and on no other: the beacons that follow
// are sent by the challenge page and would only name the site itself.  A hunt
// view filtered to the passes therefore holds no row that can say it, which is
// why it travels with this on-demand read.
type JA4ChainRow struct {
	AtMs    int64
	Phase   string
	JA4     string
	Verdict string
	Referer string
}

// JA4Chain returns every event carrying beacon token bt around aroundUnix, in
// record order -- the serve, each beacon, and any rebind rows.  This is the
// on-demand backing for the hunt page's ⇄ popover: the fingerprints here are
// what each TLS connection presented as recorded server-side, which is what
// makes the history trustworthy where the client-echoed serve_ja4 (the badge
// TRIGGER) deliberately is not.
//
// bt lives only inside payload_json, so the match is a LIKE -- bounded to a
// ±2h window on the indexed date column precisely so one operator click scans
// a few thousand rows, not the table.  The caller validates bt's charset
// ([a-z0-9.]), which is also what keeps the LIKE free of wildcards.  Capped at
// limit rows; the second return says whether more existed.
func JA4Chain(ctx context.Context, d *db.DB, bt string, aroundUnix int64, limit int) ([]JA4ChainRow, bool, error) {
	const w = "2006-01-02 15:04:05"
	from := time.Unix(aroundUnix-7200, 0).UTC().Format(w)
	to := time.Unix(aroundUnix+7200, 0).UTC().Format(w)
	stmt := `SELECT date_created, phase, ja4, ja4_verdict, payload_json FROM unmask_event` +
		d.EventDateIndexHint("date_created BETWEEN") +
		` WHERE date_created BETWEEN ? AND ? AND payload_json LIKE ? ORDER BY id LIMIT ?`
	rows, err := d.QueryContext(ctx, stmt, from, to, `%"bt":"`+bt+`"%`, limit+1)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()

	var out []JA4ChainRow
	for rows.Next() {
		// SQLite hands date_created back as TEXT, MariaDB as time.Time -- the
		// same split every other events reader handles, funneled through
		// normalizeEventTime so the layouts stay in one place.
		var (
			date                         sql.NullTime
			dateStr                      sql.NullString
			phase, ja4, verdict, payload sql.NullString
		)
		var scanErr error
		if d.Driver == db.DriverSQLite {
			scanErr = rows.Scan(&dateStr, &phase, &ja4, &verdict, &payload)
		} else {
			scanErr = rows.Scan(&date, &phase, &ja4, &verdict, &payload)
		}
		if scanErr != nil {
			return nil, false, scanErr
		}
		_, _, tsMs := normalizeEventTime(date, dateStr)
		out = append(out, JA4ChainRow{
			AtMs: tsMs, Phase: phase.String, JA4: ja4.String, Verdict: verdict.String,
			Referer: chainReferer(payload.String),
		})
	}
	truncated := len(out) > limit
	if truncated {
		out = out[:limit]
	}
	return out, truncated, rows.Err()
}

// chainReferer reads "referer" out of one row's payload_json.  A real JSON
// decode rather than the substring extractors the list view uses: those hand
// back the value as stored, and the writer stores "&" as \u0026, so a search
// URL would reach the operator with the escape in it.  At most a few dozen
// rows per click, so the decode costs nothing worth saving.
func chainReferer(payload string) string {
	if payload == "" {
		return ""
	}
	var p struct {
		Referer string `json:"referer"`
	}
	if err := json.Unmarshal([]byte(payload), &p); err != nil {
		return ""
	}
	return p.Referer
}
