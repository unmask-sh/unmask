package dashboard

import (
	"context"
	"fmt"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
)

// OldestEventTS returns the unix-sec timestamp of the earliest unmask_event row
// (0 when the table is empty).  It bounds the lower edge of the custom-range
// calendar so an operator can't pick a date with no data behind it.
func OldestEventTS(ctx context.Context, d *db.DB) (int64, error) {
	q := `SELECT COALESCE(CAST(strftime('%s', MIN(date_created)) AS INTEGER), 0) FROM unmask_event`
	if d.Driver != db.DriverSQLite {
		q = `SELECT COALESCE(UNIX_TIMESTAMP(MIN(date_created)), 0) FROM unmask_event`
	}
	var ts int64
	err := d.QueryRowContext(ctx, q).Scan(&ts)
	return ts, err
}

// OldestAggregateTS returns the unix time of the oldest hourly-aggregate bucket
// on hand, or 0 when there is none.
//
// It bounds how far back the stats page can honestly look.  The page mixes two
// sources: the summary figures and the per-day series read
// unmask_aggregate_hourly, which is pruned on a fixed window (hourlyKeep) and
// deliberately does NOT follow events_retention_days; the funnel, country and
// flag cards read raw unmask_event, which does.  Offering a range the
// aggregates cannot cover produces a page whose totals are labelled with a
// window several times longer than the data behind them -- the kind of figure
// an operator has no way to spot as wrong.  So the range picker asks this, not
// just how old the oldest event is.
func OldestAggregateTS(ctx context.Context, d *db.DB) (int64, error) {
	// bucket_hour is the text 'YYYY-MM-DD HH', not an epoch: MIN() over it is
	// still the oldest bucket (the format sorts chronologically), but it has to
	// be parsed back rather than multiplied.
	var b string
	if err := d.QueryRowContext(ctx,
		`SELECT COALESCE(MIN(bucket_hour), '') FROM unmask_aggregate_hourly`).Scan(&b); err != nil {
		return 0, err
	}
	if b == "" {
		return 0, nil
	}
	t, err := time.Parse("2006-01-02 15", b)
	if err != nil {
		return 0, nil // unparseable = treat as no history rather than a bogus bound
	}
	return t.Unix(), nil
}

// windowCtxKey carries a request's resolved Window through context so the query
// helpers can apply a custom [from,to] range without threading a new parameter
// through ~40 query signatures.  The window is a single per-request ambient
// value (every card on a page shares the same range), like a deadline -- a
// legitimate context use.  When absent, the helpers fall back to the legacy
// trailing window built from the call's `hours`, so any un-migrated caller keeps
// its exact previous behaviour.
type windowCtxKey struct{}

// WithWindow attaches a resolved Window to ctx.  The stats / hunt handlers call
// this once after resolving the range param; every dashboard query run under
// that ctx then bounds to [w.Start, w.End].
func WithWindow(ctx context.Context, w Window) context.Context {
	return context.WithValue(ctx, windowCtxKey{}, w)
}

// windowOr returns the ctx Window if one was attached, else a trailing window of
// `trailingHours` ending now (the legacy preset behaviour).
func windowOr(ctx context.Context, trailingHours int) Window {
	if w, ok := ctx.Value(windowCtxKey{}).(Window); ok {
		return w
	}
	return WindowTrailing(time.Now(), trailingHours)
}

// hourWindow / minWindow / tsWindow are the per-column window predicates the
// query SQL embeds in place of the old `col >= hourAgoExpr(...)` lower-bound.
// Each resolves the effective window (ctx override or trailing `hours`) and
// emits an inclusive lower+upper clause.  Driver-agnostic literals, so no *db.DB
// is needed.
func hourWindow(ctx context.Context, hours int, col string) string {
	return windowOr(ctx, hours).HourClause(col)
}
func minWindow(ctx context.Context, hours int, col string) string {
	return windowOr(ctx, hours).MinClause(col)
}
func tsWindow(ctx context.Context, hours int, col string) string {
	return windowOr(ctx, hours).TimestampClause(col)
}

// Window is an absolute [Start, End] time range in unix seconds (UTC).
//
// It replaces the older "N hours back from now" model so the dashboard can show
// an arbitrary operator-chosen period (a custom calendar range), not just a
// trailing window.  The presets (24h / 7d / 30d) are expressed as trailing
// windows ending at now; a "custom" range carries explicit endpoints.
//
// All buckets are stored UTC at rest (CLAUDE.md #6), so the clause helpers emit
// UTC literals.  They are plain string / integer literals, NOT driver-specific
// date math, so the same clause works on SQLite and MariaDB and is simpler than
// the now()-relative expressions it supersedes.  Start/End originate from either
// a server-side `time.Now()` (presets) or handler-validated calendar dates, so
// nothing attacker-controlled reaches the formatted literal.
type Window struct {
	Start int64 // inclusive lower bound, unix sec UTC
	End   int64 // inclusive upper bound, unix sec UTC
}

// WindowTrailing builds the [now-hours, now] window the presets use.
func WindowTrailing(now time.Time, hours int) Window {
	return Window{
		Start: now.Add(-time.Duration(hours) * time.Hour).Unix(),
		End:   now.Unix(),
	}
}

// WindowFromRange resolves a range param to a Window.  Presets are trailing;
// "custom" uses [fromTS, toTS] (already resolved by the handler from the
// operator-TZ calendar dates and clamped to the data range).  An invalid custom
// range or unknown token falls back to the 24h trailing default.
func WindowFromRange(rng string, now time.Time, fromTS, toTS int64) Window {
	switch rng {
	case "all":
		// handler passes [oldest event, now]; fall back to a year if unknown.
		if fromTS > 0 && toTS > fromTS {
			return Window{Start: fromTS, End: toTS}
		}
		return WindowTrailing(now, 24*365)
	case "custom":
		if fromTS > 0 && toTS > fromTS {
			return Window{Start: fromTS, End: toTS}
		}
		return WindowTrailing(now, 24)
	default:
		// Every trailing preset ("1h" .. "365d") resolves through RangeHours —
		// ONE token table for the picker, the queries and this window, so a
		// new preset cannot be half-wired.  Unknown tokens fall back to 24h
		// there, preserving this function's historical default.
		return WindowTrailing(now, RangeHours(rng))
	}
}

// Hours is the window span in whole hours, for the legacy callers (e.g.
// CountriesByServe) that still think in a single duration.  Always >= 1 so a
// sub-hour custom range never degenerates to "0 hours" = empty.
func (w Window) Hours() int {
	h := int((w.End - w.Start) / 3600)
	if h < 1 {
		return 1
	}
	return h
}

// Days is the window span in whole days (ceil), for callers keyed on days.
func (w Window) Days() int {
	d := int((w.End - w.Start + 86399) / 86400)
	if d < 1 {
		return 1
	}
	return d
}

func (w Window) hourLo() string { return time.Unix(w.Start, 0).UTC().Format("2006-01-02 15") }
func (w Window) hourHi() string { return time.Unix(w.End, 0).UTC().Format("2006-01-02 15") }

// hourlyAggUsable reports whether the hourly rollup may answer THIS window.
//
// Ready is necessary but not sufficient: the rollup's finest grain is one hour
// and HourClause is inclusive at both ends, so a window shorter than a day is
// answered by up to an hour of data on each side of what was asked for.  On a
// 24h read that rounding is noise; on a 1h read it is most of the answer — and
// the sub-day presets exist precisely to look at the minutes after a rule
// changed, where the hour before the change is the very thing being excluded.
// Sub-day windows therefore fall through to the raw-event scan, which bounds
// on exact timestamps.  The scan is affordable here for the same reason the
// window is short: it walks at most half a day of events, well under the 24h
// and 30d scans the site- and host-filtered views already run.
func hourlyAggUsable(ctx context.Context, hours int) bool {
	if !HourlyAggReady() {
		return false
	}
	w := windowOr(ctx, hours)
	return w.End-w.Start >= 24*3600
}

// HourClause is the window predicate for a 'YYYY-MM-DD HH' string column
// (unmask_aggregate_hourly.bucket_hour / unmask_aggregate_hll.bucket).  The
// 'YYYY-MM-DD HH' format is lexically sortable, so string >= / <= bound the
// window correctly.  Inclusive on both ends: the boundary hour bucket is kept.
func (w Window) HourClause(col string) string {
	return fmt.Sprintf("%s >= '%s' AND %s <= '%s'", col, w.hourLo(), col, w.hourHi())
}

// MinClause is the window predicate for a unix-sec/60 integer column
// (unmask_cookie_minute.bucket_min).
func (w Window) MinClause(col string) string {
	return fmt.Sprintf("%s >= %d AND %s <= %d", col, w.Start/60, col, w.End/60)
}

// TimestampClause is the window predicate for a DATETIME column
// (unmask_event.created_at) — used by the raw-scan query paths.
func (w Window) TimestampClause(col string) string {
	return fmt.Sprintf("%s >= '%s' AND %s <= '%s'", col, w.tsLo(), col, w.tsHi())
}

func (w Window) tsLo() string { return time.Unix(w.Start, 0).UTC().Format("2006-01-02 15:04:05") }
func (w Window) tsHi() string { return time.Unix(w.End, 0).UTC().Format("2006-01-02 15:04:05") }

// DateClause is the window predicate for a DATE-only 'YYYY-MM-DD' string column
// (e.g. unmask_aggregate_hll.bucket under the daily 'ccip' bucket_kind).
func (w Window) DateClause(col string) string {
	lo := time.Unix(w.Start, 0).UTC().Format("2006-01-02")
	hi := time.Unix(w.End, 0).UTC().Format("2006-01-02")
	return fmt.Sprintf("%s >= '%s' AND %s <= '%s'", col, lo, col, hi)
}

// HourIntClause is the window predicate for a unix-sec/3600 INTEGER hour-bucket
// column (e.g. DailyPassByCountry's bucket_hour).
func (w Window) HourIntClause(col string) string {
	return fmt.Sprintf("%s >= %d AND %s <= %d", col, w.Start/3600, col, w.End/3600)
}

func dateWindow(ctx context.Context, hours int, col string) string {
	return windowOr(ctx, hours).DateClause(col)
}
func hourIntWindow(ctx context.Context, hours int, col string) string {
	return windowOr(ctx, hours).HourIntClause(col)
}
