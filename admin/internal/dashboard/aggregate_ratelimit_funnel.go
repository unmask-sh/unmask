package dashboard

import (
	"context"
	"database/sql"
	"strings"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
)

// rlfState is the cursor for the Funnel rate_limit-row rollup (hkRateLimitFunnel).
const rlfState = "rlf_hourly"

// rlfOverlapSec is how far before an hour's start the rate-limited-IP lookup
// reaches, so a challenge interaction whose rl=1 serve landed just before the
// hour boundary is still attributed to the hour its later events fall in.  A
// serve→load→solve loop completes in seconds–minutes, so 10 min comfortably
// covers a boundary straddle without pulling in unrelated later activity.
const rlfOverlapSec = 600

// RollupRateLimitFunnel pre-aggregates the Funnel card's rate_limit row per
// hour, so funnelAgg reads a handful of counts instead of running a per-IP
// self-join over unmask_event on every page load.  For each settled hour H it
// stores, for the IPs that had an rl=1 serve in [H_start-rlfOverlapSec, H_end):
//
//	hkRateLimitFunnel 'p:<phase>'   = count of that phase's events in H
//	hkRateLimitFunnel 's:<verdict>' = count of phase=load, flags=0 events in H
//	                                  (so the read sums the operator's current
//	                                   bot verdicts into the stealth figure)
//
// Correlation is hour-local (see hkRateLimitFunnel).  Same settle / batch /
// idempotency contract as the other rollups, on its own cursor.  Verdict-
// agnostic: it stores every verdict's stealth count and lets the read filter,
// so a settings change to the bot-verdict set needs no re-roll.  Driven by the
// 60s ticker.
func RollupRateLimitFunnel(ctx context.Context, d *db.DB) error {
	if d == nil {
		return nil
	}
	cursor, err := stateCursor(ctx, d, rlfState)
	if err != nil {
		return err
	}
	nowHour := time.Now().Unix() / 3600
	lastSettled := nowHour - trafficSettleHours
	floor := nowHour - int64(hourlyKeep)*24
	start := cursor + 1
	if start < floor {
		start = floor
	}
	for start <= lastSettled {
		end := start + trafficRollupBatchHours - 1
		if end > lastSettled {
			end = lastSettled
		}
		if err := rollupRateLimitFunnelRange(ctx, d, start, end); err != nil {
			return err
		}
		start = end + 1
	}
	return nil
}

func rollupRateLimitFunnelRange(ctx context.Context, d *db.DB, fromHour, toHour int64) error {
	jsonRL := jsonExtract(d, "payload_json", "$.rl")
	// inner = the rate-limited-IP set for the hour; outer = that hour's events.
	innerSub := `ip_address IN (
	        SELECT ip_address FROM unmask_event
	        WHERE date_created >= ? AND date_created < ?
	          AND phase = 'serve' AND ` + jsonRL + ` IN ('1', 1))`
	phaseStmt := `SELECT phase, COUNT(*) FROM unmask_event
	    WHERE date_created >= ? AND date_created < ? AND ` + innerSub + `
	    GROUP BY phase`
	stealthStmt := `SELECT ja4_verdict, COUNT(*) FROM unmask_event
	    WHERE date_created >= ? AND date_created < ? AND phase = 'load' AND flags = 0 AND ` + innerSub + `
	    GROUP BY ja4_verdict`

	type key struct{ bucket, subkey string }
	counts := map[key]int64{}
	for h := fromHour; h <= toHour; h++ {
		outerLo := time.Unix(h*3600, 0).UTC().Format("2006-01-02 15:04:05")
		outerHi := time.Unix((h+1)*3600, 0).UTC().Format("2006-01-02 15:04:05")
		innerLo := time.Unix(h*3600-rlfOverlapSec, 0).UTC().Format("2006-01-02 15:04:05")
		bucket := time.Unix(h*3600, 0).UTC().Format("2006-01-02 15")

		// phase counts (outer bounds, then inner bounds inside the subquery)
		if err := scanPairs(ctx, d, phaseStmt, []any{outerLo, outerHi, innerLo, outerHi},
			func(name string, n int64) {
				if name != "" {
					counts[key{bucket, "p:" + name}] += n
				}
			}); err != nil {
			return err
		}
		// stealth counts per verdict
		if err := scanPairs(ctx, d, stealthStmt, []any{outerLo, outerHi, innerLo, outerHi},
			func(verdict string, n int64) {
				counts[key{bucket, "s:" + verdict}] += n
			}); err != nil {
			return err
		}
	}

	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	sqlite := d.Driver == db.DriverSQLite
	up := `INSERT INTO unmask_aggregate_hourly (bucket_hour, bucket_kind, bucket_key, cnt) VALUES (?, ?, ?, ?)`
	if sqlite {
		up += ` ON CONFLICT(bucket_hour, bucket_kind, bucket_key) DO UPDATE SET cnt = excluded.cnt`
	} else {
		up += ` ON DUPLICATE KEY UPDATE cnt = VALUES(cnt)`
	}
	stmt, err := tx.PrepareContext(ctx, up)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for k, c := range counts {
		if _, err := stmt.ExecContext(ctx, k.bucket, hkRateLimitFunnel, k.subkey, c); err != nil {
			return err
		}
	}
	st := `INSERT INTO unmask_aggregate_state (name, last_id, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)`
	if sqlite {
		st += ` ON CONFLICT(name) DO UPDATE SET last_id = excluded.last_id, updated_at = excluded.updated_at`
	} else {
		st += ` ON DUPLICATE KEY UPDATE last_id = VALUES(last_id), updated_at = VALUES(updated_at)`
	}
	if _, err := tx.ExecContext(ctx, st, rlfState, toHour); err != nil {
		return err
	}
	return tx.Commit()
}

// scanPairs runs a two-column (string, int64) aggregate query and calls fn for
// each row.  A NULL string column yields "" -- and that has to be real, not
// aspirational: stealthStmt groups by ja4_verdict, which is NULL on rows that
// carry no verdict, and scanning that into a bare string errors.  The error
// then wedges the whole rollup -- the cursor never advances past the hour, the
// 60s ticker retries it forever (one log line per minute), and the read path's
// "live tail" raw-scans an ever-growing window, which is exactly the load this
// rollup exists to avoid.
func scanPairs(ctx context.Context, d *db.DB, stmt string, args []any, fn func(string, int64)) error {
	rows, err := d.QueryContext(ctx, stmt, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var name sql.NullString
		var n int64
		if err := rows.Scan(&name, &n); err != nil {
			return err
		}
		fn(name.String, n)
	}
	return rows.Err()
}

// rateLimitFunnelRowAgg builds the Funnel rate_limit row from the hourly rollup
// (hkRateLimitFunnel) for the settled part of the window, plus a live raw-scan
// tail for the current unsettled hours.  Returns a zero row (no error) when the
// rollup has not run yet, so the caller still renders the rest of the funnel.
func rateLimitFunnelRowAgg(ctx context.Context, d *db.DB, hours int, botVerdicts []string) (FunnelRow, bool, error) {
	cursor, err := stateCursor(ctx, d, rlfState)
	if err != nil {
		return FunnelRow{}, false, err
	}
	if cursor < 0 {
		return FunnelRow{}, false, nil // not rolled yet
	}
	win := windowOr(ctx, hours)
	cutoffHour := win.Start / 3600
	untilHour := win.End / 3600

	botSet := map[string]bool{}
	for _, v := range botVerdicts {
		botSet[v] = true
	}
	phase := map[string]int{}
	var stealth int

	// Settled hours from the rollup.
	upToHour := cursor
	if untilHour < upToHour {
		upToHour = untilHour
	}
	if upToHour >= cutoffHour {
		lo := time.Unix(cutoffHour*3600, 0).UTC().Format("2006-01-02 15")
		hi := time.Unix(upToHour*3600, 0).UTC().Format("2006-01-02 15")
		if err := scanPairsKV(ctx, d,
			`SELECT bucket_key, cnt FROM unmask_aggregate_hourly
	         WHERE bucket_kind = ? AND bucket_hour >= ? AND bucket_hour <= ?`,
			[]any{hkRateLimitFunnel, lo, hi},
			func(subkey string, n int) {
				if name, ok := strings.CutPrefix(subkey, "p:"); ok {
					phase[name] += n
				} else if v, ok := strings.CutPrefix(subkey, "s:"); ok && botSet[v] {
					stealth += n
				}
			}); err != nil {
			return FunnelRow{}, false, err
		}
	}

	// Live tail: the unsettled hours after the cursor, scanned raw (≤ a couple of
	// hours).  outer = (cursor, now]; inner reaches rlfOverlapSec earlier so an
	// interaction straddling the settled/tail boundary is still attributed here.
	tailFromHour := cursor + 1
	if tailFromHour < cutoffHour {
		tailFromHour = cutoffHour
	}
	if tailFromHour <= untilHour {
		outerSince := "date_created >= '" + time.Unix(tailFromHour*3600, 0).UTC().Format("2006-01-02 15:04:05") + "'"
		innerSince := "date_created >= '" + time.Unix(tailFromHour*3600-rlfOverlapSec, 0).UTC().Format("2006-01-02 15:04:05") + "'"
		tail, err := rateLimitFunnelRowRange(ctx, d, "", nil, outerSince, innerSince, botVerdicts)
		if err != nil {
			return FunnelRow{}, false, err
		}
		mergeRateLimitCounts(phase, &stealth, tail)
	}

	return assembleRateLimitRow(phase, stealth), true, nil
}

// scanPairsKV is scanPairs for a (string, int) shaped query.
func scanPairsKV(ctx context.Context, d *db.DB, stmt string, args []any, fn func(string, int)) error {
	return scanPairs(ctx, d, stmt, args, func(s string, n int64) { fn(s, int(n)) })
}

// mergeRateLimitCounts folds a raw-scanned tail row's phase counts into the
// running phase map + stealth accumulator (derived fields are recomputed by
// assembleRateLimitRow, so only the raw counts are merged here).
func mergeRateLimitCounts(phase map[string]int, stealth *int, tail FunnelRow) {
	phase["serve"] += tail.Serve
	phase["load"] += tail.Load
	phase["pow_pass"] += tail.PowPass
	phase["captcha"] += tail.Captcha
	phase["bv_pow_only"] += tail.BVPowOnly
	phase["bv_captcha_only"] += tail.BVCaptchaOnly
	phase["bv_pow_then_captcha"] += tail.BVPowThenCaptcha
	phase["verify_ng"] += tail.VerifyNG
	phase["cookie_err"] += tail.CookieErr
	phase["error"] += tail.JSError
	*stealth += tail.Stealth
}

// assembleRateLimitRow turns the per-phase counts + stealth into the funnel's
// rate_limit row, deriving the same secondary fields rateLimitFunnelRow does.
func assembleRateLimitRow(phase map[string]int, stealth int) FunnelRow {
	r := assembleFunnelPseudoRow("rate_limit", phase, stealth)
	r.ServeRL = r.Serve // every rate_limit serve came via the rl path
	return r
}

// assembleFunnelPseudoRow turns per-phase counts + stealth into a cross-verdict
// funnel row (rate_limit / header / asn / geo), deriving the same secondary
// fields the per-verdict rows get.  These rows overlap the verdict rows (a
// header challenge is also counted under its JA4 verdict), so callers keep them
// OUT of the TOTAL.
func assembleFunnelPseudoRow(label string, phase map[string]int, stealth int) FunnelRow {
	r := FunnelRow{Verdict: label}
	r.Serve = phase["serve"]
	r.Load = phase["load"]
	r.Stealth = stealth
	r.PowPass = phase["pow_pass"]
	r.Captcha = phase["captcha"]
	r.BVPowOnly = phase["bv_pow_only"]
	r.BVCaptchaOnly = phase["bv_captcha_only"]
	r.BVPowThenCaptcha = phase["bv_pow_then_captcha"]
	r.VerifyNG = phase["verify_ng"]
	r.CookieErr = phase["cookie_err"]
	r.JSError = phase["error"]
	if r.Serve > r.Load {
		r.Silent = r.Serve - r.Load
	}
	r.PowSolved = r.BVPowOnly + r.PowPass
	r.BVTotal = r.BVPowOnly + r.BVCaptchaOnly + r.BVPowThenCaptcha
	r.CaptchaPassed = r.BVCaptchaOnly + r.BVPowThenCaptcha
	if r.Load > 0 {
		r.PowRate = float64(r.PowSolved) / float64(r.Load)
		r.CaptchaRate = float64(r.Captcha) / float64(r.Load)
	}
	return r
}

// forceReasonFunnelKinds are the force_reason values that get their own funnel
// pseudo-row (the by-axis twin of the verdict rows), in display order.
// rate_limit has its own dedicated row; ja4_bot overlaps the verdict rows; none
// is the bulk of ordinary traffic -- all three are excluded here.  This slice is
// the single source of truth: the rollup filter (forceReasonFunnelKindSet) and
// the scan-path SQL IN() are both derived from it, so a new kind is added in one
// place.
var forceReasonFunnelKinds = []string{"honeypot", "banned", "protected", "stale", "header", "asn", "geo"}

// forceReasonFunnelKindSet is the O(1) membership form of forceReasonFunnelKinds
// for the per-event hourly rollup hot path.
var forceReasonFunnelKindSet = func() map[string]bool {
	m := make(map[string]bool, len(forceReasonFunnelKinds))
	for _, k := range forceReasonFunnelKinds {
		m[k] = true
	}
	return m
}()

// forceReasonFunnelInList renders forceReasonFunnelKinds as a SQL IN() list of
// quoted literals.  The values are code constants (no user input), so simple
// quoting is injection-safe.
func forceReasonFunnelInList() string {
	return "'" + strings.Join(forceReasonFunnelKinds, "','") + "'"
}

// forceReasonRowsFromPhaseMaps assembles the header/asn/geo funnel rows from
// reason->phase->count maps, in forceReasonFunnelKinds order, skipping axes with
// no events (these axes are off by default, so most installs show none).
func forceReasonRowsFromPhaseMaps(byRP map[string]map[string]int) []FunnelRow {
	var out []FunnelRow
	for _, reason := range forceReasonFunnelKinds {
		ph := byRP[reason]
		if len(ph) == 0 {
			continue
		}
		out = append(out, assembleFunnelPseudoRow(reason, ph, 0))
	}
	return out
}
