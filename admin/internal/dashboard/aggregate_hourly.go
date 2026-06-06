package dashboard

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/classify"
	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/ipgeo"
)

// hourlyReady is set once AggregateHourly has completed a full pass in this
// process. Until then Funnel scans raw events, so a fresh start / restart —
// whose first pass backfills the whole retained history (~10s) — never serves
// a half-filled aggregate.
var hourlyReady atomic.Bool

// unmask_aggregate_hourly bucket_kind values (plain counts). See migration
// 0006. Initially only the funnel + per-country serve count rolled up here;
// the original commit dismissed captcha-force / flags as "dominated by
// per-bucket distinct-IP work that aggregating would not speed up."  That
// predates the 0007 HLL machinery — once sketches are hour-bucketable, the
// distinct-IP argument no longer holds, and we add per-reason count + HLL
// for CaptchaForceBreakdown below (= hkCaptchaForce / hkCaptchaForceIP).
const (
	hkFunnel       = "fnl" // key '<vid>|<verdict>|<phase>'
	hkLoadF0       = "lf0" // key '<vid>|<verdict>'   phase=load, flags=0
	hkServeRL      = "srl" // key '<vid>|<verdict>'   phase=serve, payload rl=1
	hkCountry      = "cc"  // key '<country>'         phase=serve
	hkSiteAll      = "sa"  // key '<site>'            all phases (Sites total events)
	hkSiteServe    = "ss"  // key '<site>'            phase=serve (Sites serve count)
	hkSiteBV       = "sb"  // key '<site>'            phase starts with 'bv_' (Sites passed count)
	hkServeKind    = "svk" // key '<classifyCategory>' phase=serve, payload rl != 1 (DailyServeByKind stack count)
	hkCaptchaForce = "cf"  // key '<force_reason>'    phase=load (CaptchaForceBreakdown count)
	hkFlags        = "fl"  // key '<flags>' (decimal) phase=load (FlagsDistribution count)
	hkAITag        = "ait" // key '<crawler-tag>'     phase=serve, payload rl != 1 (AI traffic breakdown count, install-wide)
	hkAITagSite    = "aits" // key '<site>|<crawler-tag>' phase=serve, payload rl != 1 (AI traffic per-site)
)

// unmask_aggregate_hll bucket_kind values (HLL sketches). See migration 0007.
const (
	hkVerdictIP     = "vdip" // hourly bucket, key '<verdict>'  distinct IP, all phases
	hkCountryIP     = "ccip" // daily  bucket, key '<country>'  distinct IP, phase=serve
	hkSiteIP        = "siip" // hourly bucket, key '<site>'     distinct IP, all phases
	hkServeIP       = "svip" // hourly bucket, key ''           distinct IP, phase=serve / payload rl != 1
	hkLoadVerdictIP    = "lvip" // hourly bucket, key '<verdict>'  distinct IP, phase=load (Funnel)
	hkCaptchaForceIP   = "cfip" // hourly bucket, key '<force_reason>' distinct IP, phase=load (CaptchaForceBreakdown)
	hkFlagsIP          = "flip" // hourly bucket, key '<flags>' (decimal) distinct IP, phase=load (FlagsDistribution)
	hkAITagIP          = "atip" // hourly bucket, key '<crawler-tag>' distinct IP, phase=serve / rl != 1 (AI traffic)
	hkAITagSiteIP      = "atsip" // hourly bucket, key '<site>|<crawler-tag>' distinct IP, phase=serve / rl != 1 (per-site)
)

const (
	hourlyState = "hourly" // unmask_aggregate_state.name for this aggregator
	hourlyBatch = 20000    // unmask_event rows per backfill chunk / tx
	hourlyKeep  = 32       // days of buckets to retain (covers the 30d range)
)

// hourColExpr formats a datetime column to a 'YYYY-MM-DD HH' bucket string.
// All timestamps are UTC by construction (sqlite stores date_created via
// datetime('now'); MariaDB's session time_zone is pinned to '+00:00' in
// db.Open), so the stored bucket is the UTC hour.  The operator's cookie TZ
// is then applied by the read-side query layer via *time.Location.
func hourColExpr(d *db.DB, col string) string {
	if d.Driver == db.DriverSQLite {
		return "strftime('%Y-%m-%d %H', " + col + ")"
	}
	return "DATE_FORMAT(" + col + ", '%Y-%m-%d %H')"
}

// hourAgoExpr is SQL for the 'YYYY-MM-DD HH' bucket n hours before now.
func hourAgoExpr(d *db.DB, n int) string {
	if d.Driver == db.DriverSQLite {
		return fmt.Sprintf("strftime('%%Y-%%m-%%d %%H', 'now', '-%d hours')", n)
	}
	return fmt.Sprintf("DATE_FORMAT(NOW() - INTERVAL %d HOUR, '%%Y-%%m-%%d %%H')", n)
}

// hourAgoTimestamp is SQL for the hour-aligned timestamp n hours before now
// ('YYYY-MM-DD HH:00:00'), so the funnel's raw distinct-IP queries cover the
// same window boundary as the aggregate.
func hourAgoTimestamp(d *db.DB, n int) string {
	if d.Driver == db.DriverSQLite {
		return fmt.Sprintf("strftime('%%Y-%%m-%%d %%H:00:00', 'now', '-%d hours')", n)
	}
	return fmt.Sprintf("DATE_FORMAT(NOW() - INTERVAL %d HOUR, '%%Y-%%m-%%d %%H:00:00')", n)
}

// dayAgoExpr is SQL for the 'YYYY-MM-DD HH' bucket n days before now.
func dayAgoExpr(d *db.DB, n int) string {
	if d.Driver == db.DriverSQLite {
		return fmt.Sprintf("strftime('%%Y-%%m-%%d %%H', 'now', '-%d days')", n)
	}
	return fmt.Sprintf("DATE_FORMAT(NOW() - INTERVAL %d DAY, '%%Y-%%m-%%d %%H')", n)
}

// dateAgoExpr is SQL for the 'YYYY-MM-DD' day-bucket n days before now.
func dateAgoExpr(d *db.DB, n int) string {
	if d.Driver == db.DriverSQLite {
		return fmt.Sprintf("strftime('%%Y-%%m-%%d', 'now', '-%d days')", n)
	}
	return fmt.Sprintf("DATE_FORMAT(NOW() - INTERVAL %d DAY, '%%Y-%%m-%%d')", n)
}

type hourlyKey struct{ hour, kind, key string }
type hllKey struct{ bucket, kind, key string }

// aggBatch is one chunk's worth of accumulated aggregation: plain counts and
// HLL sketches, both keyed by bucket.
type aggBatch struct {
	counts   map[hourlyKey]int64
	sketches map[hllKey]*hll
}

func newAggBatch() *aggBatch {
	return &aggBatch{counts: map[hourlyKey]int64{}, sketches: map[hllKey]*hll{}}
}

func (b *aggBatch) sketch(k hllKey) *hll {
	s := b.sketches[k]
	if s == nil {
		s = &hll{}
		b.sketches[k] = s
	}
	return s
}

// AggregateHourly incrementally rolls new unmask_event rows into
// unmask_aggregate_hourly + unmask_aggregate_hll. It is the single writer of
// those tables (counts accumulate, sketches merge), driven by the admin's 60s
// ticker plus a startup run. Each call processes only rows past
// unmask_aggregate_state name='hourly'.last_id, so the first call after
// install backfills the retained history and later calls are cheap. A rebuild
// = delete that state row and truncate the tables; the next call backfills
// from id 0. gip may be nil (no IP-geo configured) — country rollups are then
// skipped.
func AggregateHourly(ctx context.Context, d *db.DB, gip *ipgeo.Reader) error {
	last, err := hourlyLastID(ctx, d)
	if err != nil {
		return err
	}
	for {
		n, maxID, err := aggregateHourlyChunk(ctx, d, gip, last)
		if err != nil {
			return err
		}
		if n == 0 {
			hourlyReady.Store(true) // a full pass is done: the agg paths may read now
			return nil
		}
		last = maxID
	}
}

// HourlyAggReady reports whether the hourly aggregate is safe to read — i.e.
// AggregateHourly has finished at least one full pass in this process.
func HourlyAggReady() bool { return hourlyReady.Load() }

// PruneHourly drops buckets past the retention window. The aggregate tables
// only need to serve the stats page's longest (30-day) range.
func PruneHourly(ctx context.Context, d *db.DB) error {
	if _, err := d.ExecContext(ctx,
		`DELETE FROM unmask_aggregate_hourly WHERE bucket_hour < `+dayAgoExpr(d, hourlyKeep)); err != nil {
		return err
	}
	if _, err := d.ExecContext(ctx,
		`DELETE FROM unmask_aggregate_hll WHERE bucket < `+dayAgoExpr(d, hourlyKeep)); err != nil {
		return err
	}
	// unmask_traffic_hll keys on a unix-minute integer (written by the
	// nginx-log pipeline), not a bucket-hour string, so it can't share
	// dayAgoExpr — compute the cutoff minute directly.
	minCutoff := time.Now().Unix()/60 - int64(hourlyKeep)*1440
	_, err := d.ExecContext(ctx,
		`DELETE FROM unmask_traffic_hll WHERE bucket_min < ?`, minCutoff)
	return err
}

func hourlyLastID(ctx context.Context, d *db.DB) (int64, error) {
	var id int64
	err := d.QueryRowContext(ctx,
		`SELECT last_id FROM unmask_aggregate_state WHERE name = ?`, hourlyState).Scan(&id)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	return id, err
}

func aggregateHourlyChunk(ctx context.Context, d *db.DB, gip *ipgeo.Reader, afterID int64) (int, int64, error) {
	rows, err := d.QueryContext(ctx, `
        SELECT id, `+hourColExpr(d, "date_created")+`, site, ja4_verdict, ja4_verdict_id, phase, flags, payload_json, user_agent, ip_address
        FROM unmask_event WHERE id > ? ORDER BY id LIMIT ?`, afterID, hourlyBatch)
	if err != nil {
		return 0, 0, err
	}
	geo := gip != nil && gip.Loaded()
	batch := newAggBatch()
	// classify cache: serve-phase events feed the per-kind daily chart, so
	// every event ends up running classify.IsBot (= 600-alt regex).  Memoize
	// per-ua so backfill stays cheap (ja4Action is "" here; see the serve
	// case below for the reasoning).
	classifyCache := make(map[string]classify.Category, 256)
	// tagCache mirrors classifyCache for crawler-tag lookups.  Same access
	// pattern (= 80-char truncated UA → "" when no tag matches).
	tagCache := make(map[string]string, 256)
	var n int
	var maxID int64
	for rows.Next() {
		var (
			id      int64
			hour    string
			site    string
			verdict sql.NullString
			vid     sql.NullInt64
			phase   string
			flags   int
			payload sql.NullString
			ua      sql.NullString
			ip      []byte
		)
		if err := rows.Scan(&id, &hour, &site, &verdict, &vid, &phase, &flags, &payload, &ua, &ip); err != nil {
			rows.Close()
			return 0, 0, err
		}
		n++
		maxID = id
		if len(hour) < 13 {
			continue // unparseable date_created: skip rather than mis-bucket
		}
		day := hour[:10]
		// verdict key part mirrors Funnel's COALESCE(ja4_verdict,'(none)'); the
		// verdict id is kept so the read side can apply canon() rename-merge.
		v := "(none)"
		if verdict.Valid {
			v = verdict.String
		}
		vv := strconv.FormatInt(vid.Int64, 10) + "|" + v
		batch.counts[hourlyKey{hour, hkFunnel, vv + "|" + phase}]++
		// vdip: distinct IP per verdict, all phases (VerdictDistribution).
		batch.sketch(hllKey{hour, hkVerdictIP, v}).add(ip)
		// site dimension: feeds dashboard.Sites (= the stats-page entry list).
		// Total / serve / passed counts + distinct IP per site, all bucketed
		// hourly so 7d / 30d ranges read O(hours * sites) rows instead of
		// scanning the raw event table.
		if site != "" {
			batch.counts[hourlyKey{hour, hkSiteAll, site}]++
			batch.sketch(hllKey{hour, hkSiteIP, site}).add(ip)
		}
		switch phase {
		case "load":
			if flags == 0 {
				batch.counts[hourlyKey{hour, hkLoadF0, vv}]++
			}
			// lvip: phase=load distinct IP per verdict.  Funnel needs both the
			// per-verdict count and the total (= union of sketches), so we
			// store only per-verdict and let the read side merge across keys.
			batch.sketch(hllKey{hour, hkLoadVerdictIP, v}).add(ip)
			// CaptchaForceBreakdown: per-reason count + distinct IP.  Matches
			// the raw query's CASE-fold: any value outside the known seven
			// reasons (or no force_reason key at all) collapses to 'unknown'.
			fr := normalizeForceReason(payloadForceReason(payload.String))
			batch.counts[hourlyKey{hour, hkCaptchaForce, fr}]++
			batch.sketch(hllKey{hour, hkCaptchaForceIP, fr}).add(ip)
			// FlagsDistribution: per-flags count + distinct IP.  flags is a
			// small bitfield (= mostly 0..31), so key cardinality stays low.
			// Stored as a decimal string so the bucket_key column matches
			// other count keys' type.
			flagsKey := strconv.Itoa(flags)
			batch.counts[hourlyKey{hour, hkFlags, flagsKey}]++
			batch.sketch(hllKey{hour, hkFlagsIP, flagsKey}).add(ip)
		case "serve":
			if site != "" {
				batch.counts[hourlyKey{hour, hkSiteServe, site}]++
			}
			rl := payloadRL(payload.String)
			if rl {
				batch.counts[hourlyKey{hour, hkServeRL, vv}]++
			} else {
				// DailyServeByKind reads svk + svip.  Drop rate-limited
				// serves on the rl path (they have their own dashboard card)
				// to match dailyServeByKindScan's `NOT IN ('1', 1)` filter.
				//
				// classify.IsBot needs both ua and ja4Action -- ja4Action
				// requires the operator's current botVerdicts list, which is
				// settings-driven and changes at runtime.  Persisting the
				// final Category at rollup time would freeze that list to
				// whatever it was at backfill, so we save the ua-only
				// category (= ja4Action "") together with the raw verdict and
				// let the read side fold in the JA4Bot promotion via the
				// up-to-date settings.
				uaStr := ua.String
				if len(uaStr) > 80 {
					uaStr = uaStr[:80]
				}
				kind, ok := classifyCache[uaStr]
				if !ok {
					kind = classify.IsBot(uaStr, "")
					classifyCache[uaStr] = kind
				}
				batch.counts[hourlyKey{hour, hkServeKind, strconv.Itoa(int(kind)) + "|" + v}]++
				batch.sketch(hllKey{hour, hkServeIP, ""}).add(ip)
				// AI traffic breakdown: only crawler-tag UAs contribute (= a
				// human visitor matches nothing and gets a zero-cost map
				// lookup).  Stored on the rl != 1 path so the rate-limit
				// pseudo-row doesn't double-count.
				tag, tok := tagCache[uaStr]
				if !tok {
					tag = classify.LookupTag(uaStr)
					tagCache[uaStr] = tag
				}
				if tag != "" {
					batch.counts[hourlyKey{hour, hkAITag, tag}]++
					batch.sketch(hllKey{hour, hkAITagIP, tag}).add(ip)
					// Per-site bucket for the site-filtered card path.  The
					// install-wide hkAITag above stays the canonical key for
					// the unfiltered card; this one duplicates the count
					// scoped to a site so the read side can answer
					// "?site=foo" without scanning unmask_event.  Skip when
					// the event has no site label (= unknown vhost).
					if site != "" {
						siteKey := site + "|" + tag
						batch.counts[hourlyKey{hour, hkAITagSite, siteKey}]++
						batch.sketch(hllKey{hour, hkAITagSiteIP, siteKey}).add(ip)
					}
				}
			}
			if geo {
				if cc := gip.LookupBytes(ip); cc != "" {
					batch.counts[hourlyKey{hour, hkCountry, cc}]++
					// ccip is daily: CountriesByServe is a fixed 30-day view, so
					// day granularity keeps the sketch table tiny.
					batch.sketch(hllKey{day, hkCountryIP, cc}).add(ip)
				}
			}
		default:
			// Any phase beginning with 'bv_' = a _bv issuance phase (= the
			// visitor passed PoW / CAPTCHA / etc.).  Counts as "passed" in
			// Sites' summary, matching the meaning in Funnel.
			if site != "" && len(phase) >= 3 && phase[:3] == "bv_" {
				batch.counts[hourlyKey{hour, hkSiteBV, site}]++
			}
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, 0, err
	}
	rows.Close()
	if n == 0 {
		return 0, 0, nil
	}
	if err := hourlyFlush(ctx, d, batch, maxID); err != nil {
		return 0, 0, err
	}
	return n, maxID, nil
}

// hourlyFlush writes one chunk's counts + sketches and advances last_id in a
// single tx, so a crash mid-chunk never double-counts (counts accumulate,
// sketches merge — both idempotent only under the last_id cursor).
func hourlyFlush(ctx context.Context, d *db.DB, batch *aggBatch, maxID int64) error {
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	sqlite := d.Driver == db.DriverSQLite

	// plain counts: accumulate.
	upCnt := `INSERT INTO unmask_aggregate_hourly (bucket_hour, bucket_kind, bucket_key, cnt) VALUES (?, ?, ?, ?)`
	if sqlite {
		upCnt += ` ON CONFLICT(bucket_hour, bucket_kind, bucket_key) DO UPDATE SET cnt = cnt + excluded.cnt`
	} else {
		upCnt += ` ON DUPLICATE KEY UPDATE cnt = cnt + VALUES(cnt)`
	}
	cntStmt, err := tx.PrepareContext(ctx, upCnt)
	if err != nil {
		return err
	}
	defer cntStmt.Close()
	for k, c := range batch.counts {
		if _, err := cntStmt.ExecContext(ctx, k.hour, k.kind, k.key, c); err != nil {
			return err
		}
	}

	// HLL sketches: load the stored sketch, merge this chunk's, store. The
	// last_id cursor stops a re-merge of already-seen rows.
	upHLL := `INSERT INTO unmask_aggregate_hll (bucket, bucket_kind, bucket_key, sketch) VALUES (?, ?, ?, ?)`
	if sqlite {
		upHLL += ` ON CONFLICT(bucket, bucket_kind, bucket_key) DO UPDATE SET sketch = excluded.sketch`
	} else {
		upHLL += ` ON DUPLICATE KEY UPDATE sketch = VALUES(sketch)`
	}
	hllStmt, err := tx.PrepareContext(ctx, upHLL)
	if err != nil {
		return err
	}
	defer hllStmt.Close()
	for k, s := range batch.sketches {
		var stored []byte
		err := tx.QueryRowContext(ctx,
			`SELECT sketch FROM unmask_aggregate_hll WHERE bucket = ? AND bucket_kind = ? AND bucket_key = ?`,
			k.bucket, k.kind, k.key).Scan(&stored)
		if err != nil && err != sql.ErrNoRows {
			return err
		}
		if len(stored) > 0 {
			s.merge(loadHLL(stored))
		}
		if _, err := hllStmt.ExecContext(ctx, k.bucket, k.kind, k.key, s[:]); err != nil {
			return err
		}
	}

	st := `INSERT INTO unmask_aggregate_state (name, last_id, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)`
	if sqlite {
		st += ` ON CONFLICT(name) DO UPDATE SET last_id = excluded.last_id, updated_at = excluded.updated_at`
	} else {
		st += ` ON DUPLICATE KEY UPDATE last_id = VALUES(last_id), updated_at = VALUES(updated_at)`
	}
	if _, err := tx.ExecContext(ctx, st, hourlyState, maxID); err != nil {
		return err
	}
	return tx.Commit()
}

// splitFnlKey parses an 'fnl' bucket_key '<vid>|<verdict>|<phase>'. The verdict
// itself may contain '|', so vid is taken before the first separator and phase
// after the last.
func splitFnlKey(key string) (vid int, verdict, phase string, ok bool) {
	i := strings.IndexByte(key, '|')
	j := strings.LastIndexByte(key, '|')
	if i < 0 || j <= i {
		return 0, "", "", false
	}
	vid, _ = strconv.Atoi(key[:i])
	return vid, key[i+1 : j], key[j+1:], true
}

// splitVVKey parses an 'lf0' / 'srl' bucket_key '<vid>|<verdict>'.
func splitVVKey(key string) (vid int, verdict string, ok bool) {
	i := strings.IndexByte(key, '|')
	if i < 0 {
		return 0, "", false
	}
	vid, _ = strconv.Atoi(key[:i])
	return vid, key[i+1:], true
}

// payloadRL mirrors the SQL test json_extract(payload,'$.rl') IN ('1', 1).
// payloadForceReason extracts payload_json.force_reason.  Returns "" when
// payload is empty, malformed, or missing the key.  normalizeForceReason
// folds the value into the seven known buckets (or "unknown").
func payloadForceReason(payload string) string {
	if payload == "" {
		return ""
	}
	var m map[string]any
	if json.Unmarshal([]byte(payload), &m) != nil {
		return ""
	}
	s, _ := m["force_reason"].(string)
	return s
}

// normalizeForceReason mirrors the raw query's CASE WHEN ... IN (...) ELSE
// 'unknown' fold.  Known seven reasons pass through; everything else (empty
// string included) becomes "unknown".  Keep in sync with queries.go's
// captchaForceKinds slice.
func normalizeForceReason(fr string) string {
	switch fr {
	case "none", "ja4_bot", "honeypot", "banned", "protected", "rate_limit", "test":
		return fr
	}
	return "unknown"
}

func payloadRL(payload string) bool {
	if payload == "" {
		return false
	}
	var m map[string]any
	if json.Unmarshal([]byte(payload), &m) != nil {
		return false
	}
	switch v := m["rl"].(type) {
	case string:
		return v == "1"
	case float64:
		return v == 1
	}
	return false
}
