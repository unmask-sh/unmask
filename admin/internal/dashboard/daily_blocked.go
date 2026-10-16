package dashboard

import (
	"context"
	"fmt"
	"log"
	"sort"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
)

// The stats page's "blocked" trend: per day, the bot requests unmask stopped,
// by the landing page's definition (overview_admin.go, the hero figure):
// challenges fired that produced no pass, minus the ordinary visitors who
// loaded the transparent proof-of-work and left.
//
//	blocked = fired − PoW passes − CAPTCHA passes − unruled PoW abandons
//
// This file gathers the event-side terms per day -- serves, the two kinds of
// pass, the unruled abandons -- from the hourly rollup where it can (the
// default view; hkPhase and hkUnruledPoW are the landing page's own source)
// and from the event table where it must (a site or host filter, or the hours
// the rollup has not settled).  "Fired" is best read from the access log, as
// the landing page does: a deny page serves no challenge and writes no serve
// event, so on a site that denies bots outright the event side undercounts
// several times over.  The handler takes the access log's per-day not-pass
// count (DailyPassByDay's KindNotPass) when the log feed is on and falls back
// to the serves here when it is not -- the same two rulers, in the same order,
// as the hero.

// DailyBlockedDay: one day's terms.  Serves is the event-side "fired"; the
// handler decides which ruler the Fired column shows.
type DailyBlockedDay struct {
	Date    string
	Serves  int // phase=serve events (challenge pages served)
	PoW     int // phase=bv_pow_only (a proof-of-work answered)
	Captcha int // phase in (bv_captcha_only, bv_pow_then_captcha) (a CAPTCHA answered)
	Abandon int // phase=abandon, no rule pointing at the visitor, chain pow_only
}

type blockedAcc map[string]*DailyBlockedDay

func (a blockedAcc) day(date string) *DailyBlockedDay {
	d := a[date]
	if d == nil {
		d = &DailyBlockedDay{Date: date}
		a[date] = d
	}
	return d
}

// add folds one count into a day: phase names as the rollup and the event
// table spell them; unruled is the hkUnruledPoW reading of an abandon.
func (a blockedAcc) add(date, phase string, unruled bool, cnt int) {
	d := a.day(date)
	switch phase {
	case "serve":
		d.Serves += cnt
	case "bv_pow_only":
		d.PoW += cnt
	case "bv_captcha_only", "bv_pow_then_captcha":
		d.Captcha += cnt
	case "abandon":
		if unruled {
			d.Abandon += cnt
		}
	}
}

func (a blockedAcc) finish() []DailyBlockedDay {
	out := make([]DailyBlockedDay, 0, len(a))
	for _, d := range a {
		out = append(out, *d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Date < out[j].Date })
	return out
}

// DailyBlockedByDay returns the event-side terms of the blocked figure for
// each of the last `days` days, day boundaries in tz (the operator's cookie
// TZ, as the other 30-day series).  Days with no events are absent.
func DailyBlockedByDay(ctx context.Context, d *db.DB, site string, hosts []string, days int, tz *time.Location) ([]DailyBlockedDay, error) {
	if tz == nil {
		tz = time.UTC
	}
	t0 := time.Now()
	defer func() {
		if elapsed := time.Since(t0); elapsed > 500*time.Millisecond {
			log.Printf("DailyBlockedByDay: %v elapsed (slow)", elapsed)
		}
	}()
	acc := blockedAcc{}
	if site == "" && len(hosts) == 0 {
		if HourlyAggReady() {
			if err := blockedAggRows(ctx, d, days, "", acc, tz); err != nil {
				return nil, err
			}
			return acc.finish(), nil
		}
		// No full pass in this process yet: the hours the rollup has settled
		// from the rollup, the remainder from the event table.
		cursor, boundary, ok, err := hourlySettledBoundary(ctx, d)
		if err != nil {
			return nil, err
		}
		if ok {
			if err := blockedAggRows(ctx, d, days, boundary.UTC().Format("2006-01-02 15"), acc, tz); err != nil {
				return nil, err
			}
			for _, where := range settledRemainderClauses(windowOr(ctx, days*24), cursor, boundary) {
				if err := blockedScanRows(ctx, d, where, acc, tz); err != nil {
					return nil, err
				}
			}
			return acc.finish(), nil
		}
	}
	where := tsWindow(ctx, days*24, "date_created") + siteCond(site) + hostCond(hosts)
	if err := blockedScanRows(ctx, d, where, acc, tz); err != nil {
		return nil, err
	}
	return acc.finish(), nil
}

// blockedAggRows reads the hourly rollup's phase counts (hkPhase) and unruled
// PoW abandons (hkUnruledPoW) over the window, below upTo when given (the
// settled boundary, 'YYYY-MM-DD HH'), into acc by local day.
func blockedAggRows(ctx context.Context, d *db.DB, days int, upTo string, acc blockedAcc, tz *time.Location) error {
	bound := ""
	if upTo != "" {
		bound = fmt.Sprintf(" AND bucket_hour < '%s'", upTo)
	}
	rows, err := d.QueryContext(ctx, fmt.Sprintf(`
        SELECT bucket_hour, bucket_kind, bucket_key, cnt
        FROM unmask_aggregate_hourly
        WHERE ((bucket_kind = '%s' AND bucket_key IN ('serve', 'bv_pow_only', 'bv_captcha_only', 'bv_pow_then_captcha'))
            OR (bucket_kind = '%s' AND bucket_key = 'abandon'))
          AND %s%s`, hkPhase, hkUnruledPoW, hourWindow(ctx, days*24, "bucket_hour"), bound))
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var bucketHour, kind, key string
		var cnt int
		if err := rows.Scan(&bucketHour, &kind, &key, &cnt); err != nil {
			return err
		}
		hourT, perr := time.ParseInLocation("2006-01-02 15", bucketHour, time.UTC)
		if perr != nil {
			continue // unparseable bucket: skip rather than mis-date
		}
		acc.add(hourT.In(tz).Format("2006-01-02"), key, kind == hkUnruledPoW, cnt)
	}
	return rows.Err()
}

// blockedScanRows reads the terms from the event table for the rows `where`
// selects: the five phases, with an abandon counted only when no rule pointed
// at the visitor and the chain was the transparent proof-of-work -- the same
// filter hkUnruledPoW is written with (countUnruledPoW's scan twin).
func blockedScanRows(ctx context.Context, d *db.DB, where string, acc blockedAcc, tz *time.Location) error {
	reason := jsonExtract(d, "payload_json", "$.force_reason")
	mode := jsonExtract(d, "payload_json", "$.chmode")
	rows, err := d.QueryContext(ctx, fmt.Sprintf(`
        SELECT date_created, phase,
               CASE WHEN phase = 'abandon'
                     AND (%[1]s IS NULL OR %[1]s IN ('', 'none'))
                     AND %[2]s = 'pow_only' THEN 1 ELSE 0 END
        FROM unmask_event
        WHERE phase IN ('serve', 'bv_pow_only', 'bv_captcha_only', 'bv_pow_then_captcha', 'abandon')
          AND %[3]s`, reason, mode, where))
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var ts any
		var phase string
		var unruled int
		if err := rows.Scan(&ts, &phase, &unruled); err != nil {
			return err
		}
		t, ok := normalizeEventTime(ts)
		if !ok {
			continue
		}
		acc.add(t.In(tz).Format("2006-01-02"), phase, unruled == 1, 1)
	}
	return rows.Err()
}
