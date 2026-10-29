package dashboard

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/unmask-sh/unmask/admin/internal/db"
)

// PassIPTop ranks the window's addresses by the pass cookies they presented
// in a day -- over several days, the busiest day's count -- or, byPeak, by
// the busiest hour one of their cookies had (unmask_pass_ip_day, written by
// the access-log reader from the bv= field).  Requests and Judged sum over
// the window; JA4Count is the busiest day's fingerprint count.  The rows are
// CookieReuseRows so the stats page decorates them like the reuse rankings
// beside them; Cookies and Peak are theirs alone.
func PassIPTop(ctx context.Context, d *db.DB, site string, hosts []string, hours, limit int, byPeak bool) ([]CookieReuseRow, error) {
	_ = hosts              // no host column on unmask_pass_ip_day (mirrors CookieReuseTopIPs)
	cond := siteCond(site) // validates via siteValRE; never interpolate site raw
	order := "cookies DESC, peak DESC"
	if byPeak {
		order = "peak DESC, cookies DESC"
	}
	w := windowOr(ctx, hours)
	stmt := fmt.Sprintf(`
        SELECT ip,
               MAX(cookies)             AS cookies,
               MAX(peak_hour)           AS peak,
               MAX(ja4s)                AS ja4n,
               MAX(ja4)                 AS ja4,
               MAX(ua)                  AS ua,
               COALESCE(SUM(cnt), 0)    AS reqs,
               COALESCE(SUM(judged), 0) AS judged,
               MAX(last_seen)           AS last_seen
        FROM unmask_pass_ip_day
        WHERE bucket_day >= ? AND bucket_day <= ?%s
        GROUP BY ip
        ORDER BY %s, judged DESC, last_seen DESC LIMIT ?`, cond, order)
	rows, err := d.QueryContext(ctx, stmt, w.Start/86400, w.End/86400, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CookieReuseRow
	for rows.Next() {
		var raw []byte
		var cookies, peak, ja4n, reqs, judged int
		var ja4, ua, ls sql.NullString
		if err := rows.Scan(&raw, &cookies, &peak, &ja4n, &ja4, &ua, &reqs, &judged, &ls); err != nil {
			return nil, err
		}
		out = append(out, CookieReuseRow{
			IP: ipFromBytes(raw), JA4: ja4.String,
			UA: truncate(ua.String, 80), UAFull: ua.String,
			JA4Count: ja4n, Requests: reqs, Judged: judged,
			Cookies: cookies, Peak: peak,
			LastSeen: ls.String, LastSeenTS: parseDateTimeToUnix(ls.String),
		})
	}
	return out, rows.Err()
}
