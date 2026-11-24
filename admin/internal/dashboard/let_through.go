package dashboard

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/events"
	iphll "github.com/unmask-sh/unmask/admin/internal/hll"
)

// What the site answered without a challenge, for the admin's list (BAN > Let
// through): the per-reason counts of unmask_let_hourly and the addresses of
// unmask_let_ip_hourly, both written by the access-log reader
// (nginxlog/let_through.go) from the configuration's why=.

// LetReasonRow is one (reason, detail) of the window.
type LetReasonRow struct {
	Reason    string
	Detail    string
	Requests  int
	Addresses int // distinct addresses, estimated from the hours' sketches
}

// LetAddrRow is one address of the window under one reason.
type LetAddrRow struct {
	IP       string
	Site     string
	Reason   string
	Detail   string
	Requests int
	JA4      string
	UA       string
	Path     string // the latest path it asked for
	FirstTS  int64  // unix seconds, UTC
	LastTS   int64
	// Challenged: the address was shown a challenge in the window (it has an
	// event).  HadPass: it presented a pass cookie on the site in the window.
	// An address with neither got its pages without ever meeting the check.
	Challenged bool
	HadPass    bool
}

// Unchecked reports whether nothing in the window says the address met the
// challenge: no event, and no pass presented.
func (r LetAddrRow) Unchecked() bool { return !r.Challenged && !r.HadPass }

// letHours is the window in the tables' unit (unix hours).
func letHours(ctx context.Context, hours int) (from, to int64) {
	w := windowOr(ctx, hours)
	return w.Start / 3600, w.End / 3600
}

// LetThroughReasons sums the window per (reason, detail), the busiest first.
// The address count is the union of the hours' sketches, so an address seen
// in several hours counts once.
func LetThroughReasons(ctx context.Context, d *db.DB, site string, hours int) ([]LetReasonRow, error) {
	from, to := letHours(ctx, hours)
	rows, err := d.QueryContext(ctx, `
        SELECT reason, detail, cnt, ips
        FROM unmask_let_hourly
        WHERE bucket_hour >= ? AND bucket_hour <= ?`+siteCond(site), from, to)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type acc struct {
		row LetReasonRow
		sk  iphll.Sketch // the access-log reader's sketch, not this package's hll
	}
	byKey := map[string]*acc{}
	for rows.Next() {
		var reason, detail string
		var cnt int
		var sk []byte
		if err := rows.Scan(&reason, &detail, &cnt, &sk); err != nil {
			return nil, err
		}
		k := reason + "\x00" + detail
		a := byKey[k]
		if a == nil {
			a = &acc{row: LetReasonRow{Reason: reason, Detail: detail}}
			byKey[k] = a
		}
		a.row.Requests += cnt
		a.sk.MergeBytes(sk) // either stored form, without a sketch a row
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]LetReasonRow, 0, len(byKey))
	for _, a := range byKey {
		a.row.Addresses = a.sk.Estimate()
		out = append(out, a.row)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Requests != out[j].Requests {
			return out[i].Requests > out[j].Requests
		}
		if out[i].Reason != out[j].Reason {
			return out[i].Reason < out[j].Reason
		}
		return out[i].Detail < out[j].Detail
	})
	return out, nil
}

// LetThroughAddresses lists the window's addresses under reason: those with
// no sign of having met the challenge first, then the busiest, limit at most.
//
// The hours of an address fold in the database (GROUP BY site, address,
// detail, in the order of the index 0053 adds), and only the busiest few
// times limit come back: a row is kept per site, hour, ground and address, so
// a week of an install with many sites is a great many rows, and read one by
// one into the daemon they made the page slow.  JA4, User-Agent and path are
// then read off each one's latest hour, by the table's key.
func LetThroughAddresses(ctx context.Context, d *db.DB, site string, hours int, reason string, limit int) ([]LetAddrRow, error) {
	from, to := letHours(ctx, hours)
	// Whether an address met the challenge decides the order, so it is asked
	// of every address read -- cut first to what a page could show several
	// times over, the busiest.
	cut := limit * 5
	if cut <= 0 {
		cut = 250
	}
	rows, err := d.QueryContext(ctx, `
        SELECT site, ip, detail, SUM(cnt) AS n, MIN(first_seen), MAX(last_seen), MAX(bucket_hour)
        FROM unmask_let_ip_hourly
        WHERE reason = ? AND bucket_hour >= ? AND bucket_hour <= ?`+siteCond(site)+`
        GROUP BY site, ip, detail
        ORDER BY n DESC, MAX(last_seen) DESC
        LIMIT ?`, reason, from, to, cut)
	if err != nil {
		return nil, err
	}
	type found struct {
		row    *LetAddrRow
		raw    []byte
		latest int64
	}
	var order []found
	for rows.Next() {
		var f found
		var rsite, detail string
		var n int64
		var first, last sql.NullString
		if err := rows.Scan(&rsite, &f.raw, &detail, &n, &first, &last, &f.latest); err != nil {
			rows.Close()
			return nil, err
		}
		f.row = &LetAddrRow{IP: ipFromBytes(f.raw), Site: rsite, Reason: reason, Detail: detail, Requests: int(n),
			FirstTS: parseDateTimeToUnix(first.String), LastTS: parseDateTimeToUnix(last.String)}
		order = append(order, f)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	// The latest hour's JA4, User-Agent and path: one row by its key each.
	for _, f := range order {
		var ja4, ua, path sql.NullString
		err := d.QueryRowContext(ctx, `
            SELECT ja4, ua, path FROM unmask_let_ip_hourly
            WHERE bucket_hour = ? AND site = ? AND reason = ? AND detail = ? AND ip = ?`,
			f.latest, f.row.Site, reason, f.row.Detail, f.raw).Scan(&ja4, &ua, &path)
		switch {
		case err == sql.ErrNoRows:
			// Pruned or pushed out between the two reads: listed without them.
		case err != nil:
			return nil, err
		default:
			f.row.JA4, f.row.UA, f.row.Path = ja4.String, ua.String, path.String
		}
	}
	list := make([]*LetAddrRow, len(order))
	for i, f := range order {
		list[i] = f.row
	}
	w := windowOr(ctx, hours)
	if err := letMarkChallenged(ctx, d, list, w.Start); err != nil {
		return nil, err
	}
	if err := letMarkPassed(ctx, d, list, w.Start/86400, w.End/86400); err != nil {
		return nil, err
	}
	sort.SliceStable(list, func(i, j int) bool {
		if a, b := list[i].Unchecked(), list[j].Unchecked(); a != b {
			return a
		}
		if list[i].Requests != list[j].Requests {
			return list[i].Requests > list[j].Requests
		}
		return list[i].LastTS > list[j].LastTS
	})
	if limit > 0 && len(list) > limit {
		list = list[:limit]
	}
	out := make([]LetAddrRow, len(list))
	for i, r := range list {
		out[i] = *r
	}
	return out, nil
}

// letChunk: the addresses asked after in one statement.
const letChunk = 100

// letMarkChallenged sets Challenged on the rows whose address has an event
// since the window's start: a challenge page served, a proof-of-work or a
// CAPTCHA answered.  By the address index, a few seeks a chunk.
func letMarkChallenged(ctx context.Context, d *db.DB, rows []*LetAddrRow, since int64) error {
	byIP := map[string][]*LetAddrRow{}
	var ips []string
	for _, r := range rows {
		if _, seen := byIP[r.IP]; !seen {
			ips = append(ips, r.IP)
		}
		byIP[r.IP] = append(byIP[r.IP], r)
	}
	start := time.Unix(since, 0).UTC().Format("2006-01-02 15:04:05")
	for len(ips) > 0 {
		n := min(letChunk, len(ips))
		args := make([]any, 0, n+1)
		for _, ip := range ips[:n] {
			if b := events.PackIP(ip); b != nil {
				args = append(args, b)
			}
		}
		ips = ips[n:]
		if len(args) == 0 {
			continue
		}
		q := fmt.Sprintf(`SELECT DISTINCT ip_address FROM unmask_event %s WHERE ip_address IN (%s) AND date_created >= ?`,
			d.EventIPIndexHint(), placeholders(len(args)))
		res, err := d.QueryContext(ctx, q, append(args, start)...)
		if err != nil {
			return err
		}
		for res.Next() {
			var raw []byte
			if err := res.Scan(&raw); err != nil {
				res.Close()
				return err
			}
			for _, r := range byIP[ipFromBytes(raw)] {
				r.Challenged = true
			}
		}
		if err := res.Close(); err != nil {
			return err
		}
	}
	return nil
}

// letMarkPassed sets HadPass on the rows whose address presented a pass
// cookie on the row's site in the window's days (unmask_pass_ip_day, whose
// key is day, site, address -- so each statement is a set of key lookups).
func letMarkPassed(ctx context.Context, d *db.DB, rows []*LetAddrRow, fromDay, toDay int64) error {
	bySite := map[string]map[string][]*LetAddrRow{}
	for _, r := range rows {
		m := bySite[r.Site]
		if m == nil {
			m = map[string][]*LetAddrRow{}
			bySite[r.Site] = m
		}
		m[r.IP] = append(m[r.IP], r)
	}
	for site, byIP := range bySite {
		ips := make([]string, 0, len(byIP))
		for ip := range byIP {
			ips = append(ips, ip)
		}
		sort.Strings(ips)
		for len(ips) > 0 {
			n := min(letChunk, len(ips))
			ipArgs := make([]any, 0, n)
			for _, ip := range ips[:n] {
				if b := events.PackIP(ip); b != nil {
					ipArgs = append(ipArgs, b)
				}
			}
			ips = ips[n:]
			if len(ipArgs) == 0 {
				continue
			}
			for day := fromDay; day <= toDay; day++ {
				args := append([]any{day, site}, ipArgs...)
				res, err := d.QueryContext(ctx,
					`SELECT ip FROM unmask_pass_ip_day WHERE bucket_day = ? AND site = ? AND ip IN (`+placeholders(len(ipArgs))+`)`, args...)
				if err != nil {
					return err
				}
				for res.Next() {
					var raw []byte
					if err := res.Scan(&raw); err != nil {
						res.Close()
						return err
					}
					for _, r := range byIP[ipFromBytes(raw)] {
						r.HadPass = true
					}
				}
				if err := res.Close(); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// placeholders is n question marks, comma separated.
func placeholders(n int) string {
	if n <= 0 {
		return ""
	}
	return strings.Repeat("?,", n-1) + "?"
}
