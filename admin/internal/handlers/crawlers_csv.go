// /admin/stats/crawlers.csv -- the crawler counters by day, as a file.
//
// The crawler card answers "who came, and were they let in" for one window on
// one screen.  An operator who reports it -- so many requests from each AI
// crawler, to each site, on each day -- needs the rows, in a form a
// spreadsheet opens.  This is the per-site crawler table
// (unmask_crawler_site_hourly) summed into the operator's days: one row per
// day, site, category and crawler.
package handlers

import (
	"context"
	"database/sql"
	"encoding/csv"
	"log"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/dashboard"
	"github.com/unmask-sh/unmask/admin/internal/nginxconf"
)

// crawlersCSVLink is the window the crawler card's CSV link carries: a range
// token of the statistics page, and the two dates of its custom range
// (YYYY-MM-DD, empty unless Range is "custom").  The site is not part of it:
// the file follows the site picker's cookie, like the page the link is on.
type crawlersCSVLink struct {
	Range string
	From  string
	To    string
}

// crawlersCSVHeader names the file's columns, in order.  challenged and
// passed split total; verified and named_pass are counts within it, and
// range_published says whether verified can be anything but zero.
var crawlersCSVHeader = []string{
	"date", "site", "category", "crawler",
	"total", "challenged", "passed", "verified", "named_pass", "range_published",
}

// crawlersCSVTimeout bounds the read.  The longest window is the table's
// whole retention -- a row per hour, site and crawler -- and the file is
// every site's rows unless one is picked, so it gets what the statistics page
// gets for all of its cards together (statsOverallTimeout).
const crawlersCSVTimeout = 30 * time.Second

// crawlersCSVWin is the window of one file: the hour buckets it reads, both
// ends included, and the two dates its name carries (operator's zone).
type crawlersCSVWin struct {
	fromHour, toHour int64
	fromDate, toDate string
}

// crawlersCSVWindow resolves the request's window the way the statistics
// page resolves its own, so the card's link can hand the page's range over
// as it is: a custom range of two calendar dates in the operator's zone
// (range=custom, or the dates alone), else a trailing preset.  Anything else
// is the last 30 days -- a table by day wants more than the page's default
// day.
func crawlersCSVWindow(r *http.Request, now time.Time, loc *time.Location) crawlersCSVWin {
	const day = "2006-01-02"
	q := r.URL.Query()
	rng := q.Get("range")
	if rng == "custom" || rng == "" {
		if fromTS, toTS := parseCustomRange(q.Get("from"), q.Get("to"), loc); fromTS > 0 && toTS > fromTS {
			return crawlersCSVWin{
				// The first bucket that starts on the first day.  In a zone
				// with a half-hour offset the bucket that holds local
				// midnight starts before it, and is counted with the day
				// before (see crawlersCSVRows).
				fromHour: (fromTS + 3599) / 3600,
				toHour:   toTS / 3600,
				fromDate: time.Unix(fromTS, 0).In(loc).Format(day),
				toDate:   time.Unix(toTS, 0).In(loc).Format(day),
			}
		}
	}
	hours := 24 * 30
	switch rng {
	case "1h", "3h", "6h", "12h", "24h", "7d", "30d", "90d", "180d", "365d", "all":
		// The statistics page's presets (renderStats).  "all" is its longest
		// span; the table keeps about a month, so it is everything on hand.
		hours = dashboard.RangeHours(rng)
	}
	// A trailing window starts in the hour that holds its first instant, as
	// the card's drill-down does, so the file and the card count the same rows.
	fromHour := (now.Unix() - int64(hours)*3600) / 3600
	return crawlersCSVWin{
		fromHour: fromHour,
		toHour:   now.Unix() / 3600,
		fromDate: time.Unix(fromHour*3600, 0).In(loc).Format(day),
		toDate:   now.In(loc).Format(day),
	}
}

// crawlersCSVRow is one line of the file.
type crawlersCSVRow struct {
	date, site, category, crawler  string
	total, served, verified, named int
}

// The sums of one local day's run of hours, for every site and for one.
// Statements of their own for the plan test beside the card's
// (crawler_plan_test.go): the first ranges over the hours by the table's key,
// the second goes through the (site, bucket_hour) index.
const (
	crawlersCSVDayStmt = `SELECT site, category, crawler, SUM(total), SUM(served), SUM(verified), SUM(named)
		FROM unmask_crawler_site_hourly WHERE bucket_hour >= ? AND bucket_hour <= ?
		GROUP BY site, category, crawler`
	crawlersCSVDaySiteStmt = `SELECT site, category, crawler, SUM(total), SUM(served), SUM(verified), SUM(named)
		FROM unmask_crawler_site_hourly WHERE bucket_hour >= ? AND bucket_hour <= ? AND site = ?
		GROUP BY site, category, crawler`
	crawlerSiteNewestStmt = `SELECT MAX(bucket_hour) FROM unmask_crawler_site_hourly`
)

// crawlerSiteExtent is the oldest and the newest hour bucket the per-site
// crawler table holds; the third result is false when it is empty.
func crawlerSiteExtent(ctx context.Context, h *Handler) (int64, int64, bool, error) {
	// One statement each (the oldest is crawlerSiteFirstHourStmt): a lone MIN
	// or MAX is a seek on the key, the two in one statement walk the index
	// from end to end.
	var oldest, newest sql.NullInt64
	if err := h.DB.QueryRowContext(ctx, crawlerSiteFirstHourStmt).Scan(&oldest); err != nil {
		return 0, 0, false, err
	}
	if err := h.DB.QueryRowContext(ctx, crawlerSiteNewestStmt).Scan(&newest); err != nil {
		return 0, 0, false, err
	}
	return oldest.Int64, newest.Int64, oldest.Valid && newest.Valid, nil
}

// crawlersCSVRows sums the window's hourly rows into days: one row per
// (local date, site, category, crawler), sorted in that order.  site is the
// site picker's ("" = every site, each on rows of its own).  The rows begin
// where the per-site table does: what was counted before it existed is in
// the install-wide tables only, under no site, and is not in the file.
//
// The table is stored by UTC hour and the days are the operator's, so each
// hour bucket goes to the local date its first instant falls on -- worked
// out here, not in SQL, like every other day boundary.  In a zone whose
// offset is not a whole number of hours a bucket straddles local midnight,
// and the day edges are hour-granular there: up to half an hour of one day
// is counted with its neighbour.
//
// The sums themselves are the database's, one query per local day over that
// day's run of hours.  The table holds a row per hour, site and crawler, and
// a month of an install with many sites is a great many of them: summed
// there, only the file's rows come back, a day's at a time, and the
// connection is free for other requests between the days.
func crawlersCSVRows(ctx context.Context, h *Handler, win crawlersCSVWin, site string, loc *time.Location) ([]crawlersCSVRow, error) {
	// Only the hours the table holds are walked: a window may be asked for
	// that is years wider (the page's "all", a custom range of any dates).
	lo, hi, ok, err := crawlerSiteExtent(ctx, h)
	if err != nil || !ok {
		return nil, err
	}
	from, to := max(win.fromHour, lo), min(win.toHour, hi)

	stmt := crawlersCSVDayStmt
	if site != "" {
		stmt = crawlersCSVDaySiteStmt
	}
	dateOf := func(hour int64) string { return time.Unix(hour*3600, 0).In(loc).Format("2006-01-02") }

	type key struct{ date, site, category, crawler string }
	sums := map[key]*crawlersCSVRow{}
	for start := from; start <= to; {
		// The run of hours that share start's local date.
		date, end := dateOf(start), start
		for end < to && dateOf(end+1) == date {
			end++
		}
		args := []any{start, end}
		if site != "" {
			args = append(args, site)
		}
		rows, err := h.DB.QueryContext(ctx, stmt, args...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			k := key{date: date}
			var total, served, verified, named int
			if err := rows.Scan(&k.site, &k.category, &k.crawler, &total, &served, &verified, &named); err != nil {
				rows.Close()
				return nil, err
			}
			// A date comes from one run of hours, so a key is new here; the
			// sums are merged all the same, should a zone ever say otherwise.
			row := sums[k]
			if row == nil {
				row = &crawlersCSVRow{date: k.date, site: k.site, category: k.category, crawler: k.crawler}
				sums[k] = row
			}
			row.total += total
			row.served += served
			row.verified += verified
			row.named += named
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, err
		}
		start = end + 1
	}
	out := make([]crawlersCSVRow, 0, len(sums))
	for _, row := range sums {
		out = append(out, *row)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		switch {
		case a.date != b.date:
			return a.date < b.date
		case a.site != b.site:
			return a.site < b.site
		case a.category != b.category:
			return a.category < b.category
		}
		return a.crawler < b.crawler
	})
	return out, nil
}

// csvText guards a text cell against being run as a formula by the
// spreadsheet that opens the file: a cell that starts with =, +, -, @, a tab
// or a carriage return is evaluated there, and the site is a Host header --
// whatever a client sent.  Such a cell gets a leading apostrophe, which a
// spreadsheet reads as "text follows".
func csvText(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + s
	}
	return s
}

// AdminCrawlersCSV: GET {base}/admin/stats/crawlers.csv[?range=|from=&to=]
//
// The crawler counters by day, site, category and crawler, as a CSV download.
// The window is the statistics page's (crawlersCSVWindow, 30 days by
// default), the days are the operator's (the TZ cookie), and the site picker
// narrows it to one site as it narrows the page.  Open to every role that
// opens the statistics page: it is that page's data.
func (h *Handler) AdminCrawlersCSV(w http.ResponseWriter, r *http.Request) {
	if h.DB == nil {
		http.Error(w, "the database is not available", http.StatusServiceUnavailable)
		return
	}
	loc := resolveLocation(r)
	win := crawlersCSVWindow(r, time.Now(), loc)
	site := crawlerSiteFilter(resolveSiteFilter(r))
	ctx, cancel := context.WithTimeout(r.Context(), crawlersCSVTimeout)
	defer cancel()
	rows, err := crawlersCSVRows(ctx, h, win, site, loc)
	if err != nil {
		if r.Context().Err() != nil {
			return // the client went away: nobody to answer
		}
		log.Printf("crawlers csv (site=%s hours=%d..%d): %v", LogSafe(site), win.fromHour, win.toHour, err)
		http.Error(w, "could not read the crawler counters", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="unmask-crawlers-`+win.fromDate+`_`+win.toDate+`.csv"`)
	w.Header().Set("Cache-Control", "no-store")
	// Whether a crawler's vendor publishes ranges, asked once per name.
	published := map[string]string{}
	cw := csv.NewWriter(w)
	_ = cw.Write(crawlersCSVHeader)
	for _, row := range rows {
		pub, ok := published[row.crawler]
		if !ok {
			pub = "0"
			if yes, _ := nginxconf.CrawlerVendorRange(row.crawler, ""); yes {
				pub = "1"
			}
			published[row.crawler] = pub
		}
		_ = cw.Write([]string{
			csvText(row.date), csvText(row.site), csvText(row.category), csvText(row.crawler),
			strconv.Itoa(row.total), strconv.Itoa(row.served), strconv.Itoa(row.total - row.served),
			strconv.Itoa(row.verified), strconv.Itoa(row.named), pub,
		})
	}
	cw.Flush()
	if err := cw.Error(); err != nil && r.Context().Err() == nil {
		log.Printf("crawlers csv: write: %v", err)
	}
}
