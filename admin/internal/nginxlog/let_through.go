package nginxlog

import (
	"context"
	"database/sql"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/events"
	"github.com/unmask-sh/unmask/admin/internal/hll"
)

// What the site answered without a challenge, and why: per (hour, site,
// reason, detail) the requests and the addresses behind them
// (unmask_let_hourly), and for every reason but the pass cookie the addresses
// themselves, the busiest of the hour (unmask_let_ip_hourly, migration 0052).
//
// A request that is let through fires no challenge and writes no event; the
// access log is the only record of it, and until this table it said how many
// and never who.  The admin lists them (BAN > Let through) so that a ground
// for passing that somebody is leaning on -- a crawler's name anyone can
// claim, a bypass path wider than it was meant, a location left without
// protect.inc -- shows, with the address to ban.
//
// The reason is the configuration's (why=, http.inc's $unmask_why_log); the
// detail is the daemon's: the cookie's kind, the bypass range or path row the
// request matched (SetLetThroughDetail), the crawler's name.  Reason "none"
// is a request that got through on no ground the configuration can name: a
// fault to report.  The page lists it last -- it should be empty -- and the
// admin's notification list says when it is not (SetLetFaultObserver).
//
// A pass cookie is counted and not listed: it is every visitor who cleared
// the challenge, the reuse ranking and the pass count already keep its
// addresses (unmask_cookie_ip_minute, unmask_pass_ip_day), and nothing about
// it is a way round the check.
//
// The addresses of a bucket are held to letAddrsPerKey.  Past that a new
// address takes the place of one that has made room-worthy few requests of
// its own (letAddrSettled or fewer), the lowest-standing of those, and
// inherits its standing: an address that keeps coming is past that mark
// after a few requests and stays, while a crowd of one-request addresses
// turns over beneath it.  Only a bucket whose every address is past the mark
// gives up its lowest-standing one.  The row of an address pushed out is
// deleted, and the bucket's totals -- requests, and the address sketch --
// keep counting everything.  What the list does not promise, then: on a
// ground a crowd passes on, an address with a request or two an hour is in
// the totals and not in the list.  Hours are UTC.
//
// What it may hold is bounded twice over (letKeysMax, letAddrsMax), because
// both of its dimensions are a client's to vary: a catch-all vhost takes any
// Host, and a crowd of addresses costs whoever rents one nothing.  Neither
// bound drops a request from the totals.
//
// Nodes that share one database each hold their own hundred, and each
// deletes the rows of the addresses it pushes out -- that is what keeps the
// table to a hundred rows a node.  An address one node pushes out while
// another still counts it therefore loses its row, and gets one again, with
// the count from there on, at its next request through the other.  The
// totals are not touched by this: they are read, merged and written under
// the flush's lock.

// The reasons of why=.
const (
	LetCookie  = "cookie"  // a valid pass
	LetIP      = "ip"      // a bypass address
	LetPath    = "path"    // a bypass path
	LetName    = "name"    // a crawler known by its name alone
	LetPreview = "preview" // a link-preview fetcher, by its name and its network
	LetGlobal  = "global"  // the Global axis says pass
	LetSigned  = "signed"  // a verified signature or token
	LetWatch   = "watch"   // judged a challenge on a site in monitor mode
	LetNoGate  = "nogate"  // a location without protect.inc
	LetDown    = "down"    // the daemon did not answer: fail-open
	LetAhead   = "ahead"   // judged a challenge; nginx's own answer (a return, a redirect) came first
	LetNone    = "none"    // no ground the configuration can name
)

const (
	// letAddrsPerKey: the addresses kept for one (hour, site, reason, detail).
	letAddrsPerKey = 100
	// letAddrSettled: an address with more requests of its own than this is
	// not displaced while one with fewer is in the bucket.
	letAddrSettled = 2
	// letAddrsFloor: the addresses a bucket may hold when the buckets
	// together hold letAddrsMax.
	letAddrsFloor = 10
	// letKeysSpare: the room past letKeysMax for the buckets a line with none
	// of its own is counted in -- one a reason, so a configuration fills a
	// fraction of it.
	letKeysSpare = 64
	// letHoursHeld: the hours' worth of buckets (letKeysMax each) the reader
	// holds at most.  One hour's are held at a time, and the last hour's for
	// the minute until its flush; more only while flushes fail.
	letHoursHeld = 4

	letReasonWidth = 16
	letDetailWidth = 64
	letPathWidth   = 200
)

// What bounds the memory.  Variables so a test can make them small.
var (
	// letKeysMax bounds the buckets of one hour, each a 1 KiB sketch and its
	// addresses.  A catch-all vhost takes any Host a client sends (aggSite
	// gives 256 new ones a minute a site of their own), and every crawler
	// name on every site is a bucket.  Past the bound a line with no bucket
	// yet is counted under OtherSite with no detail: the request is in the
	// totals and its address is listed, by the ground it passed on, and the
	// map does not grow for as long as the flood lasts.  (The page looks for
	// such an address's pass under that site, so its mark can say less than
	// happened.)
	letKeysMax = 5000
	// letAddrsMax bounds the addresses held across all the buckets.  At it a
	// bucket holding letAddrsFloor or more takes a new address only in the
	// place of one of its own, the way a full bucket does; at twice it so
	// does every bucket, and one that holds none lists nobody.  Twice
	// letAddrsMax is the most the reader holds.
	letAddrsMax = 50000
)

type letKey struct {
	hour   int64 // unix hour (epoch seconds / 3600, UTC)
	site   string
	reason string
	detail string
}

// letAddr is one address of a bucket.
type letAddr struct {
	// floor: the standing inherited from the address this one displaced.
	// The row's cnt is what was counted (pending accumulates into it); the
	// order of displacement is floor + seen.
	floor   int
	seen    int // requests counted since the address was taken in
	pending int // of seen, the ones not written yet
	first   int64
	last    int64
	ja4     string
	ua      string
	path    string
	written bool // a row exists for it
}

type letBucket struct {
	cnt   int        // requests since the last flush
	ips   hll.Sketch // their addresses, since the last flush
	addrs map[string]*letAddr
	// dropped: addresses pushed out whose row is to be deleted.
	dropped []string
	dirty   bool
}

// letAddrEntry / letEntry: what one flush writes for a bucket.
type letAddrEntry struct {
	ip            string
	cnt           int
	first, last   int64
	ja4, ua, path string
}

type letEntry struct {
	key     letKey
	cnt     int
	ips     hll.Sketch
	addrs   []letAddrEntry
	dropped []string
}

// SetLetThroughDetail installs the two functions that name what a bypass
// matched: the range (a preset's id, or the operator's row) an address is in,
// and the bypass path row a path on a host matches.  "" when nothing the
// daemon knows matches -- the render nginx runs may be older than the
// settings.  Called per line; the handler caches its matchers per settings.
// nil-safe.
func (r *Reader) SetLetThroughDetail(ip func(ip string) string, path func(host, path string) string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.letIPDetail, r.letPathDetail = ip, path
	r.mu.Unlock()
}

// SetLetFaultObserver installs the function told, after each flush, of the
// requests the flush wrote under the reason "none": the clock hour (unix
// seconds / 3600) they are counted in, how many, and how many by site.  That
// ground should hold nothing, so the page that lists it is not one an
// operator watches; the admin's notification list is told instead
// (notifier.LetThroughFault).  Called on the flush's goroutine, once an hour
// that had any, after the rows are committed.  nil-safe.
func (r *Reader) SetLetFaultObserver(f func(hour int64, count int, sites map[string]int)) {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.letFault = f
	r.mu.Unlock()
}

// tellLetFault reports what a committed flush wrote under the reason "none",
// by hour.
func (r *Reader) tellLetFault(entries []letEntry) {
	r.mu.Lock()
	tell := r.letFault
	r.mu.Unlock()
	if tell == nil {
		return
	}
	byHour := map[int64]map[string]int{}
	for _, e := range entries {
		if e.key.reason != LetNone || e.cnt <= 0 {
			continue
		}
		sites := byHour[e.key.hour]
		if sites == nil {
			sites = map[string]int{}
			byHour[e.key.hour] = sites
		}
		sites[e.key.site] += e.cnt
	}
	for hour, sites := range byHour {
		n := 0
		for _, c := range sites {
			n += c
		}
		tell(hour, n, sites)
	}
}

// bumpLet counts one line the site answered without a challenge.  site is the
// bucket's site (OtherSite past the cap); the line names the host.  Runs on
// the log reader's goroutine.  nil-safe.
func (r *Reader) bumpLet(site string, p parsed) {
	if r == nil || r.d == nil || p.why == "" || p.ip == "" {
		return
	}
	// The time is the line's own, held to this hour and the last: a stamp
	// from anywhere else would start buckets that no flush ends.
	now := time.Now().Unix()
	ts := int64(p.msec)
	if ts > now+60 || ts < now-3600 {
		ts = now
	}
	reason, detail := r.letReason(p)
	r.bumpLetAt(site, reason, detail, p, ts)
}

// letReason is the reason and the detail a line is filed under.
func (r *Reader) letReason(p parsed) (reason, detail string) {
	reason = fitColumn(p.why, letReasonWidth)
	r.mu.Lock()
	ipDetail, pathDetail := r.letIPDetail, r.letPathDetail
	r.mu.Unlock()
	switch reason {
	case LetCookie:
		detail = p.kind
	case LetIP:
		if ipDetail != nil {
			detail = ipDetail(p.ip)
		}
	case LetPath:
		if pathDetail != nil {
			detail = pathDetail(p.site, p.lp)
		}
	case LetName:
		// pv=1: the configuration checked the fetcher's network as well as
		// its name ($unmask_preview_verified), which is more than a claim.
		if p.pv {
			reason = LetPreview
		}
		if r.classifyCrawler != nil && r.crawlerNamer != nil && p.ua != "" {
			detail = r.crawlerNamer(p.ua, r.classifyCrawler(p.ua))
		}
	}
	return reason, fitColumn(detail, letDetailWidth)
}

// letBucketLocked is the bucket a line is counted in (the caller holds r.mu):
// its own, or, when it has none and its hour holds letKeysMax buckets (or the
// reader letHoursHeld hours' worth, which takes flushes that fail), the one
// of its reason under OtherSite.  nil only past the spare room for those:
// more reasons than a configuration has, or a database that has been away
// for hours.
func (r *Reader) letBucketLocked(key letKey) *letBucket {
	if b := r.letBuckets[key]; b != nil {
		return b
	}
	inHour, held := r.letHourKeys[key.hour], len(r.letBuckets)
	if inHour >= letKeysMax || held >= letHoursHeld*letKeysMax {
		key.site, key.detail = OtherSite, ""
		if b := r.letBuckets[key]; b != nil {
			return b
		}
		if inHour >= letKeysMax+letKeysSpare || held >= letHoursHeld*letKeysMax+letKeysSpare {
			return nil
		}
	}
	return r.newLetBucketLocked(key)
}

func (r *Reader) newLetBucketLocked(key letKey) *letBucket {
	if r.letBuckets == nil { // a Reader made by hand may have none
		r.letBuckets = map[letKey]*letBucket{}
	}
	if r.letHourKeys == nil {
		r.letHourKeys = map[int64]int{}
	}
	b := &letBucket{addrs: map[string]*letAddr{}}
	r.letBuckets[key] = b
	r.letHourKeys[key.hour]++
	return b
}

func (r *Reader) bumpLetAt(site, reason, detail string, p parsed, ts int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	b := r.letBucketLocked(letKey{hour: ts / 3600, site: site, reason: reason, detail: detail})
	if b == nil {
		return
	}
	b.cnt++
	if ipb := events.PackIP(p.ip); ipb != nil {
		b.ips.Add(ipb)
	}
	b.dirty = true
	if reason == LetCookie {
		return
	}
	a := b.addrs[p.ip]
	if a == nil {
		// A full bucket takes a newcomer in the place of one of its own.  So
		// does a bucket that has its share while the buckets together hold
		// letAddrsMax, and any bucket at twice that -- where one that holds
		// nobody lists nobody, and the request is in its totals alone.
		n := len(b.addrs)
		switch {
		case n >= letAddrsPerKey,
			n >= letAddrsFloor && r.letAddrCount >= letAddrsMax,
			n > 0 && r.letAddrCount >= 2*letAddrsMax:
			a = &letAddr{first: ts, floor: b.displace()}
		case r.letAddrCount >= 2*letAddrsMax:
			return
		default:
			a = &letAddr{first: ts}
			r.letAddrCount++
		}
		b.addrs[p.ip] = a
	}
	a.seen++
	a.pending++
	a.last = ts
	if p.ja4 != "" {
		a.ja4 = fitColumn(p.ja4, passJA4Width)
	}
	a.ua = fitColumn(p.ua, cookieIPUAMax)
	if p.lp != "" {
		a.path = fitColumn(p.lp, letPathWidth)
	}
}

// displace takes one address out of the bucket and returns its standing, for
// the address about to take its place: the lowest-standing of those with
// letAddrSettled requests of their own or fewer, and only when there is none
// the lowest-standing of all.  Standing is what Space-Saving counts by --
// the inherited floor plus the requests seen -- so the newcomers take turns;
// preferring the unsettled is what keeps the inherited part from pushing out
// an address whose requests are all its own.  Its row, if one was written, is
// queued for deletion.
func (b *letBucket) displace() int {
	var out, outAny string
	low, lowAny := -1, -1
	for ip, a := range b.addrs {
		s := a.floor + a.seen
		if lowAny < 0 || s < lowAny {
			lowAny, outAny = s, ip
		}
		if a.seen <= letAddrSettled && (low < 0 || s < low) {
			low, out = s, ip
		}
	}
	if out == "" {
		low, out = lowAny, outAny
	}
	if out == "" {
		return 0
	}
	if b.addrs[out].written {
		b.dropped = append(b.dropped, out)
	}
	delete(b.addrs, out)
	return low
}

// collectLetLocked takes what the buckets have to write (the caller holds
// r.mu): every dirty bucket, its deltas reset.  The bucket of an hour that is
// over is dropped with that -- restoreLetLocked brings it back if the flush
// fails, and a line of that hour that comes later still starts it again, its
// counts adding to the rows.  What the reader holds is counted afresh here,
// so the two bounds do not rest on increments alone.
func (r *Reader) collectLetLocked(now time.Time) []letEntry {
	hour := now.Unix() / 3600
	var out []letEntry
	keys, held := map[int64]int{}, 0
	for k, b := range r.letBuckets {
		if b.dirty {
			e := letEntry{key: k, cnt: b.cnt, ips: b.ips, dropped: b.dropped}
			for ip, a := range b.addrs {
				if a.pending == 0 {
					continue
				}
				e.addrs = append(e.addrs, letAddrEntry{ip: ip, cnt: a.pending, first: a.first, last: a.last, ja4: a.ja4, ua: a.ua, path: a.path})
				a.pending = 0
				a.written = true
			}
			b.cnt, b.ips, b.dropped, b.dirty = 0, hll.Sketch{}, nil, false
			out = append(out, e)
		}
		if k.hour < hour {
			delete(r.letBuckets, k)
			continue
		}
		keys[k.hour]++
		held += len(b.addrs)
	}
	r.letHourKeys, r.letAddrCount = keys, held
	return out
}

// restoreLetLocked puts the deltas of a failed flush back (the caller holds
// r.mu), merged with what has been counted since.  An address that was pushed
// out meanwhile is counted in the bucket's total only: its row is on the
// list of deletions already, or was never written.
func (r *Reader) restoreLetLocked(entries []letEntry) {
	for _, e := range entries {
		b := r.letBuckets[e.key]
		if b == nil {
			b = r.newLetBucketLocked(e.key)
		}
		b.cnt += e.cnt
		b.ips.Merge(&e.ips)
		b.dropped = append(e.dropped, b.dropped...)
		b.dirty = true
		for _, ae := range e.addrs {
			a := b.addrs[ae.ip]
			if a == nil {
				if len(b.addrs) >= letAddrsPerKey {
					continue
				}
				a = &letAddr{first: ae.first, last: ae.last, ja4: ae.ja4, ua: ae.ua, path: ae.path, seen: ae.cnt}
				b.addrs[ae.ip] = a
				r.letAddrCount++
			}
			// seen never left the address; only what was on its way did.
			a.pending += ae.cnt
			if ae.first < a.first {
				a.first = ae.first
			}
		}
	}
}

// execLet writes the entries inside the flush's transaction: the totals with
// the address sketch read, merged and written back (the flush's lock keeps
// two nodes from doing that at once), the addresses, and the deletions.
func (r *Reader) execLet(ctx context.Context, tx *sql.Tx, entries []letEntry) error {
	if len(entries) == 0 {
		return nil
	}
	total, addr := letUpsertStmt(r.d.Driver), letAddrUpsertStmt(r.d.Driver)
	for _, e := range entries {
		// Read, merge, write: a row the hour already has keeps the addresses
		// it counted.  A read that fails is read as no row, the way the
		// traffic sketches' is -- the flush is not held up for it.
		var prev []byte
		if err := tx.QueryRowContext(ctx,
			`SELECT ips FROM unmask_let_hourly WHERE bucket_hour = ? AND site = ? AND reason = ? AND detail = ?`,
			e.key.hour, e.key.site, e.key.reason, e.key.detail).Scan(&prev); err == nil && len(prev) > 0 {
			e.ips.MergeBytes(prev)
		}
		// The compact form: a bucket of a site and hour holds a handful of
		// addresses, and the array would be a kilobyte a row for every site,
		// ground and detail of every hour.
		if _, err := tx.ExecContext(ctx, total, e.key.hour, e.key.site, e.key.reason, e.key.detail, e.cnt, e.ips.Compact()); err != nil {
			return err
		}
		for _, ip := range e.dropped {
			ipb := events.PackIP(ip)
			if ipb == nil {
				continue
			}
			if _, err := tx.ExecContext(ctx,
				`DELETE FROM unmask_let_ip_hourly WHERE bucket_hour = ? AND site = ? AND reason = ? AND detail = ? AND ip = ?`,
				e.key.hour, e.key.site, e.key.reason, e.key.detail, ipb); err != nil {
				return err
			}
		}
		for _, a := range e.addrs {
			// The canonical bytes form (= unmask_event.ip_address): an
			// unparseable address is skipped rather than stored as garbage.
			ipb := events.PackIP(a.ip)
			if ipb == nil {
				continue
			}
			if _, err := tx.ExecContext(ctx, addr, e.key.hour, e.key.site, e.key.reason, e.key.detail, ipb,
				a.cnt, letTime(a.first), letTime(a.last), a.ja4, a.ua, a.path); err != nil {
				return err
			}
		}
	}
	return nil
}

func letTime(unix int64) string {
	return time.Unix(unix, 0).UTC().Format("2006-01-02 15:04:05.000")
}

// letUpsertStmt: (bucket_hour, site, reason, detail) is the unique key.  cnt
// accumulates; ips is written whole (execLet merged the row's into it).
func letUpsertStmt(drv db.Driver) string {
	if drv == db.DriverSQLite {
		return `INSERT INTO unmask_let_hourly (bucket_hour, site, reason, detail, cnt, ips)
			VALUES (?, ?, ?, ?, ?, ?)
			ON CONFLICT(bucket_hour, site, reason, detail) DO UPDATE SET
				cnt = cnt + excluded.cnt, ips = excluded.ips`
	}
	return `INSERT INTO unmask_let_hourly (bucket_hour, site, reason, detail, cnt, ips)
		VALUES (?, ?, ?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE
			cnt = cnt + VALUES(cnt), ips = VALUES(ips)`
}

// letAddrUpsertStmt: (bucket_hour, site, reason, detail, ip) is the unique
// key.  cnt accumulates, first_seen keeps the earlier and last_seen the
// later; ja4, ua and path take the latest write.
func letAddrUpsertStmt(drv db.Driver) string {
	if drv == db.DriverSQLite {
		return `INSERT INTO unmask_let_ip_hourly (bucket_hour, site, reason, detail, ip, cnt, first_seen, last_seen, ja4, ua, path)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(bucket_hour, site, reason, detail, ip) DO UPDATE SET
				cnt = cnt + excluded.cnt,
				first_seen = MIN(first_seen, excluded.first_seen), last_seen = MAX(last_seen, excluded.last_seen),
				ja4 = excluded.ja4, ua = excluded.ua, path = excluded.path`
	}
	return `INSERT INTO unmask_let_ip_hourly (bucket_hour, site, reason, detail, ip, cnt, first_seen, last_seen, ja4, ua, path)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE
			cnt = cnt + VALUES(cnt),
			first_seen = LEAST(first_seen, VALUES(first_seen)), last_seen = GREATEST(last_seen, VALUES(last_seen)),
			ja4 = VALUES(ja4), ua = VALUES(ua), path = VALUES(path)`
}

// letRows is the number of statements a flush of entries takes, for its
// deadline.
func letRows(entries []letEntry) int {
	n := 0
	for _, e := range entries {
		n += 2 + len(e.addrs) + len(e.dropped)
	}
	return n
}
