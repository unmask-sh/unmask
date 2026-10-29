package nginxlog

import (
	"context"
	"database/sql"
	"hash/fnv"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/events"
)

// The passes behind the reuse: per (day, site, address), how many distinct
// pass cookies were presented and how busy one of them got in an hour, into
// unmask_pass_ip_day (migration 0049).  unmask_cookie_ip_minute counts the
// REQUESTS an address makes on a pass; this counts the PASSES.  A pass is
// bound to the address and the host, so one cookie is one browser on one
// network: an address with many is many people (an office proxy, a carrier
// NAT) or one client solving the challenge over and over, and one riding a
// single pass hard shows in the hourly peak.  Those two figures are what a
// per-cookie limit would be read against -- and what the reuse cap, which
// counts per address, cannot tell apart.
//
// The pass is named by the entry of the _bv value that verified for the
// client (Reader.SetPassMatcher: the daemon verifies the way the plugin did),
// so a browser carrying one entry per network it solved on counts once per
// network, and junk entries padded around a valid one count for nothing.
// With no matcher, or when none verifies, the value as carried names it:
// never fewer passes than there were.
//
// The day's set of passes lives in memory (a hash per pass) and its size is
// written at every flush; a restart forgets the set, and the row keeps the
// larger of what it had and what the daemon has seen since, so a day's count
// can fall short of the truth, never run past it.  Days and hours are UTC.

type passKey struct {
	day  int64 // unix day (epoch seconds / 86400, UTC)
	site string
	ip   string
}

type passBucket struct {
	ids  map[uint64]struct{} // the day's distinct passes, hashed
	ja4s map[string]struct{} // the fingerprints seen with them, up to passJA4Max
	// cnt / judged: since the last flush (the row accumulates them).
	cnt    int
	judged int
	// peak: the most judged requests one pass made in an hour of the day.
	peak     int
	ja4      string // latest fingerprint seen for the address in the day
	ua       string // latest User-Agent, cut to the column
	lastSeen int64
	dirty    bool // something to write since the last flush
}

// passHourKey counts one pass's judged requests in one hour, for the peak.
type passHourKey struct {
	hour int64
	site string
	id   uint64
}

// passEntry is what one flush writes for a bucket.
type passEntry struct {
	key                              passKey
	cookies, ja4s, cnt, judged, peak int
	ja4, ua                          string
	lastSeen                         int64
}

const (
	// passBucketsMax bounds the (day, site, address) buckets, passIDsMax the
	// passes held across them and passHoursMax the hourly counters.  Past a
	// bound a new address, pass or hour is not counted rather than let the
	// maps grow for as long as a flood lasts: the figures then fall short,
	// never run past.
	passBucketsMax = 200000
	passIDsMax     = 500000
	passHoursMax   = 500000
	// passJA4Max bounds the fingerprints kept per address and day: past it
	// the count has said what it has to say (a shared address).
	passJA4Max = 256
	// passJA4Width is the ja4 column's width (a fingerprint is 36 bytes).
	passJA4Width = 40
)

// passID folds a pass's name to the hash the sets hold.
func passID(s string) uint64 {
	h := fnv.New64a()
	h.Write([]byte(s))
	return h.Sum64()
}

// SetPassMatcher installs the function that names the pass a logged request
// rode on -- the entry of the _bv value that verifies for the address and the
// host, "" when none does (handlers.Handler.MatchPassEntry).  nil-safe.
func (r *Reader) SetPassMatcher(f func(value, ip, host string) string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.matchPass = f
	r.mu.Unlock()
}

// bumpPass records one line carrying a verified pass (kind set, bv the value
// as logged) into the day's bucket of its address.  site is the bucket's
// site (OtherSite past the cap), host the $host the cookie is bound to.
// Runs on the log reader's goroutine.  nil-safe.
func (r *Reader) bumpPass(site, host, ip, ja4, ua, bv, kind string, judged bool) {
	r.bumpPassAt(site, host, ip, ja4, ua, bv, kind, judged, time.Now())
}

func (r *Reader) bumpPassAt(site, host, ip, ja4, ua, bv, kind string, judged bool, now time.Time) {
	if r == nil || r.d == nil || kind == "" || bv == "" || ip == "" {
		return
	}
	r.mu.Lock()
	match := r.matchPass
	r.mu.Unlock()
	name := ""
	if match != nil {
		name = match(bv, ip, host) // the HMAC / SHA-256 work, outside the lock
	}
	if name == "" {
		name = bv
	}
	id := passID(name)
	if len(ua) > cookieIPUAMax {
		ua = ua[:cookieIPUAMax]
	}
	if len(ja4) > passJA4Width {
		ja4 = ja4[:passJA4Width]
	}
	ts := now.Unix()
	key := passKey{day: ts / 86400, site: site, ip: ip}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.passBuckets == nil {
		r.passBuckets = map[passKey]*passBucket{}
	}
	if r.passHours == nil {
		r.passHours = map[passHourKey]int{}
	}
	b := r.passBuckets[key]
	if b == nil {
		if len(r.passBuckets) >= passBucketsMax {
			return
		}
		b = &passBucket{ids: map[uint64]struct{}{}, ja4s: map[string]struct{}{}}
		r.passBuckets[key] = b
	}
	if _, seen := b.ids[id]; !seen && r.passIDs < passIDsMax {
		b.ids[id] = struct{}{}
		r.passIDs++
	}
	if ja4 != "" {
		if _, seen := b.ja4s[ja4]; !seen && len(b.ja4s) < passJA4Max {
			b.ja4s[ja4] = struct{}{}
		}
		b.ja4 = ja4
	}
	b.cnt++
	if judged {
		b.judged++
		hk := passHourKey{hour: ts / 3600, site: site, id: id}
		n, ok := r.passHours[hk]
		if ok || len(r.passHours) < passHoursMax {
			n++
			r.passHours[hk] = n
			if n > b.peak {
				b.peak = n
			}
		}
	}
	b.ua = ua
	b.lastSeen = ts
	b.dirty = true
}

// collectPassLocked takes what the buckets have to write (the caller holds
// r.mu): every dirty bucket, its deltas reset.  A bucket of a past day with
// nothing left to write is dropped -- its day is over -- and the hourly
// counters of past hours with it.
func (r *Reader) collectPassLocked(now time.Time) []passEntry {
	today, hour := now.Unix()/86400, now.Unix()/3600
	out := make([]passEntry, 0, len(r.passBuckets))
	for k, b := range r.passBuckets {
		if b.dirty {
			out = append(out, passEntry{key: k, cookies: len(b.ids), ja4s: len(b.ja4s),
				cnt: b.cnt, judged: b.judged, peak: b.peak, ja4: b.ja4, ua: b.ua, lastSeen: b.lastSeen})
			b.cnt, b.judged, b.dirty = 0, 0, false
		} else if k.day < today {
			r.passIDs -= len(b.ids)
			delete(r.passBuckets, k)
		}
	}
	for k := range r.passHours {
		if k.hour < hour {
			delete(r.passHours, k)
		}
	}
	return out
}

// restorePassLocked puts the deltas of a failed flush back (the caller holds
// r.mu); the levels never left memory.
func (r *Reader) restorePassLocked(entries []passEntry) {
	for _, e := range entries {
		b := r.passBuckets[e.key]
		if b == nil {
			b = &passBucket{ids: map[uint64]struct{}{}, ja4s: map[string]struct{}{},
				peak: e.peak, ja4: e.ja4, ua: e.ua, lastSeen: e.lastSeen}
			r.passBuckets[e.key] = b
		}
		b.cnt += e.cnt
		b.judged += e.judged
		b.dirty = true
	}
}

// execer is the part of *sql.Tx the flush writes through.
type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// execPass writes the entries into unmask_pass_ip_day, inside the flush's
// transaction.
func (r *Reader) execPass(ctx context.Context, tx execer, entries []passEntry) error {
	if len(entries) == 0 {
		return nil
	}
	stmt := passUpsertStmt(r.d.Driver)
	for _, e := range entries {
		// The canonical bytes form (= unmask_event.ip_address): an
		// unparseable address is skipped rather than stored as garbage.
		ipb := events.PackIP(e.key.ip)
		if ipb == nil {
			continue
		}
		lastSeen := time.Unix(e.lastSeen, 0).UTC().Format("2006-01-02 15:04:05.000")
		if _, err := tx.ExecContext(ctx, stmt,
			e.key.day, e.key.site, ipb, e.cookies, e.ja4s, e.ja4, e.cnt, e.judged, e.peak, e.ua, lastSeen); err != nil {
			return err
		}
	}
	return nil
}

// passUpsertStmt: (bucket_day, site, ip) is the unique key.  cookies, ja4s
// and peak_hour are levels and keep the larger (a restarted daemon writes a
// smaller set, which must not lower the row); cnt and judged accumulate;
// ja4, ua and last_seen take the latest write.
func passUpsertStmt(drv db.Driver) string {
	if drv == db.DriverSQLite {
		return `INSERT INTO unmask_pass_ip_day (bucket_day, site, ip, cookies, ja4s, ja4, cnt, judged, peak_hour, ua, last_seen)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(bucket_day, site, ip) DO UPDATE SET
				cookies = MAX(cookies, excluded.cookies), ja4s = MAX(ja4s, excluded.ja4s),
				cnt = cnt + excluded.cnt, judged = judged + excluded.judged,
				peak_hour = MAX(peak_hour, excluded.peak_hour),
				ja4 = excluded.ja4, ua = excluded.ua, last_seen = excluded.last_seen`
	}
	return `INSERT INTO unmask_pass_ip_day (bucket_day, site, ip, cookies, ja4s, ja4, cnt, judged, peak_hour, ua, last_seen)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE
			cookies = GREATEST(cookies, VALUES(cookies)), ja4s = GREATEST(ja4s, VALUES(ja4s)),
			cnt = cnt + VALUES(cnt), judged = judged + VALUES(judged),
			peak_hour = GREATEST(peak_hour, VALUES(peak_hour)),
			ja4 = VALUES(ja4), ua = VALUES(ua), last_seen = VALUES(last_seen)`
}
