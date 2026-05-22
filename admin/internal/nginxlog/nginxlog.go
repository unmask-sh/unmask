// Package nginxlog: receive nginx's access_log over a Unix datagram
// socket, aggregate it into per-minute buckets, and write into the DB
// (= unmask_cookie_minute table).
//
// On the nginx side (= rendered by admin at /etc/unmask/nginx-rendered.conf):
//
//	log_format unmask_minimal '$msec site=$host kind=$bv_kind fc=$final_challenge hp=$serve_bot_challenge ip=$remote_addr ja4=$effective_ja4 ua=$http_user_agent';
//	access_log syslog:server=unix:/run/unmask/log.sock unmask_minimal;
//
// The ua= field (always last — it contains spaces) is classified into crawler
// categories and aggregated into unmask_crawler_minute, which feeds the
// overview "crawler traffic" funnel.  This is the only place a rescued crawler
// is counted: it is passed straight through and never lands in unmask_event.
//
// One req is recorded as **one row**.  total is separate.  The
// classification goes into the kind column:
//   - "total"            : all reqs.  always +1
//   - "captcha"          : repeater carrying a 3-seg _bv with HMAC OK
//   - "pow"              : repeater carrying a 4-seg _bv with djb2 OK
//   - "challenge_served" : $final_challenge=1 (= the req was rejected)
//   - extensibility: if the plugin returns a new kind ("signature" /
//          "webauthn" / "passkey" etc.), it gets recorded as a new
//          row automatically with no schema change.
//
// Mutual exclusion: a req where kind="captcha" or "pow" doesn't become
// challenge_served (= bv_any_valid=1 on the nginx side ->
// final_challenge=0).  Each req is exactly total +1 + (one
// classification +1).
//
// nginx sends one datagram per req.  The Reader in this package binds
// via `net.ListenUnixgram` and receives them, ++ing the counter in an
// in-memory map[(minute, site)].  Every 60s tick, UPSERT the buckets
// that are older than the current minute into the DB (= cnt = cnt +
// delta).
//
// Benefits:
//   - No intermediate file (= /var/log/nginx/unmask-access.log is gone).
//   - logrotate is irrelevant.
//   - DB writes don't scale with req count (= sites x 1/min).
//   - History survives admin restarts on the DB side (= a brief loss
//     window exists when the worker silently drops because the socket
//     is absent, but it's acceptable for aggregation).
//
// syslog protocol:
//   nginx's `access_log syslog:` is RFC 3164.  The line head has a
//   <priority> prefix (e.g. "<134>") + optional timestamp/host, so
//   strip them on the parse side.
package nginxlog

import (
	"context"
	"log"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
)

// Reader: body of the recv goroutine + flush goroutine.  Disabled
// when Loaded()=false.
type Reader struct {
	socketPath string
	d          *db.DB
	conn       *net.UnixConn

	mu             sync.Mutex
	buckets        map[bucketKey]*bucket
	crawlerBuckets map[crawlerKey]*crawlerBucket

	// onHoneypot: callback for honeypot-path-trip events (= hp=1 lines).
	// Wired up by the ban manager via SetHoneypotCallback.  nil-safe.
	onHoneypot func(ip, ja4 string)

	// classifyCrawler: UA -> crawler category ("search"/"training"/... or "").
	// Wired by main via SetCrawlerClassifier(classify.AICategory).  Set once at
	// startup before traffic; nil-safe (no crawler aggregation when unset).
	classifyCrawler func(ua string) string

	stop  chan struct{}
	doneA chan struct{} // recv goroutine completion signal
	doneB chan struct{} // flush goroutine completion signal
}

// SetHoneypotCallback: register a callback invoked on hp=1 lines.
// Intended to receive the ban manager's Add(ip, ja4).
func (r *Reader) SetHoneypotCallback(f func(ip, ja4 string)) {
	if r == nil {
		return
	}
	r.onHoneypot = f
}

// SetCrawlerClassifier: register the UA -> crawler-category function (=
// classify.AICategory).  Without it, crawler aggregation is skipped.
func (r *Reader) SetCrawlerClassifier(f func(ua string) string) {
	if r == nil {
		return
	}
	r.classifyCrawler = f
}

type bucketKey struct {
	minute int64  // unix sec / 60
	site   string // "" is equivalent to "default"
}

// crawlerKey / crawlerBucket: per-minute, per-category aggregation for the
// overview crawler funnel.  total = every request of that crawler category;
// served = the subset that did not pass straight through (= challenged).
type crawlerKey struct {
	minute   int64
	category string
}

type crawlerBucket struct {
	total  int
	served int
}

// bucket: per-minute, per-site aggregation bucket.  total counts every
// req; kinds maps a classification name to a count (= "captcha" /
// "pow" / "challenge_served" / future additions).  Reqs with an
// unknown / empty kind only +1 total and don't show up in kinds
// (= the dashboard back-computes the "no cookie" classification as
// total - sum(kinds)).
type bucket struct {
	total int
	kinds map[string]int
}

// Start: if socketPath is empty, return a disabled stub
// (= goroutines don't run).  Otherwise bind the Unix datagram socket
// and start the two recv + flush goroutines.
//
// An existing socket file is deleted and re-created (= residue from
// a prior admin).  Permissions are 0660.  Group-share the socket so
// the nginx worker (= usually the nginx user) can write to it:
//
//	add SupplementaryGroups=nginx to the systemd unit so admin joins the nginx group,
//	or add nginx to the unmask group,
//	or raise the mode to 0666 (= within the same host the impact is small).
func Start(socketPath string, d *db.DB) *Reader {
	r := &Reader{
		socketPath:     socketPath,
		d:              d,
		buckets:        map[bucketKey]*bucket{},
		crawlerBuckets: map[crawlerKey]*crawlerBucket{},
		stop:           make(chan struct{}),
		doneA:          make(chan struct{}),
		doneB:          make(chan struct{}),
	}
	if d == nil {
		close(r.doneA)
		close(r.doneB)
		return r
	}
	// Even when socket path is unset (= auth_request mode etc.), run
	// the DB flush goroutine.  recvLoop is unnecessary (= buckets are
	// incremented externally via Bump()).
	if socketPath == "" {
		close(r.doneA) // no recv
		go r.flushLoop()
		return r
	}

	// Create the parent dir (= /run/unmask etc.).  Operationally we
	// expect systemd's RuntimeDirectory to create it, but in dev /
	// Docker admin may create it.
	// systemd's default RuntimeDirectoryMode is 0755, but if the unit
	// explicitly specifies 0750 then the nginx worker (= a different
	// user) can't traverse the dir and can't connect to the socket
	// (= [alert] connect() failed: Permission denied while logging to syslog).
	// Explicitly loosen to 0755 here to permit world rx (= the socket
	// file itself is chmoded to 0666 below, so as long as the dir's x
	// bit lets nginx through, it can write).
	if dir := filepath.Dir(socketPath); dir != "" && dir != "." {
		_ = os.MkdirAll(dir, 0o755)
		_ = os.Chmod(dir, 0o755)
	}
	// Delete any existing socket file (= residue from a prior admin.
	// If it's still there, bind fails).
	_ = os.Remove(socketPath)

	addr := &net.UnixAddr{Name: socketPath, Net: "unixgram"}
	conn, err := net.ListenUnixgram("unixgram", addr)
	if err != nil {
		log.Printf("nginxlog: ListenUnixgram %s failed: %v (= aggregation disabled)", socketPath, err)
		close(r.doneA)
		close(r.doneB)
		return r
	}
	// Loosen the mode so the nginx worker can write (= 0666).  In
	// production, group-based ownership is recommended.
	if err := os.Chmod(socketPath, 0o666); err != nil {
		log.Printf("nginxlog: chmod %s 0666 failed: %v", socketPath, err)
	}
	r.conn = conn
	log.Printf("nginxlog: listening on unix:%s", socketPath)

	go r.recvLoop()
	go r.flushLoop()
	return r
}

// Close: stop the goroutines.  Final-flush remaining buckets and
// delete the socket file.
func (r *Reader) Close() {
	if r == nil {
		return
	}
	select {
	case <-r.stop:
		return
	default:
		close(r.stop)
	}
	if r.conn != nil {
		// Use SetReadDeadline to break the blocking read and let recvLoop exit.
		_ = r.conn.SetReadDeadline(time.Unix(1, 0))
	}
	<-r.doneA
	<-r.doneB
	r.flushOnce(true)
	if r.conn != nil {
		_ = r.conn.Close()
	}
	if r.socketPath != "" {
		_ = os.Remove(r.socketPath)
	}
}

// Loaded: whether the socket is bound and aggregation is enabled.
func (r *Reader) Loaded() bool {
	return r != nil && r.conn != nil
}

// regex is the core of log_format unmask_minimal (= what remains
// after stripping the syslog prefix).
//
//	$msec site=$host kind=$bv_kind fc=$final_challenge
//	  hp=$serve_bot_challenge ip=$remote_addr ja4=$effective_ja4
//	  ua=$http_user_agent
//
// nginx's syslog target puts "<priority>" + optionally timestamp +
// host at the head of the line, so we use a simple "find the
// $msec-looking number" anchor.
//
// kind values: the $unmask_bv_kind string the plugin returns
// ("captcha" / "pow" / "" / future additions).  [a-z0-9_-] is enough
// (= plugin implementations always use ASCII lowercase as a constraint).
//
// fc / hp / ip / ja4 / ua are optional groups (= degrade gracefully even
// with older config or mode mismatch).  ua is last and matched with .* —
// it contains spaces, so it must be the final field of the log line.
//
// site is matched as \S* (any non-space): the field carries $host, which is a
// real vhost name with dots / colons (an earlier [A-Za-z0-9_-] charset failed
// to parse anything but a bare "default").
var lineRE = regexp.MustCompile(
	`([0-9]+\.[0-9]+) site=(\S*) kind=([a-z0-9_-]*)` +
		`(?: fc=([01]))?(?: hp=([01]))?(?: ip=([0-9a-fA-F:.]+))?(?: ja4=([A-Za-z0-9_]+))?(?: ua=(.*))?`)

// parsed: struct holding the regex match result.
type parsed struct {
	msec float64
	site string
	kind string // "" / "captcha" / "pow" / future additions
	fc   bool
	hp   bool
	ip   string
	ja4  string
	ua   string
}

func (r *Reader) parse(line string) (parsed, bool) {
	m := lineRE.FindStringSubmatch(line)
	if m == nil {
		return parsed{}, false
	}
	v, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return parsed{}, false
	}
	s := m[2]
	if s == "" {
		s = "default"
	}
	return parsed{
		msec: v, site: s,
		kind: m[3],
		fc:   m[4] == "1",
		hp:   m[5] == "1",
		ip:   m[6],
		ja4:  m[7],
		ua:   m[8],
	}, true
}

// onLine: called from the recv goroutine.  Just increments the
// counter in the in-memory map.
//
// kind and fc are mutually exclusive in principle (= bv_any_valid=1
// implies final_challenge=0), but as a safety we prefer kind != "".
// Counting priority:
//
//	kind != "" (= "captcha" / "pow" / future additions)  > fc (= challenge served)
//	> white (= no signals tripped.  Dashboard computes via total - sum(kinds))
func (r *Reader) onLine(line string) {
	p, ok := r.parse(line)
	if !ok {
		return
	}
	if p.hp && r.onHoneypot != nil && p.ip != "" {
		r.onHoneypot(p.ip, p.ja4)
	}
	kind := p.kind
	if kind == "" && p.fc {
		kind = "challenge_served"
	}
	r.Bump(p.site, kind)
	// Crawler funnel: every request carries a UA.  fc=1 (= a challenge was the
	// final action) counts as "served"; otherwise the request passed straight
	// through (rescued / valid cookie).
	r.bumpCrawler(p.ua, p.fc)
}

// Bump: increment the minute bucket by 1 from outside
// (= auth_request mode in /api/check).  site == "" is treated as
// "default".  kind == "" only +1s total (= records the "no cookie"
// case).
//
// We flow into the same aggregation as the nginxlog syslog path, so
// the dashboard's cookie-pass-rate chart looks identical regardless
// of mode.
//
// nil-safe (= no-op when Reader isn't running).
func (r *Reader) Bump(site, kind string) {
	if r == nil || r.d == nil {
		return
	}
	key := bucketKey{minute: time.Now().Unix() / 60, site: site}
	r.mu.Lock()
	b, ok := r.buckets[key]
	if !ok {
		b = &bucket{kinds: map[string]int{}}
		r.buckets[key] = b
	}
	b.total++
	if kind != "" {
		b.kinds[kind]++
	}
	r.mu.Unlock()
}

// bumpCrawler: classify ua and increment its per-minute crawler bucket.
// served=true means the request did not pass straight through (= challenged).
// No-op when the classifier is unset or the UA is not a crawler.
func (r *Reader) bumpCrawler(ua string, served bool) {
	if r == nil || r.d == nil || r.classifyCrawler == nil || ua == "" {
		return
	}
	cat := r.classifyCrawler(ua)
	if cat == "" {
		return
	}
	key := crawlerKey{minute: time.Now().Unix() / 60, category: cat}
	r.mu.Lock()
	b := r.crawlerBuckets[key]
	if b == nil {
		b = &crawlerBucket{}
		r.crawlerBuckets[key] = b
	}
	b.total++
	if served {
		b.served++
	}
	r.mu.Unlock()
}

// BumpCrawler: exported entry point for auth_request mode (= /api/check has
// the UA but emits no access-log line of its own).  nil-safe.
func (r *Reader) BumpCrawler(ua string, served bool) {
	if r == nil {
		return
	}
	r.bumpCrawler(ua, served)
}

// flushOnce: UPSERT buckets "older than the current minute" into the DB.
// final=true flushes everything including the current minute (= for shutdown).
// Both the cookie-minute and crawler-minute buckets flush in one transaction.
func (r *Reader) flushOnce(final bool) {
	if r == nil || r.d == nil {
		return
	}
	nowMin := time.Now().Unix() / 60

	type entry struct {
		key bucketKey
		b   bucket
	}
	type crawlerEntry struct {
		key crawlerKey
		b   crawlerBucket
	}
	r.mu.Lock()
	ready := make([]entry, 0, len(r.buckets))
	for k, b := range r.buckets {
		if final || k.minute < nowMin {
			// deep copy to avoid sharing the kinds map with later mutations
			copyKinds := make(map[string]int, len(b.kinds))
			for kk, vv := range b.kinds {
				copyKinds[kk] = vv
			}
			ready = append(ready, entry{k, bucket{total: b.total, kinds: copyKinds}})
			delete(r.buckets, k)
		}
	}
	crawlerReady := make([]crawlerEntry, 0, len(r.crawlerBuckets))
	for k, b := range r.crawlerBuckets {
		if final || k.minute < nowMin {
			crawlerReady = append(crawlerReady, crawlerEntry{k, *b})
			delete(r.crawlerBuckets, k)
		}
	}
	r.mu.Unlock()

	if len(ready) == 0 && len(crawlerReady) == 0 {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tx, err := r.d.BeginTx(ctx, nil)
	if err != nil {
		log.Printf("nginxlog: flush BeginTx: %v", err)
		// put back into memory (= retry on the next flush)
		r.mu.Lock()
		for _, e := range ready {
			b, ok := r.buckets[e.key]
			if !ok {
				bb := bucket{total: e.b.total, kinds: map[string]int{}}
				for k, v := range e.b.kinds {
					bb.kinds[k] = v
				}
				r.buckets[e.key] = &bb
			} else {
				b.total += e.b.total
				for k, v := range e.b.kinds {
					b.kinds[k] += v
				}
			}
		}
		for _, e := range crawlerReady {
			if b, ok := r.crawlerBuckets[e.key]; ok {
				b.total += e.b.total
				b.served += e.b.served
			} else {
				bb := e.b
				r.crawlerBuckets[e.key] = &bb
			}
		}
		r.mu.Unlock()
		return
	}

	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	stmtKind := upsertStmt(r.d.Driver)
	for _, e := range ready {
		// 1 row: kind="total" gets total +N
		if _, err := tx.ExecContext(ctx, stmtKind,
			e.key.minute, e.key.site, "total", e.b.total); err != nil {
			log.Printf("nginxlog: flush exec(total): %v", err)
			return
		}
		// 1 row per non-empty kind (= captcha / pow / challenge_served / future additions)
		for k, v := range e.b.kinds {
			if v == 0 || k == "" {
				continue
			}
			if _, err := tx.ExecContext(ctx, stmtKind,
				e.key.minute, e.key.site, k, v); err != nil {
				log.Printf("nginxlog: flush exec(kind=%s): %v", k, err)
				return
			}
		}
	}
	stmtCrawler := crawlerUpsertStmt(r.d.Driver)
	for _, e := range crawlerReady {
		if _, err := tx.ExecContext(ctx, stmtCrawler,
			e.key.minute, e.key.category, e.b.total, e.b.served); err != nil {
			log.Printf("nginxlog: flush exec(crawler=%s): %v", e.key.category, err)
			return
		}
	}
	if err := tx.Commit(); err != nil {
		log.Printf("nginxlog: flush commit: %v", err)
		return
	}
	committed = true
}

// upsertStmt: accumulate cnt with (bucket_min, site, kind) as the unique key.
// Extensibility: kind can be any ASCII string.  New kinds don't require a schema change.
func upsertStmt(drv db.Driver) string {
	if drv == db.DriverSQLite {
		return `INSERT INTO unmask_cookie_minute (bucket_min, site, kind, cnt)
			VALUES (?, ?, ?, ?)
			ON CONFLICT(bucket_min, site, kind) DO UPDATE SET
				cnt = cnt + excluded.cnt`
	}
	return `INSERT INTO unmask_cookie_minute (bucket_min, site, kind, cnt)
		VALUES (?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE
			cnt = cnt + VALUES(cnt)`
}

// crawlerUpsertStmt: accumulate total + served with (bucket_min, category) as
// the unique key, into unmask_crawler_minute.
func crawlerUpsertStmt(drv db.Driver) string {
	if drv == db.DriverSQLite {
		return `INSERT INTO unmask_crawler_minute (bucket_min, category, total, served)
			VALUES (?, ?, ?, ?)
			ON CONFLICT(bucket_min, category) DO UPDATE SET
				total = total + excluded.total, served = served + excluded.served`
	}
	return `INSERT INTO unmask_crawler_minute (bucket_min, category, total, served)
		VALUES (?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE
			total = total + VALUES(total), served = served + VALUES(served)`
}


// flushLoop: 60-second ticker.
func (r *Reader) flushLoop() {
	defer close(r.doneB)
	tick := time.NewTicker(60 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-r.stop:
			return
		case <-tick.C:
			r.flushOnce(false)
		}
	}
}

// recvLoop: read from the Unix datagram socket and parse.
// 1 datagram = 1 line (= one line of access_log unmask_minimal).
func (r *Reader) recvLoop() {
	defer close(r.doneA)
	buf := make([]byte, 4*1024) // unmask_minimal is ~80 bytes; 4 KB with plenty of headroom
	for {
		select {
		case <-r.stop:
			return
		default:
		}
		n, _, err := r.conn.ReadFromUnix(buf)
		if err != nil {
			// When SetReadDeadline tripped, exit via the stop signal.
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				select {
				case <-r.stop:
					return
				default:
					continue
				}
			}
			// Any other error is fatal.  Log and exit.
			log.Printf("nginxlog: recv: %v (= aggregation stopped)", err)
			return
		}
		// Strip a trailing '\n'
		line := buf[:n]
		if len(line) > 0 && line[n-1] == '\n' {
			line = line[:n-1]
		}
		r.onLine(string(line))
	}
}

// PendingBuckets: for debug (= count of in-memory buckets not yet flushed).
func (r *Reader) PendingBuckets() int {
	if r == nil {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.buckets)
}
