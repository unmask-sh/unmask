// Package nginxlog: receive nginx's access_log over a Unix datagram
// socket, aggregate it into per-minute buckets, and write into the DB
// (= unmask_cookie_minute table).
//
// On the nginx side (= rendered by admin at /var/lib/unmask/nginx/http.inc):
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
//   - "pow"              : repeater carrying a 4-seg _bv with SHA-256 OK
//   - "challenge_served" : $final_challenge=1 (= the req was rejected)
//   - extensibility: if the plugin returns a new kind ("signature" /
//     "webauthn" / "passkey" etc.), it gets recorded as a new
//     row automatically with no schema change.
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
//
//	nginx's `access_log syslog:` is RFC 3164.  The line head has a
//	<priority> prefix (e.g. "<134>") + optional timestamp/host, so
//	strip them on the parse side.
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
	"github.com/unmask-sh/unmask/admin/internal/events"
	"github.com/unmask-sh/unmask/admin/internal/hll"
	"github.com/unmask-sh/unmask/admin/internal/ipgeo"
	"github.com/unmask-sh/unmask/admin/internal/safe"
)

// Reader: body of the recv goroutine + flush goroutine.  Disabled
// when Loaded()=false.
type Reader struct {
	socketPath string
	d          *db.DB
	conn       *net.UnixConn

	mu                   sync.Mutex
	buckets              map[bucketKey]*bucket
	crawlerBuckets       map[crawlerKey]*crawlerBucket
	crawlerDetailBuckets map[crawlerDetailKey]*crawlerBucket
	countryHourlyBuckets map[countryHourKey]*countryHourBucket
	cookieIPBuckets      map[cookieIPKey]*cookieIPBucket

	// geo: ipgeo reader for per-packet country lookup.  Drives the
	// unmask_traffic_country_hourly aggregation that powers the 30-day chart's
	// country breakdown.  nil-safe (= country bucket flushes with cc="").
	geo *ipgeo.Reader

	// onHoneypot: callback for honeypot-path-trip events (= hp=1 lines).  site
	// (= $host from the access log) lets the callback resolve a per-site custom
	// honeypot URL's action override, matching forward-auth.  Wired up by the ban
	// manager via SetHoneypotCallback.  nil-safe.
	onHoneypot func(ip, ja4, uri, site string)

	// isSearchBot: UA -> true for a rescued search/AI crawler.  Wired by main to
	// classify.IsBot==search_ai.  Native-mode honeypot bans are driven by the
	// access-log hp=1 line, which (unlike forward-auth's veto-pass) has no
	// search-bot exemption -- so without this, a Googlebot that crawls a page
	// containing a honeypot link gets its IP banned = a ranking accident, and an
	// attacker can <img src="victim/<honeypot>"> to ban victims' visitors.
	// nil-safe (no exemption when unset).
	isSearchBot func(ua string) bool

	// httpsRedirectOn: live "is nginx.https_redirect on?" probe.  Wired by main
	// to the settings snapshot.  A JA4-less line means the request carried no TLS
	// -- a handshake always sends a ClientHello, even a resumed session (PSK), so
	// the module fingerprints every TLS connection -- i.e. it arrived on the
	// plaintext port.  With https_redirect on nginx answers those with a 301 and
	// never serves them, yet access_log is still evaluated at request completion
	// and $serve_bot_challenge only tests the URI: a scanner probing a honeypot
	// path over :80 therefore produced an "hp=1 ja4=-" line and earned a
	// scope=ip_only auto-ban covering its WHOLE IP -- broader than, and a
	// duplicate of, the precise (ip, ja4) ban its HTTPS visit already earns.  The
	// request was bounced, not served, so it must not feed the ban list.  With
	// https_redirect off the operator has deliberately kept the plaintext port
	// under inspection, so JA4-less honeypot bans still fire.  nil-safe (no
	// exemption when unset).
	httpsRedirectOn func() bool

	// classifyCrawler: UA -> crawler tag (= one of classify.CrawlerTagOrder
	// or "" when the UA is not a known crawler).  Wired by main via
	// SetCrawlerClassifier(classify.LookupTag).  Set once at startup before
	// traffic; nil-safe (no crawler aggregation when unset).
	classifyCrawler func(ua string) string

	// crawlerNamer: (UA, category) -> individual crawler name within that
	// category (= classify.LookupCrawlerIn -- "Googlebot", "Bingbot", ...).
	// Wired by main via SetCrawlerNamer.  Drives the per-crawler drill-down
	// aggregation (unmask_crawler_detail_hourly) layered on top of the
	// per-category crawler_minute one.  nil-safe (no detail aggregation when
	// unset); takes the category from classifyCrawler so the two always agree.
	crawlerNamer func(ua, tag string) string

	// crawlerObserve: (ip, ua) for every access-log line, so the native rDNS
	// post-pass can verify a crawler-claiming visitor and auto-ban a forgery.
	// Wired by main via SetCrawlerObserver; nil-safe.  The callback itself is
	// cheap for non-crawler UAs (matchClaim short-circuits before any DNS/lock).
	crawlerObserve func(ip, ua string)

	stop  chan struct{}
	doneA chan struct{} // recv goroutine completion signal
	doneB chan struct{} // flush goroutine completion signal
}

// SetHoneypotCallback: register a callback invoked on hp=1 lines (ip, ja4, trip
// URI, and the request's site/$host for per-site action resolution).
func (r *Reader) SetHoneypotCallback(f func(ip, ja4, uri, site string)) {
	if r == nil {
		return
	}
	r.onHoneypot = f
}

// SetSearchBotCheck: register a UA -> is-rescued-search-bot predicate so the
// honeypot ban skips search/AI crawlers (= never ban Googlebot/GPTBot etc.).
func (r *Reader) SetSearchBotCheck(f func(ua string) bool) {
	if r == nil {
		return
	}
	r.isSearchBot = f
}

// SetHTTPSRedirectCheck: register the live nginx.https_redirect probe that
// suppresses a honeypot auto-ban for a request nginx answered with a 301 (see
// the httpsRedirectOn field).
func (r *Reader) SetHTTPSRedirectCheck(f func() bool) {
	if r == nil {
		return
	}
	r.httpsRedirectOn = f
}

// honeypotBanAllowed reports whether an hp=1 line may create an auto-ban.
// Both vetoes exist because the access-log path -- unlike forward-auth's
// veto-pass -- sees only the URI match, never the decision that was taken.
func (r *Reader) honeypotBanAllowed(p parsed) bool {
	if r.isSearchBot != nil && r.isSearchBot(p.ua) {
		return false // rescued search / AI crawler: banning it is a ranking accident
	}
	if p.ja4 == "" && r.httpsRedirectOn != nil && r.httpsRedirectOn() {
		return false // plaintext request we 301-ed: bounced, not served
	}
	return true
}

// SetCrawlerClassifier: register the UA -> crawler-tag function (=
// classify.LookupTag).  Without it, crawler aggregation is skipped.
func (r *Reader) SetCrawlerClassifier(f func(ua string) string) {
	if r == nil {
		return
	}
	r.classifyCrawler = f
}

// SetCrawlerObserver: register the (ip, ua) hook fired for every access-log
// line, used by the native rDNS post-pass to verify a crawler-claiming visitor
// and auto-ban a forgery.  Without it, no post-pass runs.
func (r *Reader) SetCrawlerObserver(f func(ip, ua string)) {
	if r == nil {
		return
	}
	r.crawlerObserve = f
}

// SetCrawlerNamer: register the (UA, category) -> individual-crawler-name
// function (= classify.LookupCrawlerIn).  Layers the per-crawler drill-down
// aggregation on top of the per-category one.  Without it, only the per-
// category crawler_minute aggregation runs (= the drill-down stays empty).
func (r *Reader) SetCrawlerNamer(f func(ua, tag string) string) {
	if r == nil {
		return
	}
	r.crawlerNamer = f
}

// SetIPGeo: register the ipgeo reader for per-packet country lookup.  Without
// it (or when the mmdb is not loaded), the country-hourly aggregation rolls
// every request into country="" — the read side renders this as "Unknown".
func (r *Reader) SetIPGeo(g *ipgeo.Reader) {
	if r == nil {
		return
	}
	r.geo = g
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

// crawlerDetailKey: per-hour, per-(category, individual-crawler) aggregation
// for the crawler-traffic drill-down (= unmask_crawler_detail_hourly).  Hourly
// (not per-minute like crawlerKey) to keep the row count bounded; the popover
// only shows window totals.  Reuses crawlerBucket (total / served).
type crawlerDetailKey struct {
	hour     int64
	category string
	crawler  string
}

// countryHourKey / countryHourBucket: per-hour, per-(site, country) request
// aggregation for the 30-day chart's country breakdown.  hour is the unix
// epoch hour (= time.Unix()/3600), matching the schema of
// unmask_traffic_country_hourly.
type countryHourKey struct {
	hour    int64
	site    string
	country string // "" if geo unavailable or IP unmappable
}

type countryHourBucket struct {
	total int
	kinds map[string]int
}

// cookieIPKey / cookieIPBucket: per-minute, per-(site, ip, kind) aggregation of
// cookie reuse.  A bucket is created ONLY for a request that carried a valid
// _bv cookie -- i.e. the actual reuse / scrape volume of a single cookie, which
// the challenge-event stream (unmask_event) never observes because no challenge
// fires when a valid cookie is presented.  kind separates the two ways that
// cookie was earned ("captcha" / "pow"); both matter, for opposite reasons:
// holding a CAPTCHA cookie is already a suspicion signal, while a PoW cookie is
// what every ordinary visitor holds -- so a PoW row only becomes interesting at
// high volume on a single fingerprint (= one solve being ridden).  Drives the
// cookie-reuse dashboard card via unmask_cookie_ip_minute.  ip is held as its
// raw string here (= map key) and packed to the canonical bytes form at flush
// time.
type cookieIPKey struct {
	minute int64
	site   string
	ip     string
	kind   string
}

type cookieIPBucket struct {
	cnt      int
	ja4      string // latest JA4 fingerprint seen for this IP in the bucket
	ua       string // latest User-Agent seen for this IP in the bucket
	lastSeen int64  // latest request time (unix sec, UTC)
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
	// Per-minute HyperLogLog sketches of client IPs, persisted to
	// unmask_traffic_hll so the overview can show non-human traffic by unique
	// client (not request volume).  ipAll = every request; ipChal = fc=1
	// (challenged); ipPass = carried a pow/captcha _bv cookie (passed before).
	ipAll  hll.Sketch
	ipChal hll.Sketch
	ipPass hll.Sketch
	// ipBot: clients a challenge was NOT fired for, whose UA is a crawler on
	// the curated list -- i.e. non-human traffic this install deliberately
	// lets through (verified search / AI crawlers, monitoring).  Kept apart
	// from ipChal on purpose: "bot we passed" and "client that failed a
	// challenge" are both non-human, and an operator wants the split, not the
	// sum.  Decided per line here rather than by set algebra on read, because
	// HLL cannot express intersection.
	ipBot hll.Sketch
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
		socketPath:           socketPath,
		d:                    d,
		buckets:              map[bucketKey]*bucket{},
		crawlerBuckets:       map[crawlerKey]*crawlerBucket{},
		crawlerDetailBuckets: map[crawlerDetailKey]*crawlerBucket{},
		countryHourlyBuckets: map[countryHourKey]*countryHourBucket{},
		cookieIPBuckets:      map[cookieIPKey]*cookieIPBucket{},
		stop:                 make(chan struct{}),
		doneA:                make(chan struct{}),
		doneB:                make(chan struct{}),
	}
	if d == nil {
		close(r.doneA)
		close(r.doneB)
		return r
	}
	// Even when socket path is unset (= forward-auth mode etc.), run
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
//
// ja4 is matched as \S* too: $effective_ja4 is "-" when the handshake yielded
// no fingerprint (TLS session resumption etc.).  An earlier [A-Za-z0-9_]+
// charset refused that "-", and because the groups are a sequential chain the
// mismatch also un-anchored every later field — hpuri and ua silently parsed
// empty on exactly those lines, so a resumption-visit honeypot ban lost its
// trip URL (reason showed a bare "honeypot") and its UA.  parse() normalizes
// the "-" placeholder to "" (= same meaning: no fingerprint).
var lineRE = regexp.MustCompile(
	`([0-9]+\.[0-9]+) site=(\S*) kind=([a-z0-9_-]*)` +
		`(?: fc=([01]))?(?: hp=([01]))?(?: ip=([0-9a-fA-F:.]+))?(?: ja4=(\S*))?(?: hpuri=(\S*))?(?: ua=(.*))?`)

// parsed: struct holding the regex match result.
type parsed struct {
	msec  float64
	site  string
	kind  string // "" / "captcha" / "pow" / future additions
	fc    bool
	hp    bool
	ip    string
	ja4   string
	hpuri string // honeypot trip URI ($request_uri); only set on hp=1 lines
	ua    string
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
	if len(s) > 64 {
		// Match the DB site column width.  A longer $host (or a spoofed one)
		// would overflow it and, under MariaDB STRICT_TRANS_TABLES, abort the
		// whole batch upsert -- losing every row in that flush, not just this one.
		s = s[:64]
	}
	ja4 := m[7]
	if ja4 == "-" {
		// nginx renders an unavailable $effective_ja4 as "-"; internally the
		// empty string is the "no fingerprint" value (a ban keyed on it means
		// "any JA4").  Normalize so "-" never becomes a ban key or a stat bucket.
		ja4 = ""
	}
	return parsed{
		msec: v, site: s,
		kind:  m[3],
		fc:    m[4] == "1",
		hp:    m[5] == "1",
		ip:    m[6],
		ja4:   ja4,
		hpuri: m[8],
		ua:    m[9],
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
	// Honeypot ban -- subject to the vetoes in honeypotBanAllowed (rescued
	// search/AI crawler; a plaintext request we answered with a 301).
	if p.hp && r.onHoneypot != nil && p.ip != "" && r.honeypotBanAllowed(p) {
		r.onHoneypot(p.ip, p.ja4, p.hpuri, p.site)
	}
	kind := p.kind
	if kind == "" && p.fc {
		kind = "challenge_served"
	}
	r.Bump(p.site, kind)
	// Fold the client IP into the per-minute HLL sketches (= unique-client
	// stats).  Uses the raw bv_kind (p.kind), not the "challenge_served"
	// alias, so ipPass only counts a genuine pow/captcha cookie.
	r.bumpTrafficHLL(p.site, p.ip, p.fc, p.kind, p.ua)
	// Country-hourly aggregation for the 30-day chart's country breakdown.
	// The kind passed here matches the unmask_cookie_minute kind: "" / pow /
	// captcha / challenge_served — keep the catalogue aligned so the two
	// tables can be compared 1:1.
	r.bumpCountryHourly(p.site, p.ip, kind)
	// Per-IP cookie-reuse ranking: only lines carrying a valid _bv cookie
	// (kind="captcha" / "pow") are recorded; bumpCookieIP no-ops for every other
	// kind, so this is at most two string compares on the common path.  Uses the
	// raw p.kind (not the challenge_served alias) so only genuine reuse is
	// counted, mirroring bumpTrafficHLL's pass detection.
	r.bumpCookieIP(p.site, p.ip, p.ja4, p.ua, p.kind)
	// Crawler funnel: every request carries a UA.  fc=1 (= a challenge was the
	// final action) counts as "served"; otherwise the request passed straight
	// through (rescued / valid cookie).
	r.bumpCrawler(p.ua, p.fc)
	// Native rDNS post-pass: verify a crawler-claiming visitor and auto-ban a
	// forgery.  Cheap for the common (non-crawler) UA -- the callback short-
	// circuits before any DNS or lock.
	if r.crawlerObserve != nil {
		r.crawlerObserve(p.ip, p.ua)
	}
}

// Bump: increment the minute bucket by 1 from outside
// (= forward-auth mode in /api/check).  site == "" is treated as
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

// bumpTrafficHLL: fold one request's client IP into the per-minute HLL
// sketches.  ip="" (= the log line carried no ip= field) is a no-op.
//
//	ipAll  <- every request
//	ipChal <- fc == 1 (= a challenge fired)
//	ipPass <- bv_kind is pow / captcha (= the client holds a pass cookie)
//	ipBot  <- fc == 0 AND the UA is a listed crawler (= deliberately passed)
//
// nil-safe (= no-op when the Reader isn't running).
func (r *Reader) bumpTrafficHLL(site, ip string, fc bool, bvKind, ua string) {
	if r == nil || r.d == nil || ip == "" {
		return
	}
	ipb := []byte(ip)
	key := bucketKey{minute: time.Now().Unix() / 60, site: site}
	r.mu.Lock()
	b, ok := r.buckets[key]
	if !ok {
		b = &bucket{kinds: map[string]int{}}
		r.buckets[key] = b
	}
	b.ipAll.Add(ipb)
	if fc {
		b.ipChal.Add(ipb)
	}
	if bvKind == "pow" || bvKind == "captcha" {
		b.ipPass.Add(ipb)
	}
	// A listed crawler that was not challenged: the pass was the config's
	// decision, so it belongs on the benign side of the non-human split.  One
	// that WAS challenged falls through to ipChal like any other client --
	// which is right: if an operator challenges the AI-crawler group, GPTBot
	// is not being let through and should not be counted as if it were.
	if !fc && r.classifyCrawler != nil && ua != "" {
		if tag := r.classifyCrawler(ua); tag != "" {
			b.ipBot.Add(ipb)
		}
	}
	r.mu.Unlock()
}

// bumpCountryHourly: resolve client country via ipgeo and increment the
// per-(hour, site, country) request bucket.  kind matches the
// unmask_cookie_minute catalogue ("" / pow / captcha / challenge_served).
// "" only bumps total (= the "no signal" share is back-computed on read as
// total - SUM(kinds), same as cookie_minute).
//
// nil-safe (= no-op when the Reader isn't running).  geo == nil OR
// !geo.Loaded() folds every request into country="" (rendered as "Unknown"
// on read).  ip == "" (= log line carried no ip= field) also produces "".
func (r *Reader) bumpCountryHourly(site, ip, kind string) {
	if r == nil || r.d == nil {
		return
	}
	cc := ""
	if r.geo != nil && r.geo.Loaded() && ip != "" {
		cc = r.geo.Lookup(ip)
	}
	key := countryHourKey{hour: time.Now().Unix() / 3600, site: site, country: cc}
	r.mu.Lock()
	b, ok := r.countryHourlyBuckets[key]
	if !ok {
		b = &countryHourBucket{kinds: map[string]int{}}
		r.countryHourlyBuckets[key] = b
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
	now := time.Now().Unix()
	key := crawlerKey{minute: now / 60, category: cat}
	// Resolve the individual crawler within the category (= the drill-down
	// dimension) outside the lock -- regex matching must not hold r.mu.  Empty
	// when the namer is unwired (= only per-category aggregation runs).
	var dkey crawlerDetailKey
	haveDetail := false
	if r.crawlerNamer != nil {
		if name := r.crawlerNamer(ua, cat); name != "" {
			dkey = crawlerDetailKey{hour: now / 3600, category: cat, crawler: name}
			haveDetail = true
		}
	}
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
	if haveDetail {
		if r.crawlerDetailBuckets == nil { // defensive: Start() inits it; direct-construct callers may not
			r.crawlerDetailBuckets = map[crawlerDetailKey]*crawlerBucket{}
		}
		db := r.crawlerDetailBuckets[dkey]
		if db == nil {
			db = &crawlerBucket{}
			r.crawlerDetailBuckets[dkey] = db
		}
		db.total++
		if served {
			db.served++
		}
	}
	r.mu.Unlock()
}

// BumpCrawler: exported entry point for forward-auth mode (= /api/check has
// the UA but emits no access-log line of its own).  nil-safe.
func (r *Reader) BumpCrawler(ua string, served bool) {
	if r == nil {
		return
	}
	r.bumpCrawler(ua, served)
}

// BumpTrafficHLL / BumpCountry: exported entry points for forward-auth mode.
// /api/check has the IP (and the Reader's geo is wired in both modes), but emits
// no access-log line, so without these the unique-IP (DailyUniqueIPs) and
// per-country (DailyPassByCountry) 30-day charts stay flat-zero in forward-auth.
// nil-safe.
func (r *Reader) BumpTrafficHLL(site, ip string, fc bool, bvKind, ua string) {
	if r == nil {
		return
	}
	// ua feeds the benign-bot sketch; forward-auth has it on the request, so
	// the split is populated identically on both wires.  Callers with no UA
	// pass "" and simply contribute nothing to that sketch.
	r.bumpTrafficHLL(site, ip, fc, bvKind, ua)
}

func (r *Reader) BumpCountry(site, ip, kind string) {
	if r == nil {
		return
	}
	r.bumpCountryHourly(site, ip, kind)
}

// cookieIPUAMax bounds the UA stored in unmask_cookie_ip_minute to the column
// width (= unmask_event.user_agent VARCHAR(255)).  A longer UA under MariaDB
// STRICT_TRANS_TABLES would abort the whole flush batch, so clamp it here --
// mirroring parse()'s site truncation.
const cookieIPUAMax = 255

// cookieIPKinds: the _bv kinds whose reuse is ranked per IP.  Deliberately not
// every value $bv_kind can take: "challenge_served" is a challenge being shown
// (which does write an unmask_event row, so hunt already sees it) and "" is no
// cookie at all -- neither is a cookie being reused.
func cookieIPKinds(kind string) bool { return kind == "captcha" || kind == "pow" }

// bumpCookieIP: record one cookie-reuse request into the per-(minute, site, ip,
// kind) bucket.  Only a presented valid _bv cookie counts ("captcha" / "pow");
// every other kind is a no-op, so the hot path adds at most two string compares
// per log line.  ja4 / ua keep the latest value seen for the IP within the
// minute bucket.
//
// This runs on the log-reader goroutine, never on a request path: nginx already
// emits ip= and kind= on every line (log_format unmask_minimal) and the DB is
// touched once a minute by flushOnce, so widening the filter costs a map lookup
// per matching line and nothing in nginx.
//
// nil-safe (= no-op when the Reader isn't running).  ip="" (= log line carried
// no ip= field) is a no-op since there is no client to rank.
func (r *Reader) bumpCookieIP(site, ip, ja4, ua, kind string) {
	if r == nil || r.d == nil || !cookieIPKinds(kind) || ip == "" {
		return
	}
	if len(ua) > cookieIPUAMax {
		ua = ua[:cookieIPUAMax]
	}
	now := time.Now().Unix()
	key := cookieIPKey{minute: now / 60, site: site, ip: ip, kind: kind}
	r.mu.Lock()
	b, ok := r.cookieIPBuckets[key]
	if !ok {
		b = &cookieIPBucket{}
		r.cookieIPBuckets[key] = b
	}
	b.cnt++
	b.ja4 = ja4
	b.ua = ua
	b.lastSeen = now
	r.mu.Unlock()
}

// BumpCookieIP: exported entry point for forward-auth mode (= /api/check sees
// the reuse request but emits no access-log line of its own, so without this the
// cookie-reuse card stays empty in forward-auth).  nil-safe.
func (r *Reader) BumpCookieIP(site, ip, ja4, ua, kind string) {
	if r == nil {
		return
	}
	r.bumpCookieIP(site, ip, ja4, ua, kind)
}

// flushOnce: UPSERT buckets "older than the current minute" into the DB.
// final=true flushes everything including the current minute (= for shutdown).
// Cookie-minute, crawler-minute and country-hourly buckets all flush in the
// same transaction so a partial commit can never leave them inconsistent.
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
	type crawlerDetailEntry struct {
		key crawlerDetailKey
		b   crawlerBucket
	}
	type countryEntry struct {
		key countryHourKey
		b   countryHourBucket
	}
	type cookieIPEntry struct {
		key cookieIPKey
		b   cookieIPBucket
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
			ready = append(ready, entry{k, bucket{
				total: b.total, kinds: copyKinds,
				ipAll: b.ipAll, ipChal: b.ipChal, ipPass: b.ipPass, ipBot: b.ipBot,
			}})
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
	// crawler-detail buckets flush every tick (including the current hour),
	// same as country-hourly: the UPSERT accumulates, so re-flushing the same
	// (hour, category, crawler) keeps adding the new delta and the popover is
	// fresh within ~60s instead of waiting for an hour boundary.
	crawlerDetailReady := make([]crawlerDetailEntry, 0, len(r.crawlerDetailBuckets))
	for k, b := range r.crawlerDetailBuckets {
		crawlerDetailReady = append(crawlerDetailReady, crawlerDetailEntry{k, *b})
		delete(r.crawlerDetailBuckets, k)
	}
	countryReady := make([]countryEntry, 0, len(r.countryHourlyBuckets))
	for k, b := range r.countryHourlyBuckets {
		// country buckets flush every tick (including the current hour) so the
		// 30-day chart reflects activity within ~60s instead of needing an
		// hour boundary.  The UPSERT accumulates, so re-flushing the same
		// (hour, site, country, kind) keeps adding the new delta safely.
		copyKinds := make(map[string]int, len(b.kinds))
		for kk, vv := range b.kinds {
			copyKinds[kk] = vv
		}
		countryReady = append(countryReady, countryEntry{k, countryHourBucket{total: b.total, kinds: copyKinds}})
		delete(r.countryHourlyBuckets, k)
		_ = final
	}
	// cookie-ip buckets flush once the minute closes (like cookie_minute /
	// crawler_minute) so the current minute keeps accumulating until it is whole.
	cookieIPReady := make([]cookieIPEntry, 0, len(r.cookieIPBuckets))
	for k, b := range r.cookieIPBuckets {
		if final || k.minute < nowMin {
			cookieIPReady = append(cookieIPReady, cookieIPEntry{k, *b})
			delete(r.cookieIPBuckets, k)
		}
	}
	r.mu.Unlock()

	if len(ready) == 0 && len(crawlerReady) == 0 && len(crawlerDetailReady) == 0 && len(countryReady) == 0 && len(cookieIPReady) == 0 {
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
				bb := bucket{
					total: e.b.total, kinds: map[string]int{},
					ipAll: e.b.ipAll, ipChal: e.b.ipChal, ipPass: e.b.ipPass, ipBot: e.b.ipBot,
				}
				for k, v := range e.b.kinds {
					bb.kinds[k] = v
				}
				r.buckets[e.key] = &bb
			} else {
				b.total += e.b.total
				for k, v := range e.b.kinds {
					b.kinds[k] += v
				}
				b.ipAll.Merge(&e.b.ipAll)
				b.ipChal.Merge(&e.b.ipChal)
				b.ipPass.Merge(&e.b.ipPass)
				b.ipBot.Merge(&e.b.ipBot)
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
		for _, e := range crawlerDetailReady {
			if b, ok := r.crawlerDetailBuckets[e.key]; ok {
				b.total += e.b.total
				b.served += e.b.served
			} else {
				bb := e.b
				r.crawlerDetailBuckets[e.key] = &bb
			}
		}
		for _, e := range countryReady {
			b, ok := r.countryHourlyBuckets[e.key]
			if !ok {
				bb := countryHourBucket{total: e.b.total, kinds: map[string]int{}}
				for k, v := range e.b.kinds {
					bb.kinds[k] = v
				}
				r.countryHourlyBuckets[e.key] = &bb
			} else {
				b.total += e.b.total
				for k, v := range e.b.kinds {
					b.kinds[k] += v
				}
			}
		}
		for _, e := range cookieIPReady {
			if b, ok := r.cookieIPBuckets[e.key]; ok {
				b.cnt += e.b.cnt
				// keep the most recent ja4 / ua for the IP-minute
				if e.b.lastSeen >= b.lastSeen {
					b.lastSeen = e.b.lastSeen
					b.ja4 = e.b.ja4
					b.ua = e.b.ua
				}
			} else {
				bb := e.b
				r.cookieIPBuckets[e.key] = &bb
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
		// HLL sketches: read-merge-write so a restart / late datagram for an
		// already-flushed minute unions with the stored sketch instead of
		// overwriting it.  Empty sketches are skipped (no row).
		for _, sk := range []struct {
			kind string
			s    hll.Sketch
		}{{"ip", e.b.ipAll}, {"ipc", e.b.ipChal}, {"ipp", e.b.ipPass}, {"ipb", e.b.ipBot}} {
			if sk.s.Empty() {
				continue
			}
			var prev []byte
			row := tx.QueryRowContext(ctx,
				`SELECT sketch FROM unmask_traffic_hll WHERE bucket_min = ? AND site = ? AND kind = ?`,
				e.key.minute, e.key.site, sk.kind)
			if err := row.Scan(&prev); err == nil && len(prev) > 0 {
				sk.s.Merge(hll.Load(prev))
			}
			if _, err := tx.ExecContext(ctx, trafficHLLUpsert(r.d.Driver),
				e.key.minute, e.key.site, sk.kind, sk.s.Bytes()); err != nil {
				log.Printf("nginxlog: flush exec(hll=%s): %v", sk.kind, err)
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
	stmtCrawlerDetail := crawlerDetailUpsertStmt(r.d.Driver)
	for _, e := range crawlerDetailReady {
		if _, err := tx.ExecContext(ctx, stmtCrawlerDetail,
			e.key.hour, e.key.category, e.key.crawler, e.b.total, e.b.served); err != nil {
			log.Printf("nginxlog: flush exec(crawler-detail %s/%s): %v", e.key.category, e.key.crawler, err)
			return
		}
	}
	stmtCountry := countryHourlyUpsertStmt(r.d.Driver)
	for _, e := range countryReady {
		// 1 row for kind="total" + 1 row per non-empty kind, mirroring the
		// cookie_minute upsert so the two tables read 1:1.
		if _, err := tx.ExecContext(ctx, stmtCountry,
			e.key.hour, e.key.site, e.key.country, "total", e.b.total); err != nil {
			log.Printf("nginxlog: flush exec(country total): %v", err)
			return
		}
		for k, v := range e.b.kinds {
			if v == 0 || k == "" {
				continue
			}
			if _, err := tx.ExecContext(ctx, stmtCountry,
				e.key.hour, e.key.site, e.key.country, k, v); err != nil {
				log.Printf("nginxlog: flush exec(country kind=%s): %v", k, err)
				return
			}
		}
	}
	stmtCookieIP := cookieIPUpsertStmt(r.d.Driver)
	for _, e := range cookieIPReady {
		// Pack the IP to the canonical bytes form (= unmask_event.ip_address: 4B
		// v4 / 16B v6) so the read side's ipFromBytes decodes it.  An unparseable
		// IP is skipped rather than stored as garbage.
		ipb := events.PackIP(e.key.ip)
		if ipb == nil {
			continue
		}
		lastSeen := time.Unix(e.b.lastSeen, 0).UTC().Format("2006-01-02 15:04:05.000")
		if _, err := tx.ExecContext(ctx, stmtCookieIP,
			e.key.minute, e.key.site, ipb, e.key.kind, e.b.ja4, e.b.ua, e.b.cnt, lastSeen); err != nil {
			log.Printf("nginxlog: flush exec(cookie-ip): %v", err)
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

// crawlerDetailUpsertStmt: accumulate total + served with (bucket_hour,
// category, crawler) as the unique key, into unmask_crawler_detail_hourly.
// The per-crawler drill-down layered on crawlerUpsertStmt's per-category one.
func crawlerDetailUpsertStmt(drv db.Driver) string {
	if drv == db.DriverSQLite {
		return `INSERT INTO unmask_crawler_detail_hourly (bucket_hour, category, crawler, total, served)
			VALUES (?, ?, ?, ?, ?)
			ON CONFLICT(bucket_hour, category, crawler) DO UPDATE SET
				total = total + excluded.total, served = served + excluded.served`
	}
	return `INSERT INTO unmask_crawler_detail_hourly (bucket_hour, category, crawler, total, served)
		VALUES (?, ?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE
			total = total + VALUES(total), served = served + VALUES(served)`
}

// countryHourlyUpsertStmt: accumulate cnt with (bucket_hour, site, country,
// kind) as the unique key, into unmask_traffic_country_hourly.  Mirrors the
// cookie_minute upsert pattern.
func countryHourlyUpsertStmt(drv db.Driver) string {
	if drv == db.DriverSQLite {
		return `INSERT INTO unmask_traffic_country_hourly (bucket_hour, site, country, kind, cnt)
			VALUES (?, ?, ?, ?, ?)
			ON CONFLICT(bucket_hour, site, country, kind) DO UPDATE SET
				cnt = cnt + excluded.cnt`
	}
	return `INSERT INTO unmask_traffic_country_hourly (bucket_hour, site, country, kind, cnt)
		VALUES (?, ?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE
			cnt = cnt + VALUES(cnt)`
}

// cookieIPUpsertStmt: accumulate cnt with (bucket_min, site, ip, kind) as the
// unique key, into unmask_cookie_ip_minute.  ja4 / ua / last_seen take the
// latest write (= the most recent flush for that IP-minute wins), giving the
// read side a representative fingerprint + last-activity timestamp per IP.
func cookieIPUpsertStmt(drv db.Driver) string {
	if drv == db.DriverSQLite {
		return `INSERT INTO unmask_cookie_ip_minute (bucket_min, site, ip, kind, ja4, ua, cnt, last_seen)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(bucket_min, site, ip, kind) DO UPDATE SET
				cnt = cnt + excluded.cnt,
				ja4 = excluded.ja4, ua = excluded.ua, last_seen = excluded.last_seen`
	}
	return `INSERT INTO unmask_cookie_ip_minute (bucket_min, site, ip, kind, ja4, ua, cnt, last_seen)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE
			cnt = cnt + VALUES(cnt),
			ja4 = VALUES(ja4), ua = VALUES(ua), last_seen = VALUES(last_seen)`
}

// trafficHLLUpsert: write an HLL sketch for (bucket_min, site, kind).  The
// caller has already merged any previously-stored sketch in, so a conflict
// just overwrites with the merged result.
func trafficHLLUpsert(drv db.Driver) string {
	if drv == db.DriverSQLite {
		return `INSERT INTO unmask_traffic_hll (bucket_min, site, kind, sketch)
			VALUES (?, ?, ?, ?)
			ON CONFLICT(bucket_min, site, kind) DO UPDATE SET sketch = excluded.sketch`
	}
	return `INSERT INTO unmask_traffic_hll (bucket_min, site, kind, sketch)
		VALUES (?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE sketch = VALUES(sketch)`
}

// flushLoop: 60-second ticker.
func (r *Reader) flushLoop() {
	defer close(r.doneB)
	defer safe.Recover("nginxlog-flush") // a panic here must not crash the daemon
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
		// Per-line recovery: a malformed/attacker-influenced log line that
		// panics onLine must not kill the whole reader (and the daemon).
		ls := string(line)
		safe.Run("nginxlog-line", func() { r.onLine(ls) })
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
