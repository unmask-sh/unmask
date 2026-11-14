// Package nginxlog: receive nginx's access_log over a Unix datagram
// socket, aggregate it into per-minute buckets, and write into the DB
// (= unmask_cookie_minute table).
//
// On the nginx side (= rendered by admin at /var/lib/unmask/nginx/http.inc):
//
//	log_format unmask_minimal '$msec site=$host kind=$bv_kind fc=$unmask_fc_log hp=$serve_bot_challenge ip=$remote_addr ja4=$effective_ja4 ua=$http_user_agent';
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
//   - "challenge_served" : fc=1 (= the req was rejected).  fc= is a gate's
//     decision, not the judgement alone: http.inc logs $final_challenge only
//     for a request protect.inc (or server.inc's ban / deny rewrite) saw, so
//     a location without protect.inc -- which serves its content whatever the
//     judgement says -- logs fc=0 and bp=1, passed without judgement.
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
//   - History survives admin restarts on the DB side.  The socket itself
//     survives them too where the unit allows it (handover.go): nginx's
//     workers stay connected and what they log during the restart waits
//     in the socket.  Elsewhere each worker loses its first line after a
//     restart, and every line logged while the daemon is down.
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
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/events"
	"github.com/unmask-sh/unmask/admin/internal/hll"
	"github.com/unmask-sh/unmask/admin/internal/ipgeo"
	"github.com/unmask-sh/unmask/admin/internal/live"
	"github.com/unmask-sh/unmask/admin/internal/safe"
	"github.com/unmask-sh/unmask/admin/internal/selabel"
	"github.com/unmask-sh/unmask/admin/internal/sockperm"
)

// Reader: body of the recv goroutine + flush goroutine.  Disabled
// when Loaded()=false.
type Reader struct {
	socketPath string
	d          *db.DB
	conn       *net.UnixConn
	// stored: the socket is in the service manager's store (handover.go)
	// and outlives this process, so Close leaves its file in place.
	stored bool

	mu                   sync.Mutex
	buckets              map[bucketKey]*bucket
	crawlerBuckets       map[crawlerKey]*crawlerBucket
	crawlerDetailBuckets map[crawlerDetailKey]*crawlerBucket
	crawlerSiteBuckets   map[crawlerSiteKey]*crawlerSiteBucket
	namedBuckets         map[namedKey]*namedBucket
	countryHourlyBuckets map[countryHourKey]*countryHourBucket
	cookieIPBuckets      map[cookieIPKey]*cookieIPBucket
	// passBuckets / passHours / passIDs: the per-address, per-day count of
	// the passes presented (pass_ip.go); matchPass names the pass a line
	// rode on, nil until set.
	passBuckets map[passKey]*passBucket
	passHours   map[passHourKey]int
	passIDs     int
	matchPass   func(value, ip, host string) string
	// observePass hears of a pass an address presents for the first time in
	// a day (SetPassObserver); nil until set.
	observePass func(ip, ja4, site, kind, id string)

	// geo: ipgeo reader for per-packet country lookup.  Drives the
	// unmask_traffic_country_hourly aggregation that powers the 30-day chart's
	// country breakdown.  nil-safe (= country bucket flushes with cc="").
	geo *ipgeo.Reader
	// live, when set, sees every request as it is read -- the dashboard's
	// "right now" strip, which the minute buckets above are too coarse for.
	live *live.Counter
	// ruleHit counts the custom rule a line names (cr=); nil until set.
	ruleHit func(id string)
	// renderSeen hears the render id every line carries (rv=, "" when the
	// line has none); nil until set.  Set before Receive, read unlocked.
	renderSeen func(id string)
	// beforeFlush runs at the start of every flush; nil but in a test
	// (the flush loop's recovery is tested through it).
	beforeFlush func()
	// moduleSeen hears the module id every line carries (mo=: the hash of
	// the module file nginx loaded, "" when the line has none); nil until
	// set.  Set before Receive, read unlocked.
	moduleSeen func(id string)
	// isDenied answers whether a client is banned with an action that refuses
	// it outright.  The access-log line does not say that nginx denied the
	// request, and the line of a refused client can still carry a pass
	// cookie: the live strip must not count it as passed.
	isDenied func(ip, ja4 string) bool

	// onHoneypot: callback for honeypot-path-trip events (= hp=1 lines).  site
	// (= $host from the access log) lets the callback resolve a per-site custom
	// honeypot URL's action override, matching forward-auth; scheme (http /
	// https, "" on a line from a configuration that predates the field) lets
	// the ban's reason name the URL in full.  Wired up by the ban manager via
	// SetHoneypotCallback.  nil-safe.
	onHoneypot func(ip, ja4, uri, site, scheme string)

	// isSearchBot: UA -> true for a rescued search/AI crawler.  Wired by main to
	// classify.IsBot==search_ai.  Native-mode honeypot bans are driven by the
	// access-log hp=1 line, which (unlike forward-auth's veto-pass) has no
	// search-bot exemption -- so without this, a Googlebot that crawls a page
	// containing a honeypot link gets its IP banned = a ranking accident, and an
	// attacker can <img src="victim/<honeypot>"> to ban victims' visitors.
	// nil-safe (no exemption when unset).
	isSearchBot func(ua string) bool
	// rangeVerifiedUA: UA -> true when the crawler it names is one the
	// configuration verifies against its vendor's published ranges.  For
	// such a name the search-bot exemption above holds only when the
	// request was in fact passed on that range (bp=1): the name alone is
	// what a scanner wears.  nil-safe (every rescued name stays exempt).
	rangeVerifiedUA func(ua string) bool

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

	// crawlerInRange: (crawler name, client address) -> true when the address
	// is inside the ranges that crawler's vendor publishes.  Wired by main via
	// SetCrawlerRangeCheck (nginxconf.CrawlerVendorRange); the per-site rows
	// count those requests as verified, which is how they tell the vendor's
	// crawler from a client wearing its name.  nil-safe (nothing counts as
	// verified when unset).
	crawlerInRange func(name, ip string) bool

	// crawlerObserve: (ip, ua) for every access-log line, so the native rDNS
	// post-pass can verify a crawler-claiming visitor and auto-ban a forgery.
	// Wired by main via SetCrawlerObserver; nil-safe.  The callback itself is
	// cheap for non-crawler UAs (matchClaim short-circuits before any DNS/lock).
	crawlerObserve func(ip, ua string)

	stop chan struct{}
	// ready: closed by Receive, once every callback is registered.  The
	// receive loop reads nothing before that -- a socket kept over a restart
	// comes with the lines logged meanwhile, and they are to be classified,
	// attributed and checked for honeypot hits like any other.
	ready     chan struct{}
	readyOnce sync.Once
	doneA     chan struct{} // recv goroutine completion signal
	doneB     chan struct{} // flush goroutine completion signal
	doneC     chan struct{} // work goroutine completion signal

	// lines carries what the receive goroutine read to the work goroutine
	// that handles it (recvLoop / workLoop).  The receiver closes it when
	// it ends; the worker handles what is left and ends after it.
	lines chan string
	// droppedLines counts the lines the receiver let go because the queue
	// was full (DroppedLines).  dropSaid is when the log last said so; the
	// receive goroutine's own.
	droppedLines atomic.Uint64
	dropSaid     time.Time
	// truncatedLines counts the datagrams that arrived longer than the
	// receive buffer and were dropped unread (TruncatedLines); truncSaid is
	// when the log last said so.  Only recvLoop touches truncSaid.
	truncatedLines atomic.Uint64
	truncSaid      time.Time

	// siteKnown answers whether a Host is a site to count on its own
	// (SetSiteCheck); nil accepts every Host.  Set before Receive, read
	// unlocked.
	siteKnown func(site string) bool
	// sitesSeen is the set of distinct sites counted in the minute
	// sitesMinute, for the cap in aggSite.  Under mu.
	sitesSeen   map[string]struct{}
	sitesMinute int64
}

// recvQueueSize is how many lines may wait between the receive goroutine
// and the work goroutine.  A line is handled in microseconds; a honeypot
// trip, which writes a ban and the ban file, in milliseconds -- the queue
// covers a burst of those.  A variable so a test can make it small.
var recvQueueSize = 8192

// OtherSite is the site the minute buckets file a request under when its
// Host is not one to count on its own: past siteCapPerMinute distinct hosts
// in a minute, or, with the site list in "defined" mode, a host that is
// not on it.  A catch-all vhost takes any Host a client sends, and every
// distinct one used to cost its own buckets (three 1 KiB sketches a minute)
// and its own rows in every per-site table, for as long as the client
// cared to vary it.  The parentheses keep it apart from any hostname.  No
// page shows it: the site lists come from the event table, and these
// tables are read by a picked site or as a whole.  The one place it is
// written out is the crawler CSV, which lists every site the per-site
// crawler rows are filed under, this one among them.
const OtherSite = "(other)"

// siteCapPerMinute bounds the distinct sites the minute buckets hold.
const siteCapPerMinute = 256

// SetHoneypotCallback: register a callback invoked on hp=1 lines (ip, ja4, trip
// URI, the request's site/$host for per-site action resolution, and its
// scheme for the reason's URL).
func (r *Reader) SetHoneypotCallback(f func(ip, ja4, uri, site, scheme string)) {
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

// SetRangeVerifiedCheck registers the UA -> "this crawler's vendor publishes
// ranges" function (see rangeVerifiedUA).
func (r *Reader) SetRangeVerifiedCheck(f func(ua string) bool) {
	if r == nil {
		return
	}
	r.rangeVerifiedUA = f
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
		// A rescued search / AI crawler: banning it is a ranking accident.
		// Except a name the configuration can check against its vendor's
		// ranges that was NOT passed on that range: that is a scanner
		// wearing "Googlebot", and the name used to buy it immunity from
		// the trap it had just walked into.
		if r.rangeVerifiedUA == nil || !r.rangeVerifiedUA(p.ua) || p.bypassed {
			return false
		}
	}
	if r.httpsRedirectOn != nil && r.httpsRedirectOn() && p.plaintext() {
		return false // plaintext request we 301-ed: bounced, not served
	}
	return TripBannable(p.sfs, p.sfd, p.rh)
}

// TripBannable reports whether a honeypot trip may ban the client that made
// it, from the request's Sec-Fetch-Site, Sec-Fetch-Dest and the host its
// Referer names.  The trip itself is always answered as the trap says; the
// question here is only whether the (address, fingerprint) behind it gets
// the day-long ban.
//
// A trap URL is a string anyone can put on a page: an <img src> on a third
// party's site, a link in a forum post on this one.  The browser that loads
// such a page then trips the trap on its owner's behalf, and until now that
// banned the owner -- a cross-site denial of service against any visitor
// the attacker could get to view a page, with no way out, since a ban
// precedes every cookie.  So a trip that a page could have caused -- a
// subresource fetch, or a navigation that arrived from somewhere (any
// Sec-Fetch-Site but "none", or a Referer at all) -- bans nobody.  A scanner
// types the URL or sends none of these headers: it is banned as before.  A
// scanner that fakes a Referer escapes the ban and still meets the trap's
// answer on every trip; that trade is the right way round.
func TripBannable(sfs, sfd, refHost string) bool {
	switch sfs {
	case "cross-site", "same-site", "same-origin":
		return false
	}
	switch sfd {
	case "", "document", "empty":
	default:
		return false // image, script, style, iframe, ...: fetched by a page
	}
	return refHost == ""
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

// SetCrawlerRangeCheck: register the (crawler name, client address) ->
// "inside the ranges its vendor publishes" function
// (nginxconf.CrawlerVendorRange).  Without it the per-site rows' verified
// count stays at zero.  Set once at startup before traffic, like the
// classifier.
func (r *Reader) SetCrawlerRangeCheck(f func(name, ip string) bool) {
	if r == nil {
		return
	}
	r.crawlerInRange = f
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

// SetLive hands the reader the counter the dashboard's live strip reads.
// nil-safe on both sides.
func (r *Reader) SetLive(c *live.Counter) {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.live = c
	r.mu.Unlock()
}

// SetDeniedCheck registers how to tell a client nginx refuses outright (a ban
// whose action is deny), so the live strip does not count its requests as
// passed; the deny page's serve event counts them as refused.
func (r *Reader) SetDeniedCheck(f func(ip, ja4 string) bool) {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.isDenied = f
	r.mu.Unlock()
}

// SetRuleHit installs the custom-rule counter: f is called with the id of
// the rule that decided a request (the line's cr= field), once per line.
func (r *Reader) SetRuleHit(f func(id string)) {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.ruleHit = f
	r.mu.Unlock()
}

// SetRenderSeen installs the render watch: f is called with every line's
// render id (rv=; "" for a line without one).  Call before Receive.
func (r *Reader) SetRenderSeen(f func(id string)) {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.renderSeen = f
	r.mu.Unlock()
}

// SetModuleSeen installs the module watch: f is called with every line's
// module id (mo=; "" for a line without one).  Call before Receive.
func (r *Reader) SetModuleSeen(f func(id string)) {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.moduleSeen = f
	r.mu.Unlock()
}

// SetSiteCheck registers whether a Host is a site to count on its own: with
// the site list in "defined" mode, one on the list.  A Host f refuses is
// filed under OtherSite at once, without a bucket of its own.  Unset, every
// Host is counted, as "auto" mode has it (the per-minute cap still holds).
// Call before Receive.
func (r *Reader) SetSiteCheck(f func(site string) bool) {
	if r == nil {
		return
	}
	r.siteKnown = f
}

// aggSite is the site a line's buckets are keyed by: the Host as logged,
// or OtherSite when that Host is off the defined list (siteKnown) or is
// past the siteCapPerMinute-th distinct one this minute.  "default" (a
// line with no Host) is always its own.  The honeypot callback is given
// the Host as logged, not this: its per-site rule is the operator's.
func (r *Reader) aggSite(site string) string {
	if site == "" || site == "default" {
		return site
	}
	if f := r.siteKnown; f != nil && !f(site) {
		return OtherSite
	}
	minute := time.Now().Unix() / 60
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.sitesMinute != minute || r.sitesSeen == nil {
		r.sitesMinute = minute
		r.sitesSeen = map[string]struct{}{} // a Reader a test made by hand has none
	}
	if _, ok := r.sitesSeen[site]; ok {
		return site
	}
	if len(r.sitesSeen) >= siteCapPerMinute {
		return OtherSite
	}
	r.sitesSeen[site] = struct{}{}
	return site
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

// crawlerSiteKey / crawlerSiteBucket: per-hour, per-(site, category,
// individual-crawler) aggregation for the crawler card once a site is picked
// and for the daily CSV (= unmask_crawler_site_hourly).  It is kept beside
// the install-wide drill-down above, not in its place: the card with no site
// picked reads that one, whose rows do not multiply with the number of
// sites, and a daemon from before this table goes on writing it as it always
// did.  site is the one the other per-site buckets use (aggSite), so the
// rows a client can mint by varying its Host are bounded here as they are
// there.
//
// total and served mean what they do in crawlerBucket; verified is the
// requests whose address is inside the ranges the crawler's vendor publishes
// (crawlerInRange), named the ones the configuration let through on the
// crawler's name alone.  The two say what kind of request the name was on: a
// crawler with published ranges and few verified requests is mostly someone
// else.
type crawlerSiteKey struct {
	hour     int64
	site     string
	category string
	crawler  string
}

type crawlerSiteBucket struct {
	total    int
	served   int
	verified int
	named    int
}

// crawlerSiteBucketsMax bounds the per-site crawler buckets kept between
// flushes.  A flush drains them every minute; the bound is reached only when
// flushes cannot write -- through a schema update's hold, a database that
// refuses writes -- and a client varying its Host and its crawler name must
// not grow them without limit meanwhile.  Past it a request for a site and
// crawler that have no bucket yet is counted under OtherSite, so the sites
// still add up to the install-wide rows.  A variable so a test can make it
// small.
var crawlerSiteBucketsMax = 200000

// namedKey / namedBucket: per-hour, per-crawler count of the requests the
// configuration let through on the crawler's name alone (sb=1, no challenge, no
// cookie, no bypass), with a HyperLogLog sketch of the addresses they came
// from (= unmask_crawler_named_hourly).  A name is free to claim; this is how
// the UA-filter tab and doctor show how much is being claimed, and from how
// many places.  Hourly like the drill-down it sits beside.
type namedKey struct {
	hour    int64
	crawler string
	// country: where the address is (the ipgeo reader), "" when unknown.
	// The country tab reads the split to say, before a rule is saved, which
	// named crawlers the last day's traffic says it would stop.
	country string
}

type namedBucket struct {
	cnt int
	ips hll.Sketch
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
	cnt int
	// judged: the requests among cnt the gate judged (inside a protected
	// location, not a bypass address or path): what the reuse cap counts.
	// cnt is every line, the static files and the challenge page's own
	// parts among them.
	judged   int
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
}

// Start: if socketPath is empty, return a disabled stub
// (= goroutines don't run).  Otherwise bind the Unix datagram socket
// and start the two recv + flush goroutines.  The socket's mode and group
// are the defaults (StartWith).
func Start(socketPath string, d *db.DB) *Reader {
	return StartWith(socketPath, d, sockperm.Spec{})
}

// StartWith is Start with the socket's mode and group as the operator set
// them (nginx_log.socket_mode / socket_group).
//
// An existing socket file is deleted and re-created (= residue from a
// prior admin).  The socket is shared by group with nginx's worker: mode
// 0660, owned by the worker's group (named, or the first web server group
// the host has), which the daemon must be a member of (the service unit
// adds it as a supplementary group).  When no group can be applied the
// socket is opened to every local user (0666) instead, so that nginx's
// lines are not lost silently, and the log says so; `unmask doctor`
// repeats it.  Any local process can then write lines into the daemon's
// counts, which is what the group share is for (sockperm).
func StartWith(socketPath string, d *db.DB, perm sockperm.Spec) *Reader {
	r := &Reader{
		socketPath:           socketPath,
		d:                    d,
		buckets:              map[bucketKey]*bucket{},
		crawlerBuckets:       map[crawlerKey]*crawlerBucket{},
		crawlerDetailBuckets: map[crawlerDetailKey]*crawlerBucket{},
		crawlerSiteBuckets:   map[crawlerSiteKey]*crawlerSiteBucket{},
		namedBuckets:         map[namedKey]*namedBucket{},
		countryHourlyBuckets: map[countryHourKey]*countryHourBucket{},
		cookieIPBuckets:      map[cookieIPKey]*cookieIPBucket{},
		passBuckets:          map[passKey]*passBucket{},
		passHours:            map[passHourKey]int{},
		stop:                 make(chan struct{}),
		ready:                make(chan struct{}),
		lines:                make(chan string, recvQueueSize),
		doneA:                make(chan struct{}),
		doneB:                make(chan struct{}),
		doneC:                make(chan struct{}),
	}
	if d == nil {
		close(r.doneA)
		close(r.doneB)
		close(r.doneC)
		return r
	}
	// Even when socket path is unset (= forward-auth mode etc.), run
	// the DB flush goroutine.  recvLoop is unnecessary (= buckets are
	// incremented externally via Bump()).
	if socketPath == "" {
		// A socket the service manager kept over the restart (handover.go)
		// is not wanted now: let it go, or nginx would log into it unread.
		Release()
		close(r.doneA) // no recv
		close(r.doneC) // and nothing to work off
		go r.flushLoop()
		return r
	}

	// The socket the service manager kept over a restart is the one
	// nginx's workers are still connected to: read on from it.
	if conn := adopt(socketPath); conn != nil {
		r.conn, r.stored = conn, true
		log.Printf("nginxlog: listening on unix:%s (kept over the restart)", socketPath)
		// The kept socket is the file at the path: it takes the mode and
		// group this version asks for, as a fresh bind would, and so does
		// its directory.
		shareDir(socketPath, applySocketPerms(socketPath, perm))
		go r.recvLoop()
		go r.workLoop()
		go r.flushLoop()
		return r
	}

	// Create the parent dir (= /run/unmask etc.).  Operationally we
	// expect systemd's RuntimeDirectory to create it (0750, the daemon's
	// own), but in dev / Docker admin may create it.  The worker, another
	// user, has to pass through it to reach the socket: once the socket
	// is bound and has its group, the directory takes the same group at
	// 0750 (shareDir) -- until 0.1.54 it was opened to every local user
	// (0755) here, whatever the unit said.
	if dir := filepath.Dir(socketPath); dir != "" && dir != "." {
		_ = os.MkdirAll(dir, 0o750)
	}
	addr := &net.UnixAddr{Name: socketPath, Net: "unixgram"}
	var conn *net.UnixConn
	// Under SELinux the socket takes the web server's type: nginx may not
	// send to a socket of the daemon's own (selabel, which may run this
	// twice).
	labelled, err := selabel.ForWebServer(func() (err error) {
		// Delete any existing socket file (= residue from a prior admin.
		// If it's still there, bind fails).
		_ = os.Remove(socketPath)
		conn, err = net.ListenUnixgram("unixgram", addr)
		return err
	})
	if err != nil {
		log.Printf("nginxlog: ListenUnixgram %s failed: %v (= aggregation disabled)", socketPath, err)
		forget() // nothing bound to replace what the store may hold (handover.go)
		close(r.doneA)
		close(r.doneB)
		close(r.doneC)
		return r
	}
	// No SetReadBuffer: on a unix datagram socket SO_RCVBUF does not bound
	// what waits to be read (unix(7)); net.unix.max_dgram_qlen does, as a
	// count of datagrams, and past it nginx's worker gets EAGAIN and drops
	// the line.  What keeps that queue short is a receiver that never waits
	// on a line: recvLoop hands each one to workLoop and reads on.
	shareDir(socketPath, applySocketPerms(socketPath, perm))
	r.conn = conn
	log.Printf("nginxlog: listening on unix:%s", socketPath)
	if labelled {
		log.Printf("nginxlog: the socket carries the web server's SELinux type (%s), so nginx may send to it", selabel.WebServerType)
	}
	if handoverOn() {
		if err := store(conn); err != nil {
			log.Printf("nginxlog: could not hand the socket to the service manager (%v); a restart will drop nginx's connections", err)
		} else {
			r.stored = true
		}
	}

	go r.recvLoop()
	go r.workLoop()
	go r.flushLoop()
	return r
}

// applySocketPerms gives the socket the mode and group the operator asked
// for (sockperm): 0660 shared with the worker's group, or open to every
// local user when no group can be applied -- said in the log either way,
// since which it is decides who can write lines into the daemon's counts.
// Returns the group the socket was given ("" when none).
func applySocketPerms(path string, perm sockperm.Spec) string {
	res, err := sockperm.Apply(path, perm, 0o660, true)
	for _, n := range res.Notes {
		log.Printf("nginxlog: %s", n)
	}
	if err != nil {
		log.Printf("nginxlog: %v (nginx's worker may not be able to write to the socket)", err)
		return ""
	}
	if res.Group != "" {
		log.Printf("nginxlog: %s is mode %#o, group %s", path, res.Mode, res.Group)
	} else if res.WorldWritable() {
		log.Printf("nginxlog: %s is mode %#o (open to every local user)", path, res.Mode)
	}
	return res.Group
}

// shareDir gives the socket's directory to the socket's group at 0750, so
// the worker passes through it and other local users do not
// (sockperm.ShareDir); 0755 when there is no group to share with.
func shareDir(socketPath, group string) {
	dir := filepath.Dir(socketPath)
	if dir == "" || dir == "." {
		return
	}
	mode, notes := sockperm.ShareDir(dir, group)
	for _, n := range notes {
		log.Printf("nginxlog: %s", n)
	}
	if mode == 0o750 {
		log.Printf("nginxlog: %s is mode 0750, group %s", dir, group)
	}
}

// Receive lets the reader take lines from the socket.  Start binds (or takes
// back) the socket and reads nothing yet; the caller registers its callbacks
// -- the classifier, the country lookup, the honeypot ban -- and then calls
// this, so that no line is handled without them.  Lines that arrive in
// between wait in the socket.
func (r *Reader) Receive() {
	if r == nil || r.ready == nil {
		return
	}
	r.readyOnce.Do(func() { close(r.ready) })
}

// Close: stop the goroutines.  Final-flush remaining buckets and
// delete the socket file -- unless the service manager keeps the socket for
// the next start, which reads on from its path.
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
	<-r.doneC
	<-r.doneB
	r.flushOnce(true)
	if r.conn != nil {
		// The socket stays with the service manager only for a successor
		// that will read it (handover.go).
		if r.stored && !successorTakesOver() {
			log.Printf("nginxlog: the binary that starts next does not take the log socket over; not keeping it")
			letGo(r.conn)
			r.stored = false
		}
		_ = r.conn.Close()
	}
	if r.socketPath != "" && !r.stored {
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
//	$msec site=$host kind=$bv_kind fc=$unmask_fc_log
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
// fc / hp / ip / ja4 / hpuri / bp / scheme / cr / ob / rv / bv / ua are optional groups (= degrade
// gracefully even with older config or mode mismatch).  ua is last and matched with .* —
// it contains spaces, so it must be the final field of the log line.
//
// bv is the pass cookie as the request carried it, once the plugin verified
// it (http.inc's $unmask_bv_log admits the cookie's own alphabet only); the
// per-address count of distinct passes is keyed by it (pass_ip.go).
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
		`(?: fc=([01]))?(?: hp=([01]))?(?: ip=([0-9a-fA-F:.]+))?(?: ja4=(\S*))?(?: hpuri=(\S*))?` +
		// bp and scheme are optional: the binary is deployed before the config
		// that emits them, so both shapes have to parse for the length of that
		// window.
		`(?: bp=([01]))?(?: scheme=(\S*))?(?: cr=(\S*))?(?: ob=([01]))?(?: rv=([0-9a-f]{12}))?(?: pv=([01]))?(?: sb=([01]))?` +
		// sfs / sfd / rh: what the configuration logs of Sec-Fetch-Site,
		// Sec-Fetch-Dest and the Referer's host, each passed through a map
		// that admits only the known tokens (a client-written value cannot
		// smuggle a field into the line).  Absent from older configurations.
		// mo: the module file nginx loaded, by content hash (the module's
		// $unmask_module_id, 16 hex); "" from a configuration rendered
		// without the module, absent from older configurations.
		`(?: sfs=([a-z-]*))?(?: sfd=([a-z]*))?(?: rh=([A-Za-z0-9.:-]*))?(?: bv=([0-9A-Za-z.~]*))?(?: mo=([0-9a-f]*))?(?: ua=(.*))?` +
		// The match runs to the end of the line.  Unanchored, a line whose
		// Host carried a space and fields of its own (nginx before 1.21.1
		// passes such a Host through) parsed as those fields, the line's
		// real ones left over and ignored -- a honeypot ban on an address
		// of the client's choosing.  The configuration now logs the Host,
		// the forwarded JA4 and the trap URL without spaces (http.inc's
		// $unmask_site_log and its neighbours); this holds the parser to
		// the whole line as well.
		`$`)

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
	// bypassed: the configuration let this request through without judging it
	// (bypass IP or bypass path).  Absent on lines written before the config
	// carried the field, which read as false -- the same as "not bypassed",
	// which is the safe way round: it under-counts rather than inventing one.
	bypassed bool
	// scheme: the visitor's scheme, http or https ($unmask_forwarded_proto: the
	// edge's X-Forwarded-Proto behind a terminating LB, else $scheme).  Empty on
	// a line from a configuration that predates the field.
	scheme string
	// cr: the custom rule that decided the request (its id), "" when none
	// did or the configuration predates the field.
	cr string
	// observe: the site was in monitor mode, so the judgement (fc / hp) was
	// recorded and not enforced -- the request went through.  Absent on a
	// line from a configuration that predates the field, or from a site not
	// in the mode; both read the same: enforced.
	observe bool
	// rv: the render id of the configuration nginx logged this line under
	// (renderwatch).  "" on a line from a configuration written before
	// render ids.
	rv string
	// sb: the configuration passed this request on a crawler's name alone
	// (http.inc $is_search_bot: a UA on the list, no vendor range to check it
	// against, on a GET / HEAD).  With fc=0, no cookie and no bypass it is a
	// request that went through on the claim.  Absent on a line from a
	// configuration that predates the field.
	sb bool
	// pv: the configuration verified this request as a link-preview fetcher
	// by its name and the network it called from (http.inc
	// $unmask_preview_verified), so it did not go through on the name alone.
	// Absent on a line from a configuration that predates the field.
	pv bool
	// sfs / sfd / rh: the request's Sec-Fetch-Site and Sec-Fetch-Dest (known
	// tokens only) and the host its Referer names (hostname characters
	// only), as the configuration logged them; "" when absent or from a
	// configuration that predates the fields.  The honeypot ban reads them
	// (TripBannable).
	sfs string
	sfd string
	rh  string
	// bv: the pass cookie the request carried, as the configuration logged
	// it once the plugin verified it; "" without one, or from a
	// configuration that predates the field.
	bv string
	// mo: the hash of the module file nginx loaded (renderwatch); "" from a
	// configuration rendered without the module or one that predates the
	// field.
	mo string
	ua string
}

// plaintext reports whether the request came over the plaintext port.  The
// line says so itself once the configuration logs the scheme; a line from an
// older configuration is read the way it always was: no JA4 means no TLS,
// since the module fingerprints every handshake.
func (p parsed) plaintext() bool {
	if p.scheme != "" {
		return p.scheme == "http"
	}
	return p.ja4 == ""
}

func (r *Reader) parse(line string) (parsed, bool) {
	// The match is held to the end of the line (lineRE), and Go's $ does not
	// match before a trailing newline the way a PCRE $ does.
	line = strings.TrimRight(line, "\r\n")
	m := lineRE.FindStringSubmatch(line)
	if m == nil {
		return parsed{}, false
	}
	v, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return parsed{}, false
	}
	s := m[2]
	if s == "" || s == "-" {
		// A Host the configuration would not log as it was ($unmask_site_log
		// is empty then), or "-" for an unset one.
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
		kind:     m[3],
		fc:       m[4] == "1",
		hp:       m[5] == "1",
		ip:       m[6],
		ja4:      ja4,
		hpuri:    m[8],
		bypassed: m[9] == "1",
		scheme:   m[10],
		cr:       strings.TrimSuffix(m[11], "-"),
		observe:  m[12] == "1",
		rv:       m[13],
		pv:       m[14] == "1",
		sb:       m[15] == "1",
		sfs:      m[16],
		sfd:      m[17],
		rh:       m[18],
		bv:       m[19],
		mo:       m[20],
		ua:       m[21],
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
		// The Host as logged: the trap's per-site rule is resolved by it.
		r.onHoneypot(p.ip, p.ja4, p.hpuri, p.site, p.scheme)
	}
	// From here on the line counts under the site the buckets may hold
	// (OtherSite past the cap, or off the defined list).
	site := r.aggSite(p.site)
	kind := p.kind
	if kind == "" && p.fc {
		kind = "challenge_served"
		if p.observe {
			// Monitor mode: the judgement fired and nothing was served.  Its
			// own kind, so the composition card can name it and the landing
			// page can say what going live would have stopped.
			kind = "observe_pass"
		}
	}
	r.bumpLine(site, kind)
	// crawler_pass / bypass_pass are shares of the same total the composition
	// card divides up, so exactly one of them may fire per request -- and
	// neither may fire for a request that already counted as a pass cookie
	// above, or the human remainder is stolen from.
	//
	// Precedence, strongest statement first:
	//
	//   1. carries a valid _bv (p.kind "pow" / "captcha") -- somebody already
	//      cleared a challenge for this client.  That it also happened to
	//      match a bypass rule says nothing extra: it would have passed
	//      regardless.
	//   2. a listed crawler -- we know what this client IS, and the card's
	//      benign share is a statement about the client, not about which code
	//      path let it past.  The crawler funnel further down the same page
	//      counts it as a crawler no matter what path it asked for, so filing
	//      it as "passed through" here made one page disagree with itself by
	//      3.2x: 239,996 against 775,973 over a day.
	//   3. bypassed -- the fallback, and it has to be last, because it is the
	//      one bucket that says nothing about the traffic.  It means "exempted
	//      from judgement", so anything we can actually name should be named
	//      first and this should keep only what is left (a package manager, a
	//      monitor, an API client).
	//
	// Both overlaps have been seen in production.  Crawler and bypass firing
	// TOGETHER drove the human remainder negative (fixed in 0.1.18 -- by
	// exclusivity, which is what mattered; the order chosen there was the
	// wrong way round).  Cookie-over-bypass was the bigger one and hid behind
	// it: on an install serving its own assets from bypassed paths a large
	// share of the day's requests was counted twice, and the excess tracked
	// each site's bypass-path share exactly -- heavy where the assets are
	// local, negligible where they sit on a CDN.
	isCrawler := r.classifyCrawler != nil && p.ua != "" && r.classifyCrawler(p.ua) != ""
	switch {
	case p.kind != "":
		// counted by Bump above as "pow" / "captcha"; nothing further.
	case p.fc:
		// counted above as "challenge_served" (or "observe_pass" on a site in
		// monitor mode).
	case isCrawler:
		r.bumpKind(site, "crawler_pass")
	case p.bypassed:
		r.bumpKind(site, "bypass_pass")
	}
	r.liveHit(p, isCrawler)
	if r.renderSeen != nil {
		r.renderSeen(p.rv)
	}
	if r.moduleSeen != nil {
		r.moduleSeen(p.mo)
	}
	if p.cr != "" {
		r.mu.Lock()
		f := r.ruleHit
		r.mu.Unlock()
		if f != nil {
			f(p.cr)
		}
	}
	// Fold the client IP into the per-minute HLL sketches (= unique-client
	// stats).  Uses the raw bv_kind (p.kind), not the "challenge_served"
	// alias, so ipPass only counts a genuine pow/captcha cookie.
	r.bumpTrafficHLL(site, p.ip, p.fc, p.kind, p.ua)
	// Country-hourly aggregation for the 30-day chart's country breakdown.
	// The kind passed here matches the unmask_cookie_minute kind: "" / pow /
	// captcha / challenge_served — keep the catalogue aligned so the two
	// tables can be compared 1:1.
	r.bumpCountryHourly(site, p.ip, kind)
	// Per-IP cookie-reuse ranking: only lines carrying a valid _bv cookie
	// (kind="captcha" / "pow") are recorded; bumpCookieIP no-ops for every other
	// kind, so this is at most two string compares on the common path.  Uses the
	// raw p.kind (not the challenge_served alias) so only genuine reuse is
	// counted, mirroring bumpTrafficHLL's pass detection.  A line the gate
	// judged (bp=0) is what the reuse cap counts; the ranking shows that
	// figure beside the whole.
	r.bumpCookieIP(site, p.ip, p.ja4, p.ua, p.kind, !p.bypassed)
	// The passes behind that reuse: which cookie the line rode on, per
	// address and day (pass_ip.go).  The host as logged is what the cookie is
	// bound to; the bucket's site is the one the other tables use.
	r.bumpPass(site, p.site, p.ip, p.ja4, p.ua, p.bv, p.kind, !p.bypassed)
	// Crawler funnel: every request carries a UA.  fc=1 (= a challenge was the
	// final action) counts as "served"; otherwise the request passed straight
	// through (rescued / valid cookie / a site in monitor mode, where nothing
	// is served).
	// A line with sb=1 and nothing else passing it -- no challenge, no cookie,
	// no bypass -- went through on the crawler's name alone.  The per-site
	// rows are kept under the site the buckets above use.
	r.bumpCrawler(site, p.ua, p.fc && !p.observe, p.sb && !p.pv && !p.fc && !p.bypassed && p.kind == "", p.ip)
	// Native rDNS post-pass: verify a crawler-claiming visitor and auto-ban a
	// forgery.  Cheap for the common (non-crawler) UA -- the callback short-
	// circuits before any DNS or lock.
	if r.crawlerObserve != nil {
		r.crawlerObserve(p.ip, p.ua)
	}
}

// liveHit counts one access-log line for the dashboard's live strip, under
// the same precedence the minute buckets use: a pass cookie, else a crawler or
// a bypass.  A request a gate handed to the daemon -- a challenge, a honeypot
// trip, a client the ban list refuses, an ASN or country rule's deny -- is
// none of those, and which page the daemon answered with the line does not
// say: its serve event does, and live.ObserveEvent counts it as a challenge
// or a refusal.  Country comes from the same lookup the hourly country buckets
// use, which ipgeo caches.
func (r *Reader) liveHit(p parsed, isCrawler bool) {
	r.mu.Lock()
	c, denied, geo := r.live, r.isDenied, r.geo
	r.mu.Unlock()
	if c == nil {
		return
	}
	m := live.Of(live.Requests)
	switch {
	case p.observe && (p.fc || p.hp):
		// A site in monitor mode let it through: filed with the other requests
		// that went past without enforcement.
		m |= live.Of(live.Bypass)
	case p.hp || (denied != nil && p.ip != "" && denied(p.ip, p.ja4)):
		// Answered by the daemon, a cookie or not: its serve event counts it.
	case p.kind != "":
		m |= live.Of(live.Pass)
	case p.fc:
		// Answered by the daemon: its serve event counts it.
	case p.bypassed:
		m |= live.Of(live.Bypass)
	case isCrawler:
		// A listed crawler let through on purpose: judged and admitted, the
		// dashboard's benign bot.  After bypassed, as the minute buckets have
		// it: a crawler on a bypassed path was never judged.
		m |= live.Of(live.Crawler)
	}
	cc := ""
	if geo != nil && geo.Loaded() && p.ip != "" {
		cc = geo.Lookup(p.ip)
	}
	c.Hit(time.Now(), cc, m)
}

// liveBump is the forward-auth twin of liveHit for the exported Bump* entry
// points: /api/check has no access-log line, so each exported counter feeds
// the strip with what it knows.  Country and denial are not known here.
func (r *Reader) liveBump(m live.Mask) {
	r.mu.Lock()
	c := r.live
	r.mu.Unlock()
	if c != nil {
		c.Hit(time.Now(), "", m)
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
	// No access-log line stands behind this call, so the live strip learns of
	// the request here (onLine counts its lines itself, with more to go on).
	// A challenge_served has its page's serve event, which counts it.
	m := live.Of(live.Requests)
	switch kind {
	case "pow", "captcha", "rebind":
		m |= live.Of(live.Pass)
	}
	r.liveBump(m)
	r.bumpLine(site, kind)
}

// bumpLine is the minute-bucket increment itself: one call per request.
func (r *Reader) bumpLine(site, kind string) {
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

// bumpKind increments one counter WITHOUT touching the bucket's total.  Bump
// owns "total" -- one call per access-log line -- so a second counter for the
// same line has to stay out of it or every crawler request would be counted
// twice in the request volume.
func (r *Reader) bumpKind(site, kind string) {
	if r == nil || r.d == nil || kind == "" {
		return
	}
	key := bucketKey{minute: time.Now().Unix() / 60, site: site}
	r.mu.Lock()
	b, ok := r.buckets[key]
	if !ok {
		b = &bucket{kinds: map[string]int{}}
		r.buckets[key] = b
	}
	b.kinds[kind]++
	r.mu.Unlock()
}

// bumpTrafficHLL: fold one request's client IP into the per-minute HLL
// sketches.  ip="" (= the log line carried no ip= field) is a no-op.
//
//	ipAll  <- every request
//	ipChal <- fc == 1 (= a challenge fired)
//	ipPass <- bv_kind is pow / captcha (= the client holds a pass cookie)
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
	r.mu.Unlock()
}

// bumpCountryHourly: resolve client country via ipgeo and increment the
// per-(hour, site, country) request bucket.  kind matches the
// unmask_cookie_minute catalogue ("" / pow / captcha / challenge_served).
// "" only bumps total (= the "no signal" share is back-computed on read as
// total - SUM(kinds), same as cookie_minute).
//
// nil-safe (= no-op when the Reader isn't running).  geo == nil, or no
// database loaded, folds every public address into country="" (rendered as
// "Unknown" on read); a local address is ipgeo.Local whenever there is a
// reader, since telling one takes no database.  ip == "" (= log line
// carried no ip= field) also produces "".
func (r *Reader) bumpCountryHourly(site, ip, kind string) {
	if r == nil || r.d == nil {
		return
	}
	cc := ""
	if r.geo != nil && ip != "" {
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

// crawlerCategory: the crawler category of ua, "" when there is nothing to
// count -- the Reader is not running, no classifier is set, or the UA is not
// a crawler's.
func (r *Reader) crawlerCategory(ua string) string {
	if r == nil || r.d == nil || r.classifyCrawler == nil || ua == "" {
		return ""
	}
	return r.classifyCrawler(ua)
}

// bumpCrawler: classify ua and increment its per-minute crawler bucket, the
// hourly drill-down bucket of the crawler and the bucket of the crawler on
// that site.
// site is the one the line's other buckets are keyed by (aggSite); only the
// per-site rows carry it, the per-minute category bucket, the drill-down and
// the name-only claims stay install-wide.
// served=true means the request did not pass straight through (= challenged).
// named=true means the request went through on the crawler's name alone
// (the access-log line's sb=1 with nothing else passing it); ip is then folded
// into that crawler's hourly address sketch.  ip is also what the per-site
// rows' verified count is decided on (crawlerInRange).  No-op when the
// classifier is unset or the UA is not a crawler.
func (r *Reader) bumpCrawler(site, ua string, served, named bool, ip string) {
	if cat := r.crawlerCategory(ua); cat != "" {
		r.countCrawler(site, cat, ua, served, named, ip)
	}
}

// countCrawler is bumpCrawler past the classification: cat is ua's category
// (crawlerCategory), never "".
func (r *Reader) countCrawler(site, cat, ua string, served, named bool, ip string) {
	if site == "" {
		site = "default" // a request without a host, as parse files it
	}
	now := time.Now().Unix()
	key := crawlerKey{minute: now / 60, category: cat}
	// Where a name-only request came from, for the country tab's estimate
	// (outside the lock: the mmdb lookup).
	cc := ""
	if named && r.geo != nil && ip != "" {
		cc = r.geo.Lookup(ip)
	}
	// Resolve the individual crawler within the category (= the drill-down
	// dimension) outside the lock -- regex matching must not hold r.mu.  Empty
	// when the namer is unwired (= only per-category aggregation runs).
	var dkey crawlerDetailKey
	haveDetail, verified := false, false
	if r.crawlerNamer != nil {
		if name := r.crawlerNamer(ua, cat); name != "" {
			dkey = crawlerDetailKey{hour: now / 3600, category: cat, crawler: name}
			haveDetail = true
			// Whether the address is one the crawler's vendor publishes: a
			// prefix lookup, outside the lock like the two above.
			if r.crawlerInRange != nil && ip != "" {
				verified = r.crawlerInRange(name, ip)
			}
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
		// The same request under its site, for the card with a site picked
		// and for the CSV.
		if r.crawlerSiteBuckets == nil { // as above: a Reader made by hand may have none
			r.crawlerSiteBuckets = map[crawlerSiteKey]*crawlerSiteBucket{}
		}
		skey := crawlerSiteKey{hour: dkey.hour, site: site, category: cat, crawler: dkey.crawler}
		sb := r.crawlerSiteBuckets[skey]
		if sb == nil {
			if len(r.crawlerSiteBuckets) >= crawlerSiteBucketsMax && site != OtherSite {
				// Only while nothing drains them (crawlerSiteBucketsMax): a
				// site and crawler with no bucket yet go under OtherSite.
				skey.site = OtherSite
				sb = r.crawlerSiteBuckets[skey]
			}
			if sb == nil {
				sb = &crawlerSiteBucket{}
				r.crawlerSiteBuckets[skey] = sb
			}
		}
		sb.total++
		if served {
			sb.served++
		}
		if verified {
			sb.verified++
		}
		if named {
			sb.named++
			if r.namedBuckets == nil {
				r.namedBuckets = map[namedKey]*namedBucket{}
			}
			nk := namedKey{hour: dkey.hour, crawler: dkey.crawler, country: cc}
			nb := r.namedBuckets[nk]
			if nb == nil {
				nb = &namedBucket{}
				r.namedBuckets[nk] = nb
			}
			nb.cnt++
			if ip != "" {
				nb.ips.Add([]byte(ip))
			}
		}
	}
	r.mu.Unlock()
}

// BumpCrawler: exported entry point for forward-auth mode (= /api/check has
// the UA but emits no access-log line of its own).  site is the request's
// site as /api/check resolved it and ip its client address, for the per-site
// rows and their verified count.  nil-safe.
//
// The site goes through aggSite, as a logged Host does in onLine: the Host
// header names it, and a client varying that header would otherwise get a
// row per value, per crawler, per hour.  (Bump and the other forward-auth
// entry points key their buckets by the site as given.)  Only for a request
// that is counted: every request of the install passes here, and the others
// neither take aggSite's lock nor use up its distinct sites of the minute.
func (r *Reader) BumpCrawler(site, ua, ip string, served bool) {
	cat := r.crawlerCategory(ua)
	if cat == "" {
		return
	}
	r.countCrawler(r.aggSite(site), cat, ua, served, false, ip)
}

// BumpBypass records a request the configuration let through without judging
// it.  Forward-auth mode writes no access-log line, so it has to feed the same
// counter onLine fills in native mode -- otherwise the two wires disagree on
// what the traffic was made of, which is the divergence this counter exists to
// remove in the first place.
func (r *Reader) BumpBypass(site string) {
	if r == nil {
		return
	}
	r.bumpKind(site, "bypass_pass")
	r.liveBump(live.Of(live.Bypass))
}

// BumpCrawlerPass: the forward-auth twin of onLine's crawler_pass case -- a
// listed crawler this configuration passed on purpose.
//
// It was missing, and forward-auth is the only wire that can lose it: native
// classifies straight off the access-log line, while forward-auth has to say so
// explicitly.  So on a node answering /api/check every rescued crawler landed
// in the composition card's residue instead of its benign share, and the
// residue matched the crawler table request for request -- 227 of 1,094 on the
// node where it surfaced, with crawler_pass flat zero for the whole day.
func (r *Reader) BumpCrawlerPass(site string) {
	if r == nil {
		return
	}
	r.bumpKind(site, "crawler_pass")
	r.liveBump(live.Of(live.Crawler))
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

// fitColumn makes s a value a utf8mb4 column of n characters takes: bytes
// that are not UTF-8 are dropped, and what lies past n characters is cut, on
// a character.
//
// The User-Agent was cut at 255 bytes, which can fall inside a character,
// and in forward-auth mode it is the request's own header, which can hold
// any bytes at all (in module mode nginx has escaped them in the log line).
// MariaDB refuses such a string, and with it the transaction it rides in --
// the whole minute's flush.  The rows go back into memory and are tried
// again the next minute, with the same value among them: one request, and
// the per-minute tables stood still until the daemon was restarted.
func fitColumn(s string, n int) string {
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "")
	}
	if len(s) <= n {
		return s // within n bytes is within n characters
	}
	chars := 0
	for i := range s {
		if chars == n {
			return s[:i]
		}
		chars++
	}
	return s
}

// cookieIPKinds: the _bv kinds whose reuse is ranked per IP.  Deliberately not
// every value $bv_kind can take: "challenge_served" is a challenge being shown
// (which does write an unmask_event row, so hunt already sees it) and "" is no
// cookie at all -- neither is a cookie being reused.
func cookieIPKinds(kind string) bool {
	return kind == "captcha" || kind == "pow" || kind == "rebind"
}

// bumpCookieIP: record one cookie-reuse request into the per-(minute, site, ip,
// kind) bucket.  Only a presented valid _bv cookie counts ("captcha" / "pow" /
// "rebind"); every other kind is a no-op, so the hot path adds at most two string compares
// per log line.  ja4 / ua keep the latest value seen for the IP within the
// minute bucket.
//
// "rebind" joined the list when the plugin learned to name that kind: those
// requests used to arrive labelled "captcha" and were ranked with the rest, so
// leaving them out would have quietly removed a re-binding client from the one
// ranking that shows its per-address volume -- a blind spot created by making
// the classification more honest, which is the worst way to acquire one.
//
// This runs on the log-reader goroutine, never on a request path: nginx already
// emits ip= and kind= on every line (log_format unmask_minimal) and the DB is
// touched once a minute by flushOnce, so widening the filter costs a map lookup
// per matching line and nothing in nginx.
//
// nil-safe (= no-op when the Reader isn't running).  ip="" (= log line carried
// no ip= field) is a no-op since there is no client to rank.
func (r *Reader) bumpCookieIP(site, ip, ja4, ua, kind string, judged bool) {
	if r == nil || r.d == nil || !cookieIPKinds(kind) || ip == "" {
		return
	}
	ua = fitColumn(ua, cookieIPUAMax)
	ja4 = fitColumn(ja4, passJA4Width)
	now := time.Now().Unix()
	key := cookieIPKey{minute: now / 60, site: site, ip: ip, kind: kind}
	r.mu.Lock()
	b, ok := r.cookieIPBuckets[key]
	if !ok {
		if len(r.cookieIPBuckets) >= cookieIPBucketsMax {
			// Only while nothing drains them -- a schema update's hold, a
			// database that refuses writes: a new address is not counted
			// rather than let the map grow for as long as that lasts.
			r.mu.Unlock()
			return
		}
		b = &cookieIPBucket{}
		r.cookieIPBuckets[key] = b
	}
	b.cnt++
	if judged {
		b.judged++
	}
	b.ja4 = ja4
	b.ua = ua
	b.lastSeen = now
	r.mu.Unlock()
}

// cookieIPBucketsMax bounds the per-(minute, site, address) buckets kept
// between flushes.  A flush drains them every minute; the bound is reached
// only when flushes cannot write -- through a schema update's hold, which
// keeps them for as long as an index build takes -- and a flood of addresses
// must not grow them without limit meanwhile.
const cookieIPBucketsMax = 200000

// BumpCookieIP: exported entry point for forward-auth mode (= /api/check sees
// the reuse request but emits no access-log line of its own, so without this the
// cookie-reuse card stays empty in forward-auth).  Every request that reaches
// /api/check was judged.  nil-safe.
func (r *Reader) BumpCookieIP(site, ip, ja4, ua, kind string) {
	if r == nil {
		return
	}
	r.bumpCookieIP(site, ip, ja4, ua, kind, true)
}

// flushOnce: UPSERT buckets "older than the current minute" into the DB.
// final=true flushes everything including the current minute (= for shutdown).
// Cookie-minute, crawler-minute and country-hourly buckets all flush in the
// same transaction so a partial commit can never leave them inconsistent.
// logKeptAtStop says what a stop during a hold leaves unwritten: the
// minute buckets counted while the database's writes were held by a run
// from the shell, which the daemon cannot stop.  They are not carried over
// -- those minutes' statistics stay short -- and the loss is said, not
// silent (review finding S5).  The bans, events and audit rows of the same
// minutes are carried over (package spill).
func (r *Reader) logKeptAtStop() {
	r.mu.Lock()
	buckets, requests := len(r.buckets), int64(0)
	for _, b := range r.buckets {
		requests += int64(b.total)
	}
	r.mu.Unlock()
	if buckets > 0 {
		log.Printf("nginxlog: the database's writes are still held at the stop (a schema update or a compaction from the shell); "+
			"the counts of %d minute bucket(s), %d request(s), kept meanwhile are not written, and those minutes' statistics stay short", buckets, requests)
	}
}

func (r *Reader) flushOnce(final bool) {
	if r == nil || r.d == nil {
		return
	}
	if r.beforeFlush != nil {
		r.beforeFlush() // a test's seam
	}
	// A schema update holds the write lock: the buckets stay in memory,
	// keep counting, and go out with the first flush after it.
	if r.d.WritesHeld() {
		if final {
			r.logKeptAtStop()
		}
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
	type crawlerSiteEntry struct {
		key crawlerSiteKey
		b   crawlerSiteBucket
	}

	type namedEntry struct {
		key namedKey
		b   namedBucket
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
				ipAll: b.ipAll, ipChal: b.ipChal, ipPass: b.ipPass,
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
	// the per-site crawler buckets flush every tick too, for the same reason.
	crawlerSiteReady := make([]crawlerSiteEntry, 0, len(r.crawlerSiteBuckets))
	for k, b := range r.crawlerSiteBuckets {
		crawlerSiteReady = append(crawlerSiteReady, crawlerSiteEntry{k, *b})
		delete(r.crawlerSiteBuckets, k)
	}
	// name-only claims flush every tick too, for the same reason.
	namedReady := make([]namedEntry, 0, len(r.namedBuckets))
	for k, b := range r.namedBuckets {
		namedReady = append(namedReady, namedEntry{k, *b})
		delete(r.namedBuckets, k)
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
	// pass-count buckets flush every tick: the row keeps the levels and
	// accumulates the deltas, so the day's figures are fresh within ~60s.
	passReady := r.collectPassLocked(time.Now())
	r.mu.Unlock()

	if len(ready) == 0 && len(crawlerReady) == 0 && len(crawlerDetailReady) == 0 && len(crawlerSiteReady) == 0 && len(namedReady) == 0 && len(countryReady) == 0 && len(cookieIPReady) == 0 && len(passReady) == 0 {
		return
	}

	// Ten seconds for a minute's worth; more for the backlog of a hold, which
	// is written in this one transaction and would otherwise miss the
	// deadline at every try.
	rows := len(ready)*4 + len(crawlerReady) + len(crawlerDetailReady) + len(crawlerSiteReady) + len(namedReady) + len(countryReady)*2 + len(cookieIPReady) + len(passReady)
	within := 10*time.Second + time.Duration(rows)*time.Millisecond
	if within > 2*time.Minute {
		within = 2 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), within)
	defer cancel()

	// restore puts what was taken back into memory, merged with what has
	// been counted since, for the next flush to retry.  On every failure --
	// the transaction is rolled back, so nothing is counted twice.  It used
	// to happen only when the transaction could not begin: a statement or a
	// commit that failed lost every bucket it carried, and after a schema
	// update's hold that is everything counted during the build.
	restore := func() {
		r.mu.Lock()
		for _, e := range ready {
			b, ok := r.buckets[e.key]
			if !ok {
				bb := bucket{
					total: e.b.total, kinds: map[string]int{},
					ipAll: e.b.ipAll, ipChal: e.b.ipChal, ipPass: e.b.ipPass,
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
		for _, e := range crawlerSiteReady {
			if b, ok := r.crawlerSiteBuckets[e.key]; ok {
				b.total += e.b.total
				b.served += e.b.served
				b.verified += e.b.verified
				b.named += e.b.named
			} else {
				bb := e.b
				if r.crawlerSiteBuckets == nil {
					r.crawlerSiteBuckets = map[crawlerSiteKey]*crawlerSiteBucket{}
				}
				r.crawlerSiteBuckets[e.key] = &bb
			}
		}
		// The name-only claims were the one family taken out above and not
		// put back here: a failed flush lost the hour's count of requests
		// passed on a crawler's name, while the drill-down beside it kept its.
		for _, e := range namedReady {
			if b, ok := r.namedBuckets[e.key]; ok {
				b.cnt += e.b.cnt
				b.ips.Merge(&e.b.ips)
			} else {
				if r.namedBuckets == nil {
					r.namedBuckets = map[namedKey]*namedBucket{}
				}
				bb := e.b
				r.namedBuckets[e.key] = &bb
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
				b.judged += e.b.judged
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
		r.restorePassLocked(passReady)
		r.mu.Unlock()
	}

	tx, err := r.d.BeginTx(ctx, nil)
	if err != nil {
		log.Printf("nginxlog: flush BeginTx: %v", err)
		restore() // retry on the next flush
		return
	}

	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
			restore()
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
		}{{"ip", e.b.ipAll}, {"ipc", e.b.ipChal}, {"ipp", e.b.ipPass}} {
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
	stmtCrawlerSite := crawlerSiteUpsertStmt(r.d.Driver)
	for _, e := range crawlerSiteReady {
		if _, err := tx.ExecContext(ctx, stmtCrawlerSite,
			e.key.hour, e.key.site, e.key.category, e.key.crawler,
			e.b.total, e.b.served, e.b.verified, e.b.named); err != nil {
			log.Printf("nginxlog: flush exec(crawler-site %s/%s): %v", e.key.category, e.key.crawler, err)
			return
		}
	}
	// Name-only claims: the count accumulates; the address sketch is
	// read-merge-written like the traffic sketches, so a restart or a late
	// line unions with what is stored instead of overwriting it.
	stmtNamed := namedUpsertStmt(r.d.Driver)
	for _, e := range namedReady {
		var prev []byte
		row := tx.QueryRowContext(ctx,
			`SELECT ips FROM unmask_crawler_named_hourly WHERE bucket_hour = ? AND crawler = ? AND country = ?`,
			e.key.hour, e.key.crawler, e.key.country)
		if err := row.Scan(&prev); err == nil && len(prev) > 0 {
			e.b.ips.Merge(hll.Load(prev))
		}
		if _, err := tx.ExecContext(ctx, stmtNamed,
			e.key.hour, e.key.crawler, e.key.country, e.b.cnt, e.b.ips.Bytes()); err != nil {
			log.Printf("nginxlog: flush exec(named %s): %v", e.key.crawler, err)
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
			e.key.minute, e.key.site, ipb, e.key.kind, e.b.ja4, e.b.ua, e.b.cnt, e.b.judged, lastSeen); err != nil {
			log.Printf("nginxlog: flush exec(cookie-ip): %v", err)
			return
		}
	}
	if err := r.execPass(ctx, tx, passReady); err != nil {
		log.Printf("nginxlog: flush exec(pass-ip): %v", err)
		return
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

// crawlerSiteUpsertStmt: accumulate the four counters with (bucket_hour, site,
// category, crawler) as the unique key, into unmask_crawler_site_hourly.  The
// drill-down's rows once more, with the site kept.
func crawlerSiteUpsertStmt(drv db.Driver) string {
	if drv == db.DriverSQLite {
		return `INSERT INTO unmask_crawler_site_hourly (bucket_hour, site, category, crawler, total, served, verified, named)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(bucket_hour, site, category, crawler) DO UPDATE SET
				total = total + excluded.total, served = served + excluded.served,
				verified = verified + excluded.verified, named = named + excluded.named`
	}
	return `INSERT INTO unmask_crawler_site_hourly (bucket_hour, site, category, crawler, total, served, verified, named)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE
			total = total + VALUES(total), served = served + VALUES(served),
			verified = verified + VALUES(verified), named = named + VALUES(named)`
}

// namedUpsertStmt: accumulate cnt with (bucket_hour, crawler, country) as the
// unique key, into unmask_crawler_named_hourly; ips takes the merged sketch
// the caller computed (read-merge-write), so it is replaced, not added.
func namedUpsertStmt(drv db.Driver) string {
	if drv == db.DriverSQLite {
		return `INSERT INTO unmask_crawler_named_hourly (bucket_hour, crawler, country, cnt, ips)
			VALUES (?, ?, ?, ?, ?)
			ON CONFLICT(bucket_hour, crawler, country) DO UPDATE SET
				cnt = cnt + excluded.cnt, ips = excluded.ips`
	}
	return `INSERT INTO unmask_crawler_named_hourly (bucket_hour, crawler, country, cnt, ips)
		VALUES (?, ?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE
			cnt = cnt + VALUES(cnt), ips = VALUES(ips)`
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
		return `INSERT INTO unmask_cookie_ip_minute (bucket_min, site, ip, kind, ja4, ua, cnt, judged, last_seen)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(bucket_min, site, ip, kind) DO UPDATE SET
				cnt = cnt + excluded.cnt, judged = judged + excluded.judged,
				ja4 = excluded.ja4, ua = excluded.ua, last_seen = excluded.last_seen`
	}
	return `INSERT INTO unmask_cookie_ip_minute (bucket_min, site, ip, kind, ja4, ua, cnt, judged, last_seen)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE
			cnt = cnt + VALUES(cnt), judged = judged + VALUES(judged),
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

// flushEvery is the flush loop's tick (a variable for the tests).
var flushEvery = 60 * time.Second

// flushLoop: 60-second ticker.  A panic in a flush ends that flush, not
// the loop (safe.Guard): the buckets stay in memory and go out with the
// next tick, after the guard's wait.  Through 0.1.53 the loop as a whole
// was recovered, and one panic left the counters to grow in memory, and
// the statistics to stop, for the life of the process.
func (r *Reader) flushLoop() {
	defer close(r.doneB)
	guard := safe.NewGuard("nginxlog-flush")
	tick := time.NewTicker(flushEvery)
	defer tick.Stop()
	for {
		select {
		case <-r.stop:
			return
		case <-tick.C:
			if guard.Ready() {
				guard.Run(func() { r.flushOnce(false) })
			}
		}
	}
}

// recvLoop: read from the Unix datagram socket and queue each datagram (=
// one line of access_log unmask_minimal) for workLoop.  Reading is all it
// does: a line is handled by the worker, so a slow one -- a honeypot trip
// writing a ban, a database that is busy -- does not hold the socket's
// queue, where nginx's worker drops lines once it is full.  A line that
// finds the queue between the two full is dropped here instead, counted
// (DroppedLines) and said once a minute: that is the daemon falling behind
// the log, which the socket would otherwise hide.
func (r *Reader) recvLoop() {
	defer close(r.doneA)
	// The worker ends when the queue is closed, after what is in it.
	defer close(r.lines)
	// Nothing is read until the callbacks are in place (Receive); what
	// arrives meanwhile waits in the socket.
	select {
	case <-r.ready:
	case <-r.stop:
		return
	}
	// One datagram per line, and a datagram longer than the buffer loses its
	// tail without a word -- the fields the honeypot ban's vetoes read come
	// after the trap URL, so a cut line banned what the whole one spares.
	// unmask_minimal is ~200 bytes; its free-text fields are the User-Agent
	// (bounded by nginx's header buffers) and the trap URL (1000 at most,
	// http.inc), so 64 KB is never reached by a line nginx sends.  One that
	// does arrive cut is counted and dropped (MSG_TRUNC), never read.
	buf := make([]byte, 64*1024)
	for {
		select {
		case <-r.stop:
			return
		default:
		}
		n, _, flags, _, err := r.conn.ReadMsgUnix(buf, nil)
		if err == nil && flags&syscall.MSG_TRUNC != 0 {
			r.dropTruncated(n)
			continue
		}
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
		select {
		case r.lines <- string(line):
		default:
			r.dropLine()
		}
	}
}

// dropLine counts a line let go for a full queue and logs it at most once
// a minute.  Called on the receive goroutine only.
func (r *Reader) dropLine() {
	n := r.droppedLines.Add(1)
	if now := time.Now(); now.Sub(r.dropSaid) >= time.Minute {
		r.dropSaid = now
		log.Printf("nginxlog: the line queue is full (%d lines waiting): %d line(s) dropped so far -- the lines are handled slower than nginx logs them", cap(r.lines), n)
	}
}

// dropTruncated counts a datagram that arrived longer than the receive buffer
// (recvLoop): its tail is gone, so it is not read at all.  The log says so
// once a minute at most.
func (r *Reader) dropTruncated(kept int) {
	n := r.truncatedLines.Add(1)
	if now := time.Now(); now.Sub(r.truncSaid) >= time.Minute {
		r.truncSaid = now
		log.Printf("nginxlog: a line longer than %d bytes arrived cut and was dropped (%d so far)", kept, n)
	}
}

// TruncatedLines is how many lines arrived cut and were dropped (recvLoop),
// since the start.  nil-safe.
func (r *Reader) TruncatedLines() uint64 {
	if r == nil {
		return 0
	}
	return r.truncatedLines.Load()
}

// DroppedLines is how many lines the receiver let go for a full queue
// (recvLoop), since the start.  nil-safe.
func (r *Reader) DroppedLines() uint64 {
	if r == nil {
		return 0
	}
	return r.droppedLines.Load()
}

// workLoop handles the lines recvLoop queued, one at a time and in the
// order they were read: the parse, the classifier, the country lookup, the
// custom-rule counter and the honeypot ban all run here.  Ends when the
// receiver has closed the queue and what was in it is handled, so a line
// read before a stop still reaches the final flush.
func (r *Reader) workLoop() {
	defer close(r.doneC)
	for ls := range r.lines {
		// Per-line recovery: a malformed/attacker-influenced log line that
		// panics onLine must not kill the whole reader (and the daemon).
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
