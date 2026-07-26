// Package crawlerverify authenticates a visitor that CLAIMS (via User-Agent) to
// be a well-known search crawler, using forward-confirmed reverse DNS (rDNS) --
// the method Google/Bing/Yandex/Apple/Baidu officially publish for verification.
//
// The check, for a claim like "Googlebot":
//  1. PTR-lookup the visitor IP  ->  hostname(s)
//  2. at least one hostname ends in an expected domain (googlebot.com/google.com)
//  3. forward-lookup that hostname  ->  IPs, and the original IP is among them
//
// Passing all three is a genuine crawler (Verified).  A UA that claims a crawler
// but fails (2) or (3) is a forgery (Forged) -- the exact "fake Googlebot" class
// that risks SEO incidents.  This does NOT rely on maintaining vendor IP ranges,
// so it stays correct as those ranges change.
package crawlerverify

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"
)

// Status is the outcome of a verification.
type Status int

const (
	NotApplicable Status = iota // the UA claims no rDNS-verifiable crawler
	Verified                    // rDNS forward-confirm passed: a genuine crawler
	Forged                      // claims a crawler but rDNS disproves it
	Unresolved                  // DNS error/timeout: inconclusive (caller decides)
)

func (s Status) String() string {
	switch s {
	case Verified:
		return "verified"
	case Forged:
		return "forged"
	case Unresolved:
		return "unresolved"
	default:
		return "n/a"
	}
}

// Result carries the outcome plus context for logging / the decision layer.
type Result struct {
	Status  Status
	Crawler string // matched crawler name (e.g. "Googlebot"), when applicable
	Host    string // the PTR hostname inspected (for logging)
}

// crawler is one rDNS-verifiable bot: the case-insensitive UA needle that claims
// it, and the domains its PTR records must end in.
type crawler struct {
	name    string
	uaNeed  string
	domains []string // bare domains; host matches if == d or ends in "."+d
	// rangeBacked: the vendor publishes IP ranges that unmask ships a bypass
	// preset for, so an in-range visitor is already verified by the range and
	// rDNS is only an off-range safety net.  false = range-less (rDNS is the
	// primary verification for this crawler).  Informational for the UI.
	rangeBacked bool
}

// crawlers: the bots that publish an rDNS-verification method.  Ordered so a
// more specific needle would win if two overlapped (none currently do).
var crawlers = []crawler{
	{"Googlebot", "googlebot", []string{"googlebot.com", "google.com"}, true},
	{"Bingbot", "bingbot", []string{"search.msn.com"}, true},
	{"YandexBot", "yandex", []string{"yandex.com", "yandex.net", "yandex.ru"}, false},
	{"Applebot", "applebot", []string{"applebot.apple.com"}, true},
	{"Baiduspider", "baiduspider", []string{"baidu.com", "baidu.jp"}, false},
}

// CrawlerInfo describes one rDNS-verifiable crawler for the settings UI.
type CrawlerInfo struct {
	Name        string
	RangeBacked bool // true -> a bypass range preset usually covers it (rDNS is off-range only); false -> range-less (rDNS is the primary verification)
}

// Crawlers returns the catalog of rDNS-verifiable crawlers (UI: the per-crawler
// enable list).
func Crawlers() []CrawlerInfo {
	out := make([]CrawlerInfo, len(crawlers))
	for i, c := range crawlers {
		out[i] = CrawlerInfo{Name: c.name, RangeBacked: c.rangeBacked}
	}
	return out
}

// ClaimedCrawler returns the crawler name a UA claims to be, or "" for none.
// Lets the decision layer gate on the operator's per-crawler enable state
// before touching the cache / scheduling DNS.
func ClaimedCrawler(ua string) string {
	if c := matchClaim(ua); c != nil {
		return c.name
	}
	return ""
}

// matchClaim returns the crawler a UA claims to be, or nil.
func matchClaim(ua string) *crawler {
	low := strings.ToLower(ua)
	for i := range crawlers {
		if strings.Contains(low, crawlers[i].uaNeed) {
			return &crawlers[i]
		}
	}
	return nil
}

func domainMatch(host string, domains []string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, d := range domains {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}

// Resolver is the DNS surface crawlerverify needs; *net.Resolver satisfies it,
// and tests inject a fake.
type Resolver interface {
	LookupAddr(ctx context.Context, addr string) ([]string, error)
	LookupHost(ctx context.Context, host string) ([]string, error)
}

type cacheEntry struct {
	res    Result
	expiry time.Time
}

// Verifier performs (cached) rDNS verification.  Safe for concurrent use.
//
// Load discipline: the request path should call Cached (in-memory, no DNS) and,
// on a miss, VerifyAsync (a bounded background job) -- NOT Verify.  DNS then
// never sits in the request path, and a flood of forged crawler UAs from many
// IPs cannot amplify into unbounded DNS traffic: the worker pool caps concurrent
// lookups and a full queue is simply dropped (fail-open -- the existing gating
// axes still handle that request).
type Verifier struct {
	res     Resolver
	timeout time.Duration
	ttlOK   time.Duration // Verified/Forged: a settled answer, cache longer
	ttlSoft time.Duration // Unresolved: cache briefly so a DNS blip isn't hammered
	maxKeys int

	mu       sync.Mutex
	cache    map[string]cacheEntry
	inflight map[string]bool // keys with a background job scheduled (dedup)
	now      func() time.Time

	workers   int
	jobs      chan job
	startOnce sync.Once
}

type job struct {
	ip     string
	c      *crawler
	key    string
	onDone func(Result) // optional; called with the settled result after cacheSet
}

// New builds a Verifier.  A nil resolver uses net.DefaultResolver.
func New(res Resolver) *Verifier {
	if res == nil {
		res = net.DefaultResolver
	}
	return &Verifier{
		res:      res,
		timeout:  2 * time.Second,
		ttlOK:    6 * time.Hour,
		ttlSoft:  1 * time.Minute,
		maxKeys:  8192,
		cache:    map[string]cacheEntry{},
		inflight: map[string]bool{},
		now:      time.Now,
		workers:  6,
		jobs:     make(chan job, 256),
	}
}

// Cached returns a decision for (ip, ua) using ONLY the in-memory cache -- no
// DNS, so it is safe to call inline on every request.  ok=false means "not yet
// known": the caller should fall through to its normal handling and may call
// VerifyAsync to populate the cache for next time.  A UA that claims no crawler
// is definitively NotApplicable (ok=true), never a lookup.
func (v *Verifier) Cached(ip, ua string) (Result, bool) {
	c := matchClaim(ua)
	if c == nil {
		return Result{Status: NotApplicable}, true
	}
	return v.cacheGet(ip + "|" + c.name)
}

// VerifyAsync schedules a background rDNS verification whose result lands in the
// cache.  It is a no-op when the UA claims no crawler, when a fresh result is
// already cached, when a job for this key is already in flight, or when the
// bounded queue is full (the load cap -- dropped work is retried on a later
// request from the same IP).  Never blocks.
func (v *Verifier) VerifyAsync(ip, ua string) { v.enqueue(ip, ua, nil) }

// VerifyAsyncNotify is VerifyAsync plus a callback invoked with the settled
// result once the background lookup completes.  The native log-follower uses it
// to auto-ban a forgery.  Same no-op / dedup / load-cap rules as VerifyAsync;
// onDone does NOT fire when the job is skipped (cached / in-flight / queue-full)
// -- a cached answer is already available via Cached.
func (v *Verifier) VerifyAsyncNotify(ip, ua string, onDone func(Result)) { v.enqueue(ip, ua, onDone) }

func (v *Verifier) enqueue(ip, ua string, onDone func(Result)) {
	c := matchClaim(ua)
	if c == nil {
		return
	}
	key := ip + "|" + c.name
	v.mu.Lock()
	if e, ok := v.cache[key]; ok && !v.now().After(e.expiry) {
		v.mu.Unlock()
		return
	}
	if v.inflight[key] {
		v.mu.Unlock()
		return
	}
	v.inflight[key] = true
	v.mu.Unlock()

	v.startOnce.Do(v.startWorkers)
	select {
	case v.jobs <- job{ip: ip, c: c, key: key, onDone: onDone}:
	default:
		// Queue full: drop and clear the in-flight mark so a later request retries.
		v.mu.Lock()
		delete(v.inflight, key)
		v.mu.Unlock()
	}
}

func (v *Verifier) startWorkers() {
	for i := 0; i < v.workers; i++ {
		go func() {
			for j := range v.jobs {
				ctx := context.Background()
				var cancel context.CancelFunc
				if v.timeout > 0 {
					ctx, cancel = context.WithTimeout(ctx, v.timeout)
				}
				res := v.lookup(ctx, j.ip, j.c)
				if cancel != nil {
					cancel()
				}
				v.cacheSet(j.key, res)
				v.mu.Lock()
				delete(v.inflight, j.key)
				v.mu.Unlock()
				if j.onDone != nil {
					j.onDone(res)
				}
			}
		}()
	}
}

// Verify authenticates the (ip, ua) pair.  It performs DNS only when the UA
// actually claims a verifiable crawler; otherwise it returns NotApplicable with
// no lookups.  Results are cached by (ip, crawler).
func (v *Verifier) Verify(ctx context.Context, ip, ua string) Result {
	c := matchClaim(ua)
	if c == nil {
		return Result{Status: NotApplicable}
	}
	key := ip + "|" + c.name
	if r, ok := v.cacheGet(key); ok {
		return r
	}

	if v.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, v.timeout)
		defer cancel()
	}
	r := v.lookup(ctx, ip, c)
	v.cacheSet(key, r)
	return r
}

func (v *Verifier) lookup(ctx context.Context, ip string, c *crawler) Result {
	names, err := v.res.LookupAddr(ctx, ip)
	if err != nil || len(names) == 0 {
		// No PTR at all is inconclusive, not proof of forgery (some genuine
		// hosts lack a usable reverse zone at lookup time).
		return Result{Status: Unresolved, Crawler: c.name}
	}
	// Find a PTR hostname in the crawler's domain.
	var host string
	for _, n := range names {
		if domainMatch(n, c.domains) {
			host = strings.TrimSuffix(n, ".")
			break
		}
	}
	if host == "" {
		// PTR exists but is NOT the claimed crawler's domain -> forgery.
		return Result{Status: Forged, Crawler: c.name, Host: strings.TrimSuffix(names[0], ".")}
	}
	// Forward-confirm: the hostname must resolve back to the original IP.
	addrs, err := v.res.LookupHost(ctx, host)
	if err != nil {
		return Result{Status: Unresolved, Crawler: c.name, Host: host}
	}
	for _, a := range addrs {
		if a == ip {
			return Result{Status: Verified, Crawler: c.name, Host: host}
		}
	}
	return Result{Status: Forged, Crawler: c.name, Host: host}
}

func (v *Verifier) cacheGet(key string) (Result, bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	e, ok := v.cache[key]
	if !ok || v.now().After(e.expiry) {
		return Result{}, false
	}
	return e.res, true
}

func (v *Verifier) cacheSet(key string, r Result) {
	ttl := v.ttlOK
	if r.Status == Unresolved {
		ttl = v.ttlSoft
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if len(v.cache) >= v.maxKeys {
		// Simple bound: drop expired first, then clear if still full.
		nowT := v.now()
		for k, e := range v.cache {
			if nowT.After(e.expiry) {
				delete(v.cache, k)
			}
		}
		if len(v.cache) >= v.maxKeys {
			v.cache = map[string]cacheEntry{}
		}
	}
	v.cache[key] = cacheEntry{res: r, expiry: v.now().Add(ttl)}
}
