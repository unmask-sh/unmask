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
}

// crawlers: the bots that publish an rDNS-verification method.  Ordered so a
// more specific needle would win if two overlapped (none currently do).
var crawlers = []crawler{
	{"Googlebot", "googlebot", []string{"googlebot.com", "google.com"}},
	{"Bingbot", "bingbot", []string{"search.msn.com"}},
	{"YandexBot", "yandex", []string{"yandex.com", "yandex.net", "yandex.ru"}},
	{"Applebot", "applebot", []string{"applebot.apple.com"}},
	{"Baiduspider", "baiduspider", []string{"baidu.com", "baidu.jp"}},
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
type Verifier struct {
	res     Resolver
	timeout time.Duration
	ttlOK   time.Duration // Verified/Forged: a settled answer, cache longer
	ttlSoft time.Duration // Unresolved: cache briefly so a DNS blip isn't hammered
	maxKeys int

	mu    sync.Mutex
	cache map[string]cacheEntry
	now   func() time.Time // injectable clock for tests
}

// New builds a Verifier.  A nil resolver uses net.DefaultResolver.
func New(res Resolver) *Verifier {
	if res == nil {
		res = net.DefaultResolver
	}
	return &Verifier{
		res:     res,
		timeout: 2 * time.Second,
		ttlOK:   6 * time.Hour,
		ttlSoft: 1 * time.Minute,
		maxKeys: 8192,
		cache:   map[string]cacheEntry{},
		now:     time.Now,
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
