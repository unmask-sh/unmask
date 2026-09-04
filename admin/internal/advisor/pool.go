// pool.go — the wider slice of the window the model may nominate from.
//
// The deterministic engine flags what its four signals can describe.  With
// the model layer on, the page also shows the model the top of the rankings
// -- addresses, fingerprints and user agents with the same evidence columns
// the engine uses, plus origin (GeoIP / ASN) and reverse DNS -- so a shape no
// rule spells out (fifteen addresses sharing a user agent, a network and a
// route) can still be pointed at.  The same rule as for reviews applies: the
// model can only name something that was in this pool.  Exclusions (banned,
// dismissed, monitoring, private) are applied before the pool leaves the host.
package advisor

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/ipgeo"
)

// PoolIP is one address in the pool.  JSON names are what the model reads.
type PoolIP struct {
	IP           string `json:"ip"`
	Requests     int    `json:"requests"`
	Serves       int    `json:"challenges_served"`
	JSLoaded     int    `json:"js_loaded"`
	PowPassed    int    `json:"pow_passed"`
	CaptchaShown int    `json:"captcha_shown"`
	Passes       int    `json:"challenges_passed"`
	ScannerHits  int    `json:"scanner_path_hits,omitempty"`
	JA4          string `json:"ja4,omitempty"`
	UA           string `json:"user_agent,omitempty"`
	ASN          uint   `json:"asn,omitempty"`
	ASNOrg       string `json:"network,omitempty"`
	Country      string `json:"country,omitempty"`
	RDNS         string `json:"reverse_dns,omitempty"`
	FirstSeen    string `json:"first_seen"`
	LastSeen     string `json:"last_seen"`
}

// PoolJA4 is one TLS fingerprint in the pool.
type PoolJA4 struct {
	JA4         string `json:"ja4"`
	DistinctIPs int    `json:"distinct_addresses"`
	Requests    int    `json:"requests"`
	Serves      int    `json:"challenges_served"`
	Passes      int    `json:"challenges_passed"`
	UA          string `json:"user_agent,omitempty"`
}

// PoolUA is one user agent in the pool.
type PoolUA struct {
	UA          string `json:"user_agent"`
	DistinctIPs int    `json:"distinct_addresses"`
	Requests    int    `json:"requests"`
	Serves      int    `json:"challenges_served"`
	Passes      int    `json:"challenges_passed"`
}

// Pool is what the model is shown besides the engine's candidates.
type Pool struct {
	IPs  []PoolIP  `json:"addresses,omitempty"`
	JA4s []PoolJA4 `json:"fingerprints,omitempty"`
	UAs  []PoolUA  `json:"user_agents,omitempty"`
}

func (p Pool) Empty() bool { return len(p.IPs) == 0 && len(p.JA4s) == 0 && len(p.UAs) == 0 }

// hasIP / hasJA4: the structural check a nomination must pass.
func (p Pool) hasIP(ip string) bool {
	for _, r := range p.IPs {
		if r.IP == ip {
			return true
		}
	}
	return false
}

func (p Pool) hasJA4(ja4 string) bool {
	for _, r := range p.JA4s {
		if r.JA4 == ja4 {
			return true
		}
	}
	return false
}

// Pool sizes: enough to show the shape of the window, small enough that the
// request stays a few thousand tokens.
const (
	poolIPs  = 50
	poolJA4s = 20
	poolUAs  = 20
)

// BuildPool runs the three ranking queries and decorates the addresses.  gip
// may be nil.  Reverse DNS is bounded (see resolvePTRs) so a slow resolver
// delays the page by a couple of seconds at most, never minutes.
func BuildPool(ctx context.Context, conn *db.DB, gip *ipgeo.Reader, excl Exclusions, opt Options) (Pool, error) {
	opt = opt.resolved()
	var pool Pool

	q := `SELECT ip_address,
	        COUNT(*) AS total,
	        SUM(CASE WHEN phase='serve' THEN 1 ELSE 0 END) AS serves,
	        SUM(CASE WHEN phase IN ` + loadPhaseList + ` THEN 1 ELSE 0 END) AS loads,
	        SUM(CASE WHEN phase IN ` + powPhaseList + ` THEN 1 ELSE 0 END) AS pow_passed,
	        SUM(CASE WHEN phase IN ` + captchaPhaseList + ` THEN 1 ELSE 0 END) AS captcha_shown,
	        SUM(CASE WHEN phase IN ` + cookiePhaseList + ` THEN 1 ELSE 0 END) AS passes,
	        SUM(CASE WHEN ` + scannerCond() + ` THEN 1 ELSE 0 END) AS scanner_hits,
	        MIN(date_created), MAX(date_created),
	        COALESCE(MAX(ja4), ''), COALESCE(MAX(user_agent), '')
	      FROM unmask_event` + conn.EventDateIndexHint("w") + `
	      WHERE date_created > ` + conn.NowMinusMinutes(opt.WindowMinutes) + `
	      GROUP BY ip_address
	      ORDER BY total DESC
	      LIMIT ?`
	rows, err := conn.QueryContext(ctx, q, poolIPs)
	if err != nil {
		return pool, err
	}
	for rows.Next() {
		var r PoolIP
		var ipBytes []byte
		if err := rows.Scan(&ipBytes, &r.Requests, &r.Serves, &r.JSLoaded, &r.PowPassed, &r.CaptchaShown, &r.Passes, &r.ScannerHits,
			&r.FirstSeen, &r.LastSeen, &r.JA4, &r.UA); err != nil {
			rows.Close()
			return pool, err
		}
		r.IP = unpackIP(ipBytes)
		if skipIP(r.IP, excl) {
			continue
		}
		if len(r.UA) > maxUAForBundle {
			r.UA = r.UA[:maxUAForBundle]
		}
		if gip != nil {
			info := gip.LookupInfo(r.IP)
			r.ASN, r.ASNOrg, r.Country = info.ASN, info.ASNOrg, info.Country
		}
		pool.IPs = append(pool.IPs, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return pool, err
	}

	q = `SELECT ja4,
	        COUNT(DISTINCT ip_address) AS ips,
	        COUNT(*) AS total,
	        SUM(CASE WHEN phase='serve' THEN 1 ELSE 0 END) AS serves,
	        SUM(CASE WHEN phase IN ` + cookiePhaseList + ` THEN 1 ELSE 0 END) AS passes,
	        COALESCE(MAX(user_agent), '')
	      FROM unmask_event` + conn.EventDateIndexHint("w") + `
	      WHERE date_created > ` + conn.NowMinusMinutes(opt.WindowMinutes) + `
	        AND ja4 <> ''
	      GROUP BY ja4
	      ORDER BY ips DESC
	      LIMIT ?`
	rows, err = conn.QueryContext(ctx, q, poolJA4s)
	if err != nil {
		return pool, err
	}
	for rows.Next() {
		var r PoolJA4
		if err := rows.Scan(&r.JA4, &r.DistinctIPs, &r.Requests, &r.Serves, &r.Passes, &r.UA); err != nil {
			rows.Close()
			return pool, err
		}
		if excl.BannedJA4s[r.JA4] || excl.DismissedJA4[r.JA4] {
			continue
		}
		if len(r.UA) > maxUAForBundle {
			r.UA = r.UA[:maxUAForBundle]
		}
		pool.JA4s = append(pool.JA4s, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return pool, err
	}

	q = `SELECT COALESCE(user_agent, ''),
	        COUNT(DISTINCT ip_address) AS ips,
	        COUNT(*) AS total,
	        SUM(CASE WHEN phase='serve' THEN 1 ELSE 0 END) AS serves,
	        SUM(CASE WHEN phase IN ` + cookiePhaseList + ` THEN 1 ELSE 0 END) AS passes
	      FROM unmask_event` + conn.EventDateIndexHint("w") + `
	      WHERE date_created > ` + conn.NowMinusMinutes(opt.WindowMinutes) + `
	      GROUP BY user_agent
	      ORDER BY total DESC
	      LIMIT ?`
	rows, err = conn.QueryContext(ctx, q, poolUAs)
	if err != nil {
		return pool, err
	}
	for rows.Next() {
		var r PoolUA
		if err := rows.Scan(&r.UA, &r.DistinctIPs, &r.Requests, &r.Serves, &r.Passes); err != nil {
			rows.Close()
			return pool, err
		}
		if r.UA == "" {
			continue
		}
		if len(r.UA) > maxUAForBundle {
			r.UA = r.UA[:maxUAForBundle]
		}
		pool.UAs = append(pool.UAs, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return pool, err
	}

	ips := make([]string, 0, len(pool.IPs))
	for _, r := range pool.IPs {
		ips = append(ips, r.IP)
	}
	ptr := resolvePTRs(ctx, ips)
	for i := range pool.IPs {
		pool.IPs[i].RDNS = ptr[pool.IPs[i].IP]
	}
	return pool, nil
}

// --- reverse DNS, bounded ----------------------------------------------------

// LookupPTR is a variable so tests can stand in a resolver.
var LookupPTR = func(ctx context.Context, ip string) []string {
	names, err := net.DefaultResolver.LookupAddr(ctx, ip)
	if err != nil {
		return nil
	}
	return names
}

const (
	ptrTimeout     = 1500 * time.Millisecond
	ptrConcurrency = 16
	ptrCacheTTL    = time.Hour
)

type ptrEntry struct {
	name string
	at   time.Time
}

var ptrCache = struct {
	sync.Mutex
	m map[string]ptrEntry
}{m: map[string]ptrEntry{}}

// resolvePTRs returns the first PTR name per address (empty when there is
// none or the lookup did not answer in time).  Cached for an hour: the page is
// reloaded far more often than a PTR changes, and the cache is what keeps a
// reload from re-asking the resolver fifty questions.
func resolvePTRs(ctx context.Context, ips []string) map[string]string {
	out := make(map[string]string, len(ips))
	var todo []string
	now := time.Now()
	ptrCache.Lock()
	for _, ip := range ips {
		if e, ok := ptrCache.m[ip]; ok && now.Sub(e.at) < ptrCacheTTL {
			out[ip] = e.name
		} else {
			todo = append(todo, ip)
		}
	}
	ptrCache.Unlock()
	if len(todo) == 0 {
		return out
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, ptrConcurrency)
	for _, ip := range todo {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			lctx, cancel := context.WithTimeout(ctx, ptrTimeout)
			defer cancel()
			name := ""
			if names := LookupPTR(lctx, ip); len(names) > 0 {
				name = names[0]
			}
			mu.Lock()
			out[ip] = name
			mu.Unlock()
		}(ip)
	}
	wg.Wait()

	ptrCache.Lock()
	for _, ip := range todo {
		ptrCache.m[ip] = ptrEntry{name: out[ip], at: now}
	}
	// Keep the cache from growing without bound on a busy install.
	if len(ptrCache.m) > 5000 {
		for k, e := range ptrCache.m {
			if now.Sub(e.at) >= ptrCacheTTL {
				delete(ptrCache.m, k)
			}
		}
	}
	ptrCache.Unlock()
	return out
}
