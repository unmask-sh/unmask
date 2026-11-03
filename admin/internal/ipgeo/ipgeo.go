// Package ipgeo: optionally read MaxMind-format .mmdb files (DB-IP Lite /
// GeoLite2-Country / -City / -ASN) to resolve IP → country / city / ASN.
//
// Design:
//   - When the DB is absent (= path unset / open failed), Lookup() /
//     LookupInfo() return empty (= "" / Info{}).  Callers don't need nil-checks.
//   - Cache each (IP, lookup) in memory (= the dashboard hits the same IP
//     repeatedly), under a ceiling: two generations of cacheGenSize entries.
//   - thread-safe: lookups read the databases under a read lock that Reload
//     and Close take exclusively, so a database is never closed under a
//     lookup; the cache has a lock of its own.
//   - Country DB / City DB are interchangeable: with a City DB you get both
//     country + city.  Read the record's `country.iso_code` and `city.names.en`.
package ipgeo

import (
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/oschwald/maxminddb-golang"

	"github.com/unmask-sh/unmask/admin/internal/relay"
)

// Info: geographic + network info associated with an IP.
// Fields not resolved come back as the zero value (= "" / 0).
type Info struct {
	Country     string // ISO 3166-1 alpha-2 (e.g. "JP")
	CountryName string // English name (e.g. "Japan")
	City        string // English city name (e.g. "Tokyo").  Only populated with a City DB
	ASN         uint   // Autonomous System Number (e.g. 4713)
	ASNOrg      string // ASN organization (e.g. "NTT Communications")
	// Lat / Lon: the record's coordinates, present only with a City DB
	// (HasCoords); a Country DB places nothing.
	Lat, Lon  float64
	HasCoords bool
	// Relay: the shared-egress relay the address belongs to (relay package
	// id, e.g. "apple-private-relay"), "" for none.  Country is then the one
	// the relay gives the address; CountryDB keeps the database's when the
	// two differ, and the database's city and coordinates are dropped with
	// it (they place the relay's address, not its users).
	Relay     string
	CountryDB string
}

type Reader struct {
	// mu guards the databases and what describes them (the paths and the
	// loaded flags).  A lookup holds it shared for the duration of its
	// reads; Reload and Close hold it exclusively, so the file a lookup is
	// reading is never unmapped under it (maxminddb's Close unmaps).
	mu        sync.RWMutex
	geoDB     *maxminddb.Reader // Country or City DB
	asnDB     *maxminddb.Reader // ASN DB
	overrides map[string]Info   // test-only IP -> Info override.  populated by Open() from env.
	geoPath   string
	asnPath   string
	loaded    bool // whether geoDB opened OR overrides populated
	asnReady  bool // whether asnDB opened
	closed    bool // Close was called: a Reload after it opens nothing

	// The answer cache, under its own lock (a lookup writes it while
	// holding mu shared).  Two generations: cur fills up to genSize entries,
	// then becomes prev and a fresh cur starts; prev is dropped when cur
	// fills again.  An address asked for repeatedly is found in prev and
	// moved up, so the hot set survives the turnover; an address seen once
	// leaves within two generations.  The memory is bounded by 2*genSize
	// entries whatever the traffic -- it used to grow by every distinct
	// address the process ever saw, which on a bot-heavy install is
	// hundreds of megabytes.
	cacheMu   sync.Mutex
	cacheCur  map[string]Info
	cachePrev map[string]Info
	genSize   int

	// asnIdx is the lazily-built org/ASN suggestion index (nil until the first
	// SuggestASN call walks asnDB).  Immutable once built; discarded on Reload.
	// Guarded by idxMu, which is taken before mu (Reload takes both in that
	// order; the build holds idxMu and reads asnDB under mu shared).
	idxMu  sync.Mutex
	asnIdx *asnSuggestIndex
}

// cacheGenSize is the number of answers one cache generation holds.  An
// entry is the address string, the names a City/ASN database gives and the
// coordinates -- a few hundred bytes -- so two full generations stay in
// the tens of megabytes.  The per-address popover and the per-minute
// country buckets ask for the same addresses within minutes, which is the
// reuse the cache is for; a crawl across a large address pool mostly misses
// it and should not be remembered.
const cacheGenSize = 32768

// Open opens the IP-geo DBs at the given paths.  Both are optional;
// passing "" for either disables that lookup.
//
// Reads the env var `UNMASK_TEST_GEO_OVERRIDE` (= comma-separated
// `<ip>:<country>` pairs) to seed the override table.  Used by the e2e
// harness so country-dependent axes (= geo rules) can be tested without
// bundling a real GeoLite2 mmdb in the test container.  Unset in production.
func Open(geoPath, asnPath string) *Reader {
	r := &Reader{
		cacheCur: map[string]Info{},
		genSize:  cacheGenSize,
		geoPath:  geoPath,
		asnPath:  asnPath,
	}
	if geoPath != "" {
		if db, err := maxminddb.Open(geoPath); err == nil {
			r.geoDB = db
			r.loaded = true
		}
	}
	if asnPath != "" {
		if db, err := maxminddb.Open(asnPath); err == nil {
			r.asnDB = db
			r.asnReady = true
		}
	}
	if env := strings.TrimSpace(os.Getenv("UNMASK_TEST_GEO_OVERRIDE")); env != "" {
		r.overrides = map[string]Info{}
		for _, pair := range strings.Split(env, ",") {
			// <ip>:<country>[:<asn>].  The optional 3rd field seeds Info.ASN so the
			// e2e harness can exercise the roaming ASN veto without bundling a real
			// ASN mmdb; any override carrying an ASN also flips asnReady on (the
			// veto is gated on ASNLoaded()).  country is a 2-letter ISO code, so
			// the extra ":" never collides with it.
			parts := strings.SplitN(strings.TrimSpace(pair), ":", 3)
			if len(parts) < 2 {
				continue
			}
			ip := strings.TrimSpace(parts[0])
			cc := strings.ToUpper(strings.TrimSpace(parts[1]))
			if ip == "" || len(cc) != 2 {
				continue
			}
			info := Info{Country: cc, CountryName: cc}
			if len(parts) == 3 {
				if asn, err := strconv.ParseUint(strings.TrimSpace(parts[2]), 10, 32); err == nil && asn > 0 {
					info.ASN = uint(asn)
					r.asnReady = true
				}
			}
			r.overrides[ip] = info
		}
		if len(r.overrides) > 0 {
			r.loaded = true
		}
	}
	return r
}

// Close releases both readers.  Taken exclusively, so a lookup in flight
// finishes on the open file first; a lookup after it answers empty.
func (r *Reader) Close() {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.geoDB != nil {
		_ = r.geoDB.Close()
		r.geoDB = nil
	}
	if r.asnDB != nil {
		_ = r.asnDB.Close()
		r.asnDB = nil
	}
	r.loaded = len(r.overrides) > 0
	r.asnReady = false
	r.closed = true
}

// Loaded reports whether the geo DB is ready (= used to decide whether to show the per-country chart).
func (r *Reader) Loaded() bool {
	if r == nil {
		return false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.loaded
}

// ASNLoaded reports whether the ASN DB is ready.
func (r *Reader) ASNLoaded() bool {
	if r == nil {
		return false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.asnReady
}

// Reload: swap the mmdb path while keeping the existing reader.
// Called when the path changes via the settings UI (= no server restart needed).
// On failure (= file cannot open), reset the corresponding DB to nil and loaded=false.
// If the path is unchanged, do nothing (= avoid a needless close).
//
// Exclusive against the lookups: one that is reading the old file finishes
// before it is closed, and the ones that arrive meanwhile wait (an open is
// a map of the file, microseconds) and read the new one.
func (r *Reader) Reload(geoPath, asnPath string) {
	if r == nil {
		return
	}
	r.idxMu.Lock()
	defer r.idxMu.Unlock()
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		// The daemon is shutting down (a first-run fetch that lands after
		// it): nothing to open.
		return
	}

	if geoPath != r.geoPath {
		if r.geoDB != nil {
			_ = r.geoDB.Close()
			r.geoDB = nil
		}
		r.loaded = false
		r.geoPath = geoPath
		if geoPath != "" {
			if db, err := maxminddb.Open(geoPath); err == nil {
				r.geoDB = db
				r.loaded = true
			}
		}
	}
	if asnPath != r.asnPath {
		if r.asnDB != nil {
			_ = r.asnDB.Close()
			r.asnDB = nil
		}
		r.asnReady = false
		r.asnPath = asnPath
		r.asnIdx = nil // stale for the new DB; rebuilt on next SuggestASN
		if asnPath != "" {
			if db, err := maxminddb.Open(asnPath); err == nil {
				r.asnDB = db
				r.asnReady = true
			}
		}
	}
	// Discard the cache on a path change (= results may change with a new DB).
	r.cacheMu.Lock()
	r.cacheCur, r.cachePrev = map[string]Info{}, nil
	r.cacheMu.Unlock()
}

// Lookup returns the ISO country code only (= compatibility API).
// Still called as-is from the per-country chart.
func (r *Reader) Lookup(ip string) string {
	return r.LookupInfo(ip).Country
}

// LookupInfo returns full info for the given IP string.  Empty Info{} if
// no DB is loaded or the IP isn't found.  An address a relay lists (relay
// package) carries the relay's country -- see Info.Relay.  A local address
// is Local, with no database asked: see IsLocal.
func (r *Reader) LookupInfo(ip string) Info {
	if IsLocal(ip) {
		return Info{Country: Local, CountryName: localName}
	}
	return withRelay(ip, r.lookupDB(ip))
}

// Local is the country code of an address that is not on the public
// Internet: a private network's (10/8, 172.16/12, 192.168/16, fc00::/7),
// loopback, link-local, the carrier-NAT range 100.64/10, the unspecified
// address.  No database places such an address, and the admin used to show
// it as a country it could not tell, like a public address outside the
// database -- the same "??".  "XL" is in ISO 3166-1's user-assigned range
// (AA, QM-QZ, XA-XZ, ZZ), which no country database hands out, so it fits
// the two-letter columns and the flag files (xl.png) like any code.  It is
// not in Countries: a country rule on it would match nothing in nginx.
const Local = "XL"

const localName = "Local network"

// IsLocal reports whether ip is an address no country database can place:
// one of the local ranges Local stands for.  Decided from the address alone,
// so it holds with no database loaded, and before the relay list, which
// only ever names public addresses.
func IsLocal(ip string) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	a = a.Unmap()
	if a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || a.IsUnspecified() {
		return true
	}
	// 100.64.0.0/10, the shared address space of carrier-grade NAT (and of
	// overlay networks that borrow it): never routed on the public Internet.
	if a.Is4() {
		b := a.As4()
		return b[0] == 100 && b[1]&0xc0 == 64
	}
	return false
}

// withRelay applies the relay list to a database answer.  The table is
// looked up per call rather than cached with the answer, so a new list takes
// effect without clearing the cache.
func withRelay(ip string, info Info) Info {
	t := relay.Active()
	if t == nil {
		return info
	}
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return info
	}
	h, ok := t.Lookup(a)
	if !ok {
		return info
	}
	info.Relay = h.Relay
	// A relay that gives no country (a cloud proxy whose addresses sit where
	// the database says) only names itself; the database's answer stands.
	if h.Country != "" && info.Country != h.Country {
		info.CountryDB = info.Country
		info.Country = h.Country
		info.CountryName = CountryName(h.Country)
		info.City = ""
		info.Lat, info.Lon, info.HasCoords = 0, 0, false
	}
	return info
}

// lookupDB is LookupInfo without the relay list: what the databases say.
func (r *Reader) lookupDB(ip string) Info {
	if r == nil {
		return Info{}
	}
	// test-only override table wins over mmdb (= seeded from
	// UNMASK_TEST_GEO_OVERRIDE in Open).
	if r.overrides != nil {
		if info, ok := r.overrides[ip]; ok {
			return info
		}
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.geoDB == nil && r.asnDB == nil {
		return Info{}
	}
	if info, ok := r.cacheGet(ip); ok {
		return info
	}

	parsed := net.ParseIP(ip)
	if parsed == nil {
		return r.cacheSet(ip, Info{})
	}
	info := Info{}

	if r.geoDB != nil {
		// Union record that reads from either Country DB or City DB.
		// City DB has country + city.  Country DB has only country (city is zero).
		var rec struct {
			Country struct {
				ISOCode string            `maxminddb:"iso_code"`
				Names   map[string]string `maxminddb:"names"`
			} `maxminddb:"country"`
			City struct {
				Names map[string]string `maxminddb:"names"`
			} `maxminddb:"city"`
			Location struct {
				Lat float64 `maxminddb:"latitude"`
				Lon float64 `maxminddb:"longitude"`
			} `maxminddb:"location"`
		}
		if err := r.geoDB.Lookup(parsed, &rec); err == nil {
			info.Country = rec.Country.ISOCode
			if rec.Country.Names != nil {
				info.CountryName = rec.Country.Names["en"]
			}
			if rec.City.Names != nil {
				info.City = rec.City.Names["en"]
			}
			if rec.Location.Lat != 0 || rec.Location.Lon != 0 {
				info.Lat, info.Lon, info.HasCoords = rec.Location.Lat, rec.Location.Lon, true
			}
		}
	}
	if r.asnDB != nil {
		var rec struct {
			ASN uint   `maxminddb:"autonomous_system_number"`
			Org string `maxminddb:"autonomous_system_organization"`
		}
		if err := r.asnDB.Lookup(parsed, &rec); err == nil {
			info.ASN = rec.ASN
			info.ASNOrg = rec.Org
		}
	}
	return r.cacheSet(ip, info)
}

// LookupASN resolves ONLY the network, for callers that walk a lot of addresses
// once each -- the hunt ASN ranking resolves every distinct IP in its window
// (111k over 24h on a production install).
//
// LookupInfo is the wrong tool at that scale, in two ways that compound: it
// also queries the country DB and decodes its name maps, which this caller
// throws away, and it writes every answer into the shared cache.  That cache
// pays off for the per-IP popover, where the same few addresses are asked for
// repeatedly; here every entry is single-use, so it buys nothing while adding
// two mutex round-trips per address and growing an unbounded map by the size of
// the window on every page load.  Measured across a 24h window, going through
// LookupInfo cost about a second of the page.
//
// The test override table is still honored, so a seeded ASN behaves the same
// through either entry point.
func (r *Reader) LookupASN(ip string) (uint, string) {
	if r == nil {
		return 0, ""
	}
	if r.overrides != nil {
		if info, ok := r.overrides[ip]; ok {
			return info.ASN, info.ASNOrg
		}
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.asnDB == nil {
		return 0, ""
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return 0, ""
	}
	var rec struct {
		ASN uint   `maxminddb:"autonomous_system_number"`
		Org string `maxminddb:"autonomous_system_organization"`
	}
	if err := r.asnDB.Lookup(parsed, &rec); err != nil {
		return 0, ""
	}
	return rec.ASN, rec.Org
}

// LookupBytes is for packed bytes (= unmask_event.ip_address).  Used by the per-country chart aggregation.
func (r *Reader) LookupBytes(b []byte) string {
	switch len(b) {
	case 4:
		return r.Lookup(net.IP(b).To4().String())
	case 16:
		return r.Lookup(net.IP(b).To16().String())
	}
	return ""
}

// cacheGet finds a cached answer, moving one found in the older generation
// up to the current so it outlives the next turnover.
func (r *Reader) cacheGet(key string) (Info, bool) {
	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()
	if info, ok := r.cacheCur[key]; ok {
		return info, true
	}
	if info, ok := r.cachePrev[key]; ok {
		delete(r.cachePrev, key)
		r.cacheCur[key] = info
		return info, true
	}
	return Info{}, false
}

// cacheSet records an answer; a full current generation is retired to prev
// (the previous prev, and every address only it held, is dropped).
func (r *Reader) cacheSet(key string, val Info) Info {
	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()
	if len(r.cacheCur) >= r.genSize {
		r.cachePrev = r.cacheCur
		r.cacheCur = make(map[string]Info, r.genSize/4)
	}
	r.cacheCur[key] = val
	return val
}

// cacheLen is the number of answers held, for the tests.
func (r *Reader) cacheLen() int {
	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()
	return len(r.cacheCur) + len(r.cachePrev)
}
