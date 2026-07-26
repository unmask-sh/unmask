// Package ipgeo: optionally read MaxMind-format .mmdb files (DB-IP Lite /
// GeoLite2-Country / -City / -ASN) to resolve IP → country / city / ASN.
//
// Design:
//   - When the DB is absent (= path unset / open failed), Lookup() /
//     LookupInfo() return empty (= "" / Info{}).  Callers don't need nil-checks.
//   - Cache each (IP, lookup) in memory (= the dashboard hits the same IP repeatedly).
//   - thread-safe (= sync.Mutex guards both the reader and the cache).
//   - Country DB / City DB are interchangeable: with a City DB you get both
//     country + city.  Read the record's `country.iso_code` and `city.names.en`.
package ipgeo

import (
	"net"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/oschwald/maxminddb-golang"
)

// Info: geographic + network info associated with an IP.
// Fields not resolved come back as the zero value (= "" / 0).
type Info struct {
	Country     string // ISO 3166-1 alpha-2 (e.g. "JP")
	CountryName string // English name (e.g. "Japan")
	City        string // English city name (e.g. "Tokyo").  Only populated with a City DB
	ASN         uint   // Autonomous System Number (e.g. 4713)
	ASNOrg      string // ASN organization (e.g. "NTT Communications")
}

type Reader struct {
	mu        sync.Mutex
	geoDB     *maxminddb.Reader // Country or City DB
	asnDB     *maxminddb.Reader // ASN DB
	cache     map[string]Info
	overrides map[string]Info // test-only IP -> Info override.  populated by Open() from env.
	geoPath   string
	asnPath   string
	loaded    bool // whether geoDB opened OR overrides populated
	asnReady  bool // whether asnDB opened

	// asnIdx is the lazily-built org/ASN suggestion index (nil until the first
	// SuggestASN call walks asnDB).  Immutable once built; discarded on Reload.
	asnIdx *asnSuggestIndex
}

// Open opens the IP-geo DBs at the given paths.  Both are optional;
// passing "" for either disables that lookup.
//
// Reads the env var `UNMASK_TEST_GEO_OVERRIDE` (= comma-separated
// `<ip>:<country>` pairs) to seed the override table.  Used by the e2e
// harness so country-dependent axes (= geo rules) can be tested without
// bundling a real GeoLite2 mmdb in the test container.  Unset in production.
func Open(geoPath, asnPath string) *Reader {
	r := &Reader{
		cache:   map[string]Info{},
		geoPath: geoPath,
		asnPath: asnPath,
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

// Close releases both readers.
func (r *Reader) Close() {
	if r == nil {
		return
	}
	if r.geoDB != nil {
		_ = r.geoDB.Close()
	}
	if r.asnDB != nil {
		_ = r.asnDB.Close()
	}
}

// Loaded reports whether the geo DB is ready (= used to decide whether to show the per-country chart).
func (r *Reader) Loaded() bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.loaded
}

// ASNLoaded reports whether the ASN DB is ready.
func (r *Reader) ASNLoaded() bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.asnReady
}

// Reload: swap the mmdb path while keeping the existing reader.
// Called when the path changes via the settings UI (= no server restart needed).
// On failure (= file cannot open), reset the corresponding DB to nil and loaded=false.
// If the path is unchanged, do nothing (= avoid a needless close).
func (r *Reader) Reload(geoPath, asnPath string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()

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
	r.cache = map[string]Info{}
}

// Lookup returns the ISO country code only (= compatibility API).
// Still called as-is from the per-country chart.
func (r *Reader) Lookup(ip string) string {
	return r.LookupInfo(ip).Country
}

// LookupInfo returns full info for the given IP string.  Empty Info{} if
// no DB is loaded or the IP isn't found.
func (r *Reader) LookupInfo(ip string) Info {
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
	if r.geoDB == nil && r.asnDB == nil {
		return Info{}
	}
	r.mu.Lock()
	if info, ok := r.cache[ip]; ok {
		r.mu.Unlock()
		return info
	}
	r.mu.Unlock()

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
		}
		if err := r.geoDB.Lookup(parsed, &rec); err == nil {
			info.Country = rec.Country.ISOCode
			if rec.Country.Names != nil {
				info.CountryName = rec.Country.Names["en"]
			}
			if rec.City.Names != nil {
				info.City = rec.City.Names["en"]
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

func (r *Reader) cacheSet(key string, val Info) Info {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cache[key] = val
	return val
}
