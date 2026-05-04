// Package geoip: 任意の MaxMind .mmdb (GeoLite2-Country / GeoIP2-Country)
// から IP → ISO 3166-1 alpha-2 国コードを引く.
//
// 設計:
//   - DB が無いとき (= settings.GeoIP.MMDBPath 未指定 or open 失敗) は
//     Lookup() が "" を返す. 利用側は空なら国別表示を skip する.
//   - 1 IP / 1 lookup で in-memory cache (= dashboard で同 IP が重複頻出するため).
//   - thread-safe (= sync.Mutex で reader 保護).
package geoip

import (
	"net"
	"sync"

	"github.com/oschwald/maxminddb-golang"
)

type Reader struct {
	mu     sync.Mutex
	db     *maxminddb.Reader
	cache  map[string]string
	loaded bool
	path   string
}

// Open opens the mmdb at `path`. Empty path returns a no-op Reader (= Lookup
// always returns ""). This makes geoip optional: callers don't need to nil-check.
func Open(path string) *Reader {
	r := &Reader{cache: map[string]string{}, path: path}
	if path == "" {
		return r
	}
	db, err := maxminddb.Open(path)
	if err != nil {
		// open 失敗時は no-op として返す (= 起動止めない).
		return r
	}
	r.db = db
	r.loaded = true
	return r
}

// Close releases the underlying reader.
func (r *Reader) Close() {
	if r == nil || r.db == nil {
		return
	}
	_ = r.db.Close()
}

// Loaded reports whether the DB is ready (= 国別 chart を表示してよい指標).
func (r *Reader) Loaded() bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.loaded
}

// Lookup returns the ISO country code for `ip`.  Returns "" when:
//   - the reader was opened with empty path (= no DB)
//   - the IP can't be parsed
//   - the DB has no record for the IP
//   - any internal error
func (r *Reader) Lookup(ip string) string {
	if r == nil || r.db == nil {
		return ""
	}
	r.mu.Lock()
	if cc, ok := r.cache[ip]; ok {
		r.mu.Unlock()
		return cc
	}
	r.mu.Unlock()

	parsed := net.ParseIP(ip)
	if parsed == nil {
		return r.cacheSet(ip, "")
	}
	var rec struct {
		Country struct {
			ISOCode string `maxminddb:"iso_code"`
		} `maxminddb:"country"`
	}
	if err := r.db.Lookup(parsed, &rec); err != nil {
		return r.cacheSet(ip, "")
	}
	return r.cacheSet(ip, rec.Country.ISOCode)
}

// LookupBytes is the binary-IP variant for unmask_event rows where
// ip_address は packed bytes で格納されている.
func (r *Reader) LookupBytes(b []byte) string {
	switch len(b) {
	case 4:
		return r.Lookup(net.IP(b).To4().String())
	case 16:
		return r.Lookup(net.IP(b).To16().String())
	}
	return ""
}

func (r *Reader) cacheSet(key, val string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cache[key] = val
	return val
}
