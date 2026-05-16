// /admin/api/myip — returns information about a single IP.
//
// rDNS / private-IP classification / IP family / GeoIP (Country/City/ASN, optional).
// rDNS is cached in-memory for 10 minutes (= dashboards hit the same IP repeatedly).
package handlers

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type myipResponse struct {
	IP              string   `json:"ip"`
	Family          string   `json:"family"` // "v4" / "v6"
	IsPrivate       bool     `json:"is_private"`
	IsLoopback      bool     `json:"is_loopback"`
	ReverseDNS      []string `json:"reverse_dns,omitempty"`
	ReverseDNSError string   `json:"reverse_dns_error,omitempty"` // resolver errors etc.  Other fields are still populated.
	Country         string   `json:"country,omitempty"`           // ISO code (e.g. "JP")
	CountryName     string   `json:"country_name,omitempty"`      // English name (e.g. "Japan")
	City            string   `json:"city,omitempty"`              // English city name (e.g. "Tokyo")
	ASN             uint     `json:"asn,omitempty"`               // e.g. 4713
	ASNOrg          string   `json:"asn_org,omitempty"`           // e.g. "NTT Communications"
	Error           string   `json:"error,omitempty"`             // fatal error (= invalid IP / missing required param)
}

// In-memory cache for rDNS lookups.
//   - both hit and miss (= no record) are cached (= so misses are not re-looked-up)
//   - TTL 10 min.  When the entry count exceeds 4096, flush everything (= LRU is overkill at this size).
type rdnsEntry struct {
	names []string
	errs  string
	exp   time.Time
}

const (
	rdnsTTL        = 10 * time.Minute
	rdnsMaxEntries = 4096
)

var (
	rdnsMu    sync.RWMutex
	rdnsCache = map[string]rdnsEntry{}
)

// lookupRDNSCached: pass the outer ctx with its timeout (= e.g. 800ms).
// The returned names are trimSuffix-ed; errs is the error string we surface to the user.
func lookupRDNSCached(ctx context.Context, ip string) ([]string, string) {
	rdnsMu.RLock()
	if e, ok := rdnsCache[ip]; ok && time.Now().Before(e.exp) {
		rdnsMu.RUnlock()
		return e.names, e.errs
	}
	rdnsMu.RUnlock()

	// miss → real lookup
	resolver := net.Resolver{}
	names, err := resolver.LookupAddr(ctx, ip)
	e := rdnsEntry{exp: time.Now().Add(rdnsTTL)}
	if err == nil {
		out := make([]string, 0, len(names))
		for _, n := range names {
			out = append(out, strings.TrimSuffix(n, "."))
		}
		e.names = out
	} else if !errors.Is(err, context.DeadlineExceeded) {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && !dnsErr.IsNotFound {
			e.errs = err.Error()
		}
	}

	// cache set (= do not cache timeout errors. they are transient.)
	if !errors.Is(err, context.DeadlineExceeded) {
		rdnsMu.Lock()
		if len(rdnsCache) > rdnsMaxEntries {
			rdnsCache = map[string]rdnsEntry{}
		}
		rdnsCache[ip] = e
		rdnsMu.Unlock()
	}
	return e.names, e.errs
}

// AdminMyIP: GET {base}/admin/api/myip?ip=1.2.3.4
func (h *Handler) AdminMyIP(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("ip")
	if q == "" {
		writeJSON(w, http.StatusBadRequest, myipResponse{Error: "ip parameter required"})
		return
	}
	ip := net.ParseIP(q)
	if ip == nil {
		writeJSON(w, http.StatusBadRequest, myipResponse{Error: "invalid ip"})
		return
	}

	resp := myipResponse{
		IP:         ip.String(),
		Family:     "v6",
		IsPrivate:  ip.IsPrivate(),
		IsLoopback: ip.IsLoopback(),
	}
	if ip.To4() != nil {
		resp.Family = "v4"
	}

	// Skip GeoIP / ASN lookups for loopback / private ranges.
	if !resp.IsLoopback && !resp.IsPrivate && h.GeoIP != nil {
		info := h.GeoIP.LookupInfo(ip.String())
		resp.Country = info.Country
		resp.CountryName = info.CountryName
		resp.City = info.City
		resp.ASN = info.ASN
		resp.ASNOrg = info.ASNOrg
	}

	// rDNS: 10-minute cache (= when the dashboard hammers the same IP, only look up once).
	ctx, cancel := context.WithTimeout(r.Context(), 800*time.Millisecond)
	defer cancel()
	names, errs := lookupRDNSCached(ctx, ip.String())
	resp.ReverseDNS = names
	if errs != "" {
		// An rDNS lookup failure is not a reason to drop the other fields
		// (= GeoIP / family).  Carry the error in its own field so the JS
		// side can render "rDNS: (unavailable)".
		resp.ReverseDNSError = errs
	}

	writeJSON(w, http.StatusOK, resp)
}
