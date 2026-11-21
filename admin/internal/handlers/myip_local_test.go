package handlers

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/ipgeo"
)

// TestMyIPNamesALocalAddress: the IP popover's lookup gives a local address
// the code the flag on its row carries (ipgeo.Local), database or none.  It
// used to leave private and loopback addresses out of the lookup, so the
// popover drew the "??" flag over a row that showed the local one.  A public
// address no database places stays without a country.
//
// And the word beside the flag says which local range: with only "private"
// and "loopback" to say, the popover called a link-local address and one in
// the carrier-NAT range "public" under the local flag.
func TestMyIPNamesALocalAddress(t *testing.T) {
	h := newTestHandler(t)
	h.IPGeo = ipgeo.Open("", "")

	get := func(addr string) myipResponse {
		t.Helper()
		// The reverse lookup is answered from the cache: no resolver is asked.
		rdnsMu.Lock()
		rdnsCache[net.ParseIP(addr).String()] = rdnsEntry{exp: time.Now().Add(rdnsTTL)}
		rdnsMu.Unlock()
		rr := httptest.NewRecorder()
		h.AdminMyIP(rr, httptest.NewRequest(http.MethodGet, "/unmask/admin/api/myip?ip="+url.QueryEscape(addr), nil))
		if rr.Code != http.StatusOK {
			t.Fatalf("%s: status %d (%s)", addr, rr.Code, rr.Body.String())
		}
		var resp myipResponse
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatalf("%s: %v (%s)", addr, err, rr.Body.String())
		}
		return resp
	}

	for _, c := range []struct {
		addr              string
		private, loopback bool
		kind              string
	}{
		{"127.0.0.1", false, true, "loopback"},
		{"::1", false, true, "loopback"},
		{"10.1.2.3", true, false, "private"},
		{"172.16.5.4", true, false, "private"},
		{"192.168.1.20", true, false, "private"},
		{"fd12:3456::1", true, false, "private"},
		// Local too, and never left out: link-local and the carrier-NAT range.
		{"169.254.10.1", false, false, "link-local"},
		{"fe80::1", false, false, "link-local"},
		{"100.64.0.9", false, false, "shared (CGNAT)"},
	} {
		r := get(c.addr)
		want := h.IPGeo.LookupInfo(c.addr)
		if r.Country != ipgeo.Local || r.CountryName == "" || r.CountryName != want.CountryName {
			t.Errorf("%s: country %q (%q), want %q (%q) as on its row", c.addr, r.Country, r.CountryName, ipgeo.Local, want.CountryName)
		}
		if r.IsPrivate != c.private || r.IsLoopback != c.loopback {
			t.Errorf("%s: private=%v loopback=%v, want %v and %v", c.addr, r.IsPrivate, r.IsLoopback, c.private, c.loopback)
		}
		if r.Type != c.kind {
			t.Errorf("%s: type %q under the local flag, want %q", c.addr, r.Type, c.kind)
		}
		if r.City != "" || r.ASN != 0 || r.Relay != "" {
			t.Errorf("%s: a local address has no city, network or relay: %+v", c.addr, r)
		}
	}

	if r := get("203.0.113.10"); r.Country != "" || r.CountryName != "" || r.Type != "public" {
		t.Errorf("a public address with no database: country %q (%q), type %q; want no country and public", r.Country, r.CountryName, r.Type)
	}
}
