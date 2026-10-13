package ipgeo

import (
	"net"
	"net/netip"
	"strings"

	"github.com/oschwald/maxminddb-golang"

	"github.com/unmask-sh/unmask/admin/internal/relay"
)

// The render's view of the relay egress list (relay package).  nginx's geo
// blocks take the most specific network that holds an address, so the list
// is written into them at the specificity it needs to win: a database network
// that lies inside a relay prefix is written -- or left out -- as the relay
// says, and a relay prefix inside a larger database network gets a line of
// its own.

// prefixOf converts a database network to a netip.Prefix (IPv4 unmapped).
func prefixOf(n *net.IPNet) (netip.Prefix, bool) {
	a, ok := netip.AddrFromSlice(n.IP)
	if !ok {
		return netip.Prefix{}, false
	}
	ones, bits := n.Mask.Size()
	if a.Is4In6() {
		a = a.Unmap()
		if bits == 128 {
			ones -= 96
		}
	}
	p, err := a.Prefix(ones)
	return p, err == nil
}

// relayOwner reports the relay prefix a database network lies inside, if any.
func relayOwner(t *relay.Table, n *net.IPNet) (netip.Prefix, relay.Hit, bool) {
	if t == nil {
		return netip.Prefix{}, relay.Hit{}, false
	}
	p, ok := prefixOf(n)
	if !ok {
		return netip.Prefix{}, relay.Hit{}, false
	}
	sp, h, hit := t.LookupPrefix(p.Addr())
	if !hit || sp.Bits() > p.Bits() {
		return netip.Prefix{}, relay.Hit{}, false
	}
	return sp, h, true
}

// enclosing looks up the database network that holds relay prefix p and is
// larger than it -- the one the prefix needs a line of its own inside.
func enclosing(db *maxminddb.Reader, p netip.Prefix, rec any) bool {
	n, ok, err := db.LookupNetwork(net.IP(p.Addr().AsSlice()), rec)
	if err != nil || !ok {
		return false
	}
	np, okp := prefixOf(n)
	return okp && np.Bits() < p.Bits()
}

// relayCountryLines finishes the country walk: every relay prefix that a
// country rule has to see as the relay's -- because the relay's country is
// ruled, or the database's network around or inside it is -- and that the
// walk has not written already.
func relayCountryLines(b *strings.Builder, db *maxminddb.Reader, t *relay.Table, wanted map[string]bool, written map[netip.Prefix]bool, innerRuled map[netip.Prefix]bool) {
	t.Each(func(p netip.Prefix, h relay.Hit) {
		if written[p] {
			return
		}
		ruled := wanted[h.Country] || innerRuled[p]
		if !ruled {
			var rec struct {
				Country struct {
					ISOCode string `maxminddb:"iso_code"`
				} `maxminddb:"country"`
			}
			ruled = enclosing(db, p, &rec) && wanted[rec.Country.ISOCode]
		}
		if ruled {
			b.WriteString("    " + p.String() + " " + h.Country + ";\n")
		}
	})
}

// relayASNLines finishes an ASN walk: every relay prefix inside a network the
// walk wrote gets the empty value, which no rule names -- so the address is
// judged as an unlisted network, not as the network the relay sits in.
func relayASNLines(b *strings.Builder, db *maxminddb.Reader, t *relay.Table, matched func(asn uint, org string) bool) {
	t.Each(func(p netip.Prefix, _ relay.Hit) {
		var rec struct {
			ASN uint   `maxminddb:"autonomous_system_number"`
			Org string `maxminddb:"autonomous_system_organization"`
		}
		if enclosing(db, p, &rec) && matched(rec.ASN, rec.Org) {
			b.WriteString(geoLine(p.String(), ""))
		}
	})
}
