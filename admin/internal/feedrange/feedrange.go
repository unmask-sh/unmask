// Package feedrange says how wide an address range that arrives in a feed
// may be.
//
// The daemon pulls three lists of ranges and acts on each without asking:
// the crawlers' published ranges, whose clients pass without a challenge;
// the CDNs' egress ranges, whose word for the client's address is believed;
// and the relays' egress ranges, whose clients are bound and counted as a
// relay's.  The documents are signed, and a signature says who wrote a
// document, not that it is right: a source that listed 0.0.0.0/0 -- a
// vendor's mistake, a hub's, a file imported by hand -- would have switched
// the feature on for every address there is, and the share-of-the-list guard
// (a source may not shrink below half) reads a list that grew by one row as
// healthy.
package feedrange

import (
	"fmt"
	"net/netip"
)

// MinBits4 and MinBits6: the shortest prefix a feed may carry.  A /8 is the
// largest block of IPv4 any one holder was ever given, and no operator holds
// an IPv6 block wider than a /16 (the widest are the /19s and /20s of a few
// carriers; a /12 is a whole registry's).  The ranges vendors publish are
// far narrower than either: nothing real is refused, and what is refused is
// not a range.
const (
	MinBits4 = 8
	MinBits6 = 16
)

// mapped4 is the block that stands for IPv4 inside IPv6 (::ffff:a.b.c.d).
var mapped4 = netip.MustParsePrefix("::ffff:0:0/96")

// TooWide reports whether p covers more addresses than a feed may name: an
// IPv4 prefix shorter than MinBits4, an IPv6 prefix shorter than MinBits6,
// and an IPv6 prefix that takes in that much of IPv4 through the v4-mapped
// block -- ::ffff:0:0/96 is every IPv4 address, and so is any IPv6 prefix
// that holds it.
func TooWide(p netip.Prefix) bool {
	if !p.IsValid() {
		return false
	}
	p = p.Masked()
	a := p.Addr()
	switch {
	case a.Is4():
		return p.Bits() < MinBits4
	case p.Bits() < MinBits6:
		return true
	case p.Bits() <= mapped4.Bits():
		return p.Contains(mapped4.Addr())
	case mapped4.Contains(a):
		return p.Bits()-mapped4.Bits() < MinBits4
	}
	return false
}

// Check returns an error that names s when it parses as a prefix that is
// TooWide, and nil otherwise: what does not parse, and a single address, are
// for the caller's own reading.
func Check(s string) error {
	p, err := netip.ParsePrefix(s)
	if err != nil || !TooWide(p) {
		return nil
	}
	return fmt.Errorf("%s is wider than any range a feed may carry (the floor is /%d, and /%d for IPv6)", p.Masked(), MinBits4, MinBits6)
}
