package ban

import (
	"net/netip"
	"strings"
)

// normalizeIP returns an address in the text form nginx hands the module as
// $remote_addr (inet_ntop, RFC 5952): hexadecimal in lower case, the longest
// run of zero groups as "::", a v4-mapped address as "::ffff:a.b.c.d".  The
// ban file is matched by string equality on both wires, so "2001:DB8::1" and
// "2001:0db8:0:0:0:0:0:1" typed into a ban must become the one spelling the
// request carries.  A prefix ("2001:db8:1:2::/64", an address-wide ban) is
// masked and written the same way.  What does not parse as either is
// returned trimmed, as it was: the file then carries what the operator
// typed, which is at worst a line that matches nothing.
func normalizeIP(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return s
	}
	if strings.IndexByte(s, '/') >= 0 {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return s
		}
		return p.Masked().String()
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return s
	}
	return a.String()
}

// parsePrefixKey reads a ban key's ip field as a prefix when it is one
// ("203.0.113.0/24", "2001:db8:1:2::/64"); ok is false for a single address
// or anything else.
func parsePrefixKey(ip string) (netip.Prefix, bool) {
	if strings.IndexByte(ip, '/') < 0 {
		return netip.Prefix{}, false
	}
	p, err := netip.ParsePrefix(ip)
	if err != nil {
		return netip.Prefix{}, false
	}
	return p.Masked(), true
}

// addrInPrefix reports whether the address text ip lies in p.  A v4-mapped
// address is unmapped first so "::ffff:203.0.113.5" lies in 203.0.113.0/24
// the way nginx's dual-stack listener would present it.
func addrInPrefix(p netip.Prefix, ip string) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	if a.Is4In6() && p.Addr().Is4() {
		a = a.Unmap()
	}
	return p.Contains(a)
}
