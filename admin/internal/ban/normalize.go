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

// altSpelling is the other text an IPv4 address reaches a ban in:
// "::ffff:203.0.113.5" for "203.0.113.5" and the reverse, as nginx and netip
// both print a v4-mapped address.  "" for an address with one spelling (an
// IPv6 one), a prefix, or what does not parse.
//
// An IPv4 client is "203.0.113.5" on an IPv4 socket and "::ffff:203.0.113.5"
// on an IPv6 socket that takes both families, or where a proxy wrote it so.
// A single-address row is matched by its text on both wires, so a ban typed
// as the one did not hold on the client seen as the other -- while a prefix
// row, which is matched as an address, did (addrInPrefix).  The module looks
// a client up under both (ngx_unmask_ban_alt_ip), and so does the mirror.
func altSpelling(ip string) string {
	if strings.IndexByte(ip, '/') >= 0 {
		return ""
	}
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return ""
	}
	switch {
	case a.Is4In6():
		return a.Unmap().String()
	case a.Is4():
		return netip.AddrFrom16(a.As16()).String()
	}
	return ""
}

// sameAddr: whether the row address rowIP names the client address ip, in
// either spelling of it.
func sameAddr(rowIP, ip string) bool {
	if rowIP == "" {
		return false
	}
	return rowIP == ip || rowIP == altSpelling(ip)
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
