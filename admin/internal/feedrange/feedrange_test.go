package feedrange

import (
	"net/netip"
	"strings"
	"testing"
)

func TestTooWide(t *testing.T) {
	for s, want := range map[string]bool{
		// Everything, and the widths below the floor.
		"0.0.0.0/0": true, "128.0.0.0/1": true, "10.0.0.0/7": true, "0.0.0.0/7": true,
		"::/0": true, "2000::/3": true, "2400::/12": true, "2001::/15": true,
		// The floor itself and narrower: a holder's own block.
		"17.0.0.0/8": false, "10.0.0.0/8": false, "104.16.0.0/13": false, "192.0.2.0/24": false, "203.0.113.7/32": false,
		"2001::/16": false, "2a06:98c0::/29": false, "2001:db8::/32": false, "2001:db8::1/128": false,
		// IPv4 by way of IPv6: the v4-mapped block is all of IPv4, and so is
		// whatever holds it; inside it the IPv4 floor applies.
		"::ffff:0:0/96": true, "::ffff:0.0.0.0/97": true, "::ffff:10.0.0.0/103": true, "::/64": true, "::/80": true, "::fffe:0:0/95": true,
		"::ffff:10.0.0.0/104": false, "::ffff:192.0.2.0/120": false, "::ffff:203.0.113.7/128": false,
		// An IPv6 prefix as long as the mapped block's, or about, that is
		// not it and does not hold it.
		"64:ff9b::/96": false, "2001:db8::/96": false, "::1/128": false, "::/81": false, "::/95": false,
		// Host bits set: read as the prefix they are in.
		"10.1.2.3/7": true, "10.1.2.3/8": false,
	} {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			t.Fatalf("%s: %v", s, err)
		}
		if got := TooWide(p); got != want {
			t.Errorf("TooWide(%s) = %v, want %v", s, got, want)
		}
		if err := Check(s); (err != nil) != want {
			t.Errorf("Check(%s) = %v, want an error: %v", s, err, want)
		}
	}
	if TooWide(netip.Prefix{}) {
		t.Error("the zero prefix is too wide")
	}
	// What is not a prefix is not this check's to refuse.
	for _, s := range []string{"", "203.0.113.7", "2001:db8::1", "not-a-range", "10.0.0.0/33", "0.0.0.0"} {
		if err := Check(s); err != nil {
			t.Errorf("Check(%q) = %v, want nil", s, err)
		}
	}
	if err := Check("0.0.0.0/0"); err == nil || !strings.Contains(err.Error(), "0.0.0.0/0") || !strings.Contains(err.Error(), "/8") {
		t.Errorf("the error does not name the range and the floor: %v", err)
	}
}
