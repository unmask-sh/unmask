package ban

import (
	"context"
	"strings"
	"testing"
)

// AddAutoNet bans the client, not the one address: an IPv6 client's /64, as
// one address row for every fingerprint; an IPv4 client's address and
// fingerprint, as AddAuto does.  What it asks the CDN egress list and the
// allowlist about is the address, and a /64 the allowlist reaches into is
// not banned -- the address is, in its place.
func TestAddAutoNetBansTheIPv6Slash64(t *testing.T) {
	mgr, _ := egressManager(t) // 198.51.100.* is a CDN's
	mgr.SetEgress(func(ip string) (string, bool) {
		if strings.HasPrefix(ip, "198.51.100.") || strings.HasPrefix(ip, "2001:db8:cd:") {
			return "cloudfront", true
		}
		return "", false
	})
	mgr.SetWhitelist(func(ip string) bool {
		return ip == "2001:db8:5:6::99" || ip == "2001:db8:5:6::/64"
	})
	ctx := context.Background()
	const ja4, other = "t13d230800_bfd000000000_000000000000", "t13d1516h2_8daaf6152771_02713d6af862"
	add := func(ip string) {
		mgr.AddAutoNet(ctx, ip, ja4, ScopeIPJA4, SourceRateLimitAbuse, "pass budget", "captcha_only", 3600)
	}
	banned := func(ip, ja4 string) bool {
		_, _, b := mgr.IsBannedActionSource(ctx, ip, ja4)
		return b
	}

	add("2001:db8:1:2::1")
	if !banned("2001:db8:1:2::1", ja4) || !banned("2001:db8:1:2:ffff::7", other) {
		t.Error("the /64 is not banned for every address and fingerprint of it")
	}
	if banned("2001:db8:1:3::1", ja4) {
		t.Error("the next /64 is banned")
	}
	rows := mgr.Snapshot()
	if len(rows) != 1 || rows[0].IP != "2001:db8:1:2::/64" || rows[0].JA4 != "" || rows[0].Scope != ScopeIPOnly {
		t.Fatalf("rows after one IPv6 ban: %+v, want the /64 alone, address scope", rows)
	}

	// IPv4: the address and the fingerprint, as before.
	add("203.0.113.9")
	if !banned("203.0.113.9", ja4) || banned("203.0.113.9", other) || banned("203.0.113.10", ja4) {
		t.Error("an IPv4 ban is not the address and fingerprint alone")
	}

	// A CDN's address gets no automatic ban, and neither does its /64.
	add("2001:db8:cd:1::1")
	add("198.51.100.7")
	if banned("2001:db8:cd:1::1", ja4) || banned("2001:db8:cd:1::2", ja4) || banned("198.51.100.7", ja4) {
		t.Error("a ban landed on a CDN's address or its /64")
	}

	// The allowlist reaches into this /64: the address, not the /64.
	add("2001:db8:5:6::1")
	if !banned("2001:db8:5:6::1", ja4) {
		t.Error("beside an allowlisted address: the client's own address is not banned")
	}
	if banned("2001:db8:5:6::2", ja4) || banned("2001:db8:5:6::1", other) {
		t.Error("beside an allowlisted address: the ban is wider than the address and fingerprint")
	}
	// The allowlisted address itself: nothing.
	add("2001:db8:5:6::99")
	if banned("2001:db8:5:6::99", ja4) {
		t.Error("an allowlisted address was banned")
	}
}
