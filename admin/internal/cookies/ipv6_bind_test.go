package cookies

import "testing"

// TestBindIP pins the IP -> seed-token normalization.  IPv4 (and IPv4-mapped)
// pass through unchanged so existing v4 cookies stay byte-identical; pure IPv6
// folds to its /64 (first 8 bytes, 16 lowercase hex).  These vectors MUST match
// the C plugin's unmask_bind_ip_token.
func TestBindIP(t *testing.T) {
	cases := map[string]string{
		"1.2.3.4":              "1.2.3.4",          // IPv4 unchanged
		"203.0.113.5":          "203.0.113.5",      // IPv4 unchanged
		"2001:db8::1":          "20010db800000000", // /64 = 2001:0db8:0000:0000
		"2001:db8:1:2:3:4:5:6": "20010db800010002", // /64 = 2001:0db8:0001:0002
		"fe80::1":              "fe80000000000000", // /64 = fe80:0000:0000:0000
		"::ffff:1.2.3.4":       "::ffff:1.2.3.4",   // v4-mapped -> IPv4 semantics, unchanged
		"not-an-ip":            "not-an-ip",        // unparseable -> as-is
		"":                     "",                 // empty -> as-is
	}
	for in, want := range cases {
		if got := bindIP(in); got != want {
			t.Errorf("bindIP(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestBindIPv6Roaming is the point of the change: two addresses in the same /64
// (e.g. an iPhone's rotating privacy addresses) share one cookie, while a
// different /64 does not -- and IPv4 stays an exact-host bind.
func TestBindIPv6Roaming(t *testing.T) {
	const (
		secret = "test-bv-secret"
		host   = "example.com"
		win    = 3600
		diff   = 18
	)
	// CAPTCHA path: issue for one v6 address, verify from another in the same /64.
	val := IssueValue(secret, "2001:db8:abcd:1::1", host, "captcha")
	if !Verify(val, secret, "2001:db8:abcd:1:ffff:ffff:ffff:ffff", host, win, win, diff) {
		t.Error("same-/64 IPv6 address should verify (privacy-address rotation must not re-challenge)")
	}
	if Verify(val, secret, "2001:db8:abcd:2::1", host, win, win, diff) {
		t.Error("different-/64 IPv6 address must NOT verify")
	}
	// IPv4 stays a /32 exact-host bind (unchanged behavior).
	v4 := IssueValue(secret, "203.0.113.7", host, "captcha")
	if !Verify(v4, secret, "203.0.113.7", host, win, win, diff) {
		t.Error("same IPv4 should verify")
	}
	if Verify(v4, secret, "203.0.113.8", host, win, win, diff) {
		t.Error("different IPv4 must NOT verify")
	}

	// PoW seed is likewise /64-bound: same /64 -> identical seed, different ->
	// different (the seed binds the client so a solve can't transfer across /64s).
	now := nowUnix()
	if PowSeed(secret, "2001:db8:abcd:1::1", host, now) != PowSeed(secret, "2001:db8:abcd:1::99", host, now) {
		t.Error("PoW seed should be identical within a /64")
	}
	if PowSeed(secret, "2001:db8:abcd:1::1", host, now) == PowSeed(secret, "2001:db8:abcd:2::1", host, now) {
		t.Error("PoW seed must differ across /64s")
	}
}
