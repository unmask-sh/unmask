package cookies

import (
	"strings"
	"testing"
)

func TestJA4Matches(t *testing.T) {
	cases := []struct {
		set, h string
		want   bool
	}{
		{"aaaa", "aaaa", true},           // single, hit
		{"aaaa", "bbbb", false},          // single, miss
		{"aaaa~bbbb", "aaaa", true},      // multi, first
		{"aaaa~bbbb", "bbbb", true},      // multi, second
		{"aaaa~bbbb~cccc", "cccc", true}, // multi, third
		{"aaaa~bbbb", "cccc", false},     // multi, miss
		{"", "", true},                   // no-JA4 deployment: empty matches empty
		{"", "aaaa", false},              // empty set never matches a real hash
	}
	for _, c := range cases {
		cl := JClaims{JA4Hash: c.set}
		if got := cl.JA4Matches(c.h); got != c.want {
			t.Errorf("JA4Matches(set=%q, h=%q) = %v, want %v", c.set, c.h, got, c.want)
		}
	}
}

func TestAppendJA4Hash(t *testing.T) {
	cases := []struct {
		name, existing, h string
		max               int
		want              string
	}{
		{"empty -> single", "", "aaaa", 3, "aaaa"},
		{"append second", "aaaa", "bbbb", 3, "aaaa~bbbb"},
		{"dedup keeps order", "aaaa~bbbb", "aaaa", 3, "aaaa~bbbb"},
		{"cap evicts oldest", "aaaa~bbbb~cccc", "dddd", 3, "bbbb~cccc~dddd"},
		{"empty h is a no-op", "aaaa", "", 3, "aaaa"},
		{"max<=0 means no cap", "aaaa~bbbb", "cccc", 0, "aaaa~bbbb~cccc"},
	}
	for _, c := range cases {
		if got := AppendJA4Hash(c.existing, c.h, c.max); got != c.want {
			t.Errorf("%s: AppendJA4Hash(%q,%q,%d) = %q, want %q", c.name, c.existing, c.h, c.max, got, c.want)
		}
	}
}

// TestBVJMultiJA4Roundtrip locks the wire format: a "~"-joined fingerprint set
// survives Issue -> Parse under a single HMAC, and both transports match.
func TestBVJMultiJA4Roundtrip(t *testing.T) {
	h2 := FingerprintHash("t13d1516h2_8daaf6152771_d8a2da3f94cd") // Chrome over TCP/HTTP2
	h3 := FingerprintHash("q13d0311h3_55b375c5d22e_653d80c3fe9d") // same Chrome over QUIC/HTTP3
	set := AppendJA4Hash(h2, h3, maxAppendForTest)
	v := IssueJValue(bvjSecret, set, FingerprintHash("Mozilla/5.0"), "abcdef0123456789abcdef01", 2516, host, "captcha")
	c, ok := ParseJValue(v, bvjSecret, host, threeDays)
	if !ok {
		t.Fatalf("multi-JA4 _bvj must verify; value=%q", v)
	}
	if !c.JA4Matches(h2) || !c.JA4Matches(h3) {
		t.Fatalf("both transports must match the stored set %q", c.JA4Hash)
	}
	if c.JA4Matches(FingerprintHash("t13d2014h2_unrelated_fingerprint")) {
		t.Fatal("an unrelated JA4 must not match")
	}
	// The full value must stay within validBVJ's 160-byte ceiling at the cap.
	if len(v) > 160 {
		t.Fatalf("multi-JA4 _bvj value %d bytes exceeds the 160 cap", len(v))
	}
}

// TestBVJSingleHashBackwardCompat: a _bvj minted before multi-JA4 carries one
// hash and no separator; it must still parse and match (degenerate 1-set).
func TestBVJSingleHashBackwardCompat(t *testing.T) {
	h := FingerprintHash("t13d1516h2_8daaf6152771_d8a2da3f94cd")
	v := IssueJValue(bvjSecret, h, "uah0", "lin0000000000000000000000", 100, host, "captcha")
	c, ok := ParseJValue(v, bvjSecret, host, threeDays)
	if !ok || !c.JA4Matches(h) {
		t.Fatalf("legacy single-hash _bvj must parse and match (ok=%v, set=%q)", ok, c.JA4Hash)
	}
	if strings.Contains(c.JA4Hash, "~") {
		t.Fatalf("single-hash set must carry no separator: %q", c.JA4Hash)
	}
}

const maxAppendForTest = 3
