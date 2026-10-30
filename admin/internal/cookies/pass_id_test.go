package cookies

import (
	"crypto/sha256"
	"strconv"
	"testing"
)

// A pass's identity follows the pass, not its spelling: every nonce that
// answers one proof-of-work seed is one pass, a seed of another second (or
// another address, or another host) is another, and a CAPTCHA-form entry is
// named by its signature.  The plugin's $unmask_bv_id says the same (its
// test is the e2e stack); the strings here are what nginx keys the per-pass
// cap on.
func TestPassIDFollowsThePass(t *testing.T) {
	const secret, ip, host = "test-secret", "203.0.113.5", "example.com"
	const difficulty = 8
	issued := nowUnix() - 30
	idOf := func(entry, ip, host string) string {
		_, _, id, _, ok := MatchingEntryID(entry, secret, ip, host, 7*86400, 14*86400, difficulty)
		if !ok {
			return ""
		}
		return id
	}

	// Two nonces that answer the same seed -- and not the other hash's seed
	// for the same second: the verifier tries every SigHash and names the
	// pass by the seed that answered, and at this difficulty one nonce in
	// 2^8 answers both.
	solves := func(seed string, n int64) bool {
		sum := sha256.Sum256([]byte(seed + ":" + strconv.FormatInt(n, 10)))
		return leadingZeroBits(sum[:]) >= difficulty
	}
	seed := PowSeed(secret, ip, host, issued)
	other := PowSeedH(SigSHA256, secret, ip, host, issued)
	var nonces []int64
	for n := int64(0); len(nonces) < 2 && n < 1_000_000; n++ {
		if solves(seed, n) && !solves(other, n) {
			nonces = append(nonces, n)
		}
	}
	if len(nonces) != 2 {
		t.Fatal("could not find two nonces for the seed")
	}
	entry := func(issued, nonce int64) string {
		return strconv.FormatInt(issued, 10) + ".pow2." + strconv.FormatInt(nonce, 36) + ".0"
	}
	a, b := entry(issued, nonces[0]), entry(issued, nonces[1])
	if a == b {
		t.Fatal("the two entries must differ in their nonce")
	}
	ida, idb := idOf(a, ip, host), idOf(b, ip, host)
	if ida == "" || len(ida) != PassIDLen || ida != seed[:PassIDLen] {
		t.Errorf("PoW identity %q, want the seed's first %d digits %q", ida, PassIDLen, seed[:PassIDLen])
	}
	if ida != idb {
		t.Errorf("two nonces of one seed: %q vs %q, want one pass", ida, idb)
	}
	// A seed of another second is another pass (the nonce found for the
	// first seed may not answer it, so solve it on its own).
	seed2, other2 := PowSeed(secret, ip, host, issued-1), PowSeedH(SigSHA256, secret, ip, host, issued-1)
	var n2 int64
	for ; n2 < 1_000_000; n2++ {
		if solves(seed2, n2) && !solves(other2, n2) {
			break
		}
	}
	if other := idOf(entry(issued-1, n2), ip, host); other == ida || other == "" {
		t.Errorf("another second: %q, want a pass of its own", other)
	}
	// Another address or host: the entry does not verify there at all.
	for name, other := range map[string]string{
		"another address": idOf(a, "203.0.113.6", host),
		"another host":    idOf(a, ip, "other.example"),
	} {
		if other != "" {
			t.Errorf("%s: %q, want no pass", name, other)
		}
	}

	// A CAPTCHA-form entry: its signature, whatever the kind.
	for _, kind := range []string{"captcha", "rebind", "passthrough", "pow"} {
		e := IssueValueAt(secret, ip, host, kind, issued)
		want := e[len(strconv.FormatInt(issued, 10))+1:][:PassIDLen]
		if got := idOf(e, ip, host); got != want {
			t.Errorf("%s entry %q: identity %q, want its signature %q", kind, e, got, want)
		}
	}
	// Neither shape names nothing.
	for _, junk := range []string{"", "1785943030", "a.b", "1785943030.pow2.zz", "x.pow2.1.0", "1785943030.short.captcha"} {
		if got := idOf(junk, ip, host); got != "" {
			t.Errorf("%q: identity %q, want none", junk, got)
		}
	}
}
