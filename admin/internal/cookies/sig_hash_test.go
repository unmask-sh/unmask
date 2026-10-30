package cookies

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"testing"
)

// The signatures move hash by configuration and verify by both: an entry
// signed with either hash verifies, a seed derived with either hash solves,
// the shapes on the wire do not change, and the identity names the seed that
// verified.
func TestSigHashesBothVerify(t *testing.T) {
	const secret, ip, host = "test-secret", "203.0.113.5", "example.com"
	now := nowUnix() - 10
	for _, h := range []SigHash{SigSHA1, SigSHA256} {
		e := IssueValueAtH(h, secret, ip, host, "captcha", now)
		if !Verify(e, secret, ip, host, 7*86400, 14*86400, 8) {
			t.Errorf("%s-signed entry %q does not verify", h, e)
		}
		if _, kind, id, _, ok := MatchingEntryID(e, secret, ip, host, 7*86400, 14*86400, 8); !ok || kind != "captcha" || id != e[len(strconv.FormatInt(now, 10))+1:][:16] {
			t.Errorf("%s-signed entry: kind %q id %q ok %v", h, kind, id, ok)
		}
		if Verify(e, "other-secret", ip, host, 7*86400, 14*86400, 8) || Verify(e, secret, "203.0.113.6", host, 7*86400, 14*86400, 8) {
			t.Errorf("%s-signed entry verifies for another secret or address", h)
		}
		j := IssueJValueAtH(h, secret, "ja4hash0000", "uahash000000", "lin", 64512, host, "captcha", now)
		if _, ok := ParseJValue(j, secret, host, 14*86400); !ok {
			t.Errorf("%s-signed _bvj does not parse", h)
		}
	}
	a, b := IssueValueAtH(SigSHA1, secret, ip, host, "captcha", now), IssueValueAtH(SigSHA256, secret, ip, host, "captcha", now)
	if a == b {
		t.Error("the two hashes signed alike")
	}
	// The SHA-256 signature is HMAC-SHA256's first 16 hex digits over the
	// same message the SHA-1 one signs.
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(strconv.FormatInt(now, 10) + ":" + ip + ":" + host + ":captcha"))
	if want := hex.EncodeToString(m.Sum(nil))[:16]; b[len(strconv.FormatInt(now, 10))+1:][:16] != want {
		t.Errorf("SHA-256 signature %q, want %q", b, want)
	}

	// The seed: 40 hex digits either way, different values, each solvable
	// and verified with the identity of the seed it answered.
	s1, s256 := PowSeedH(SigSHA1, secret, ip, host, now), PowSeedH(SigSHA256, secret, ip, host, now)
	if len(s1) != 40 || len(s256) != 40 || s1 == s256 {
		t.Fatalf("seeds %q / %q: want 40 hex digits each, different", s1, s256)
	}
	if PowSeed(secret, ip, host, now) != PowSeedH(DefaultSigHash, secret, ip, host, now) {
		t.Error("PowSeed does not follow DefaultSigHash")
	}
	for _, seed := range []string{s1, s256} {
		var nonce int64
		for ; nonce < 1_000_000; nonce++ {
			sum := sha256.Sum256([]byte(seed + ":" + strconv.FormatInt(nonce, 10)))
			if leadingZeroBits(sum[:]) >= 8 {
				break
			}
		}
		e := strconv.FormatInt(now, 10) + ".pow2." + strconv.FormatInt(nonce, 36) + ".0"
		_, kind, id, _, ok := MatchingEntryID(e, secret, ip, host, 7*86400, 14*86400, 8)
		if !ok || kind != "pow2" || id != seed[:PassIDLen] {
			t.Errorf("entry solved against %s: ok %v kind %q id %q, want the seed's first digits %q", seed[:8], ok, kind, id, seed[:PassIDLen])
		}
	}

	for s, want := range map[string]SigHash{"": SigSHA1, "sha1": SigSHA1, "sha256": SigSHA256} {
		if got, ok := ParseSigHash(s); !ok || got != want {
			t.Errorf("ParseSigHash(%q) = %v, %v", s, got, ok)
		}
	}
	if _, ok := ParseSigHash("md5"); ok {
		t.Error("ParseSigHash accepted md5")
	}
}
