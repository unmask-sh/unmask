package cookies

import (
	"crypto/sha256"
	"strconv"
	"strings"
	"testing"
)

// 3-day validity window expressed in seconds (= 259200).  Tests use second
// granularity to mirror the production unit (= seconds), not days.
const threeDays = 86400 * 3

func TestRoundtrip(t *testing.T) {
	const secret = "test-secret-please-change"
	v := IssueValue(secret, "1.2.3.4", "captcha")
	if !Verify(v, secret, "1.2.3.4", threeDays, threeDays, 18) {
		t.Fatalf("expected freshly-issued cookie to verify; got %q", v)
	}
}

func TestVerifyRejectsDifferentIP(t *testing.T) {
	const secret = "test-secret"
	v := IssueValue(secret, "1.2.3.4", "captcha")
	if Verify(v, secret, "9.9.9.9", threeDays, threeDays, 18) {
		t.Fatalf("verify should fail for different IP")
	}
}

func TestVerifyRejectsTampered(t *testing.T) {
	const secret = "test-secret"
	v := IssueValue(secret, "1.2.3.4", "captcha")
	parts := strings.SplitN(v, ".", 3)
	// flip a hex digit in the signature
	sigBytes := []byte(parts[1])
	sigBytes[0] = sigBytes[0] ^ 1
	tampered := parts[0] + "." + string(sigBytes) + "." + parts[2]
	if Verify(tampered, secret, "1.2.3.4", threeDays, threeDays, 18) {
		t.Fatalf("verify should fail for tampered signature")
	}
}

func TestVerifyRejectsMalformed(t *testing.T) {
	const secret = "s"
	cases := []string{"", "bogus", "20000", "20000.sig", "abc.def.ghi"}
	for _, c := range cases {
		if Verify(c, secret, "1.2.3.4", threeDays, threeDays, 18) {
			t.Errorf("expected reject for %q", c)
		}
	}
}

func TestVerifyExpiry(t *testing.T) {
	const secret = "s"
	// Manually construct a cookie 10 days in the past.
	old := issueValueAt(secret, "1.2.3.4", "captcha", nowUnix()-86400*10)
	if Verify(old, secret, "1.2.3.4", threeDays, threeDays, 18) {
		t.Fatalf("expected expired cookie to fail")
	}
	// And a future-dated cookie well beyond the 60-second skew tolerance.
	fut := issueValueAt(secret, "1.2.3.4", "captcha", nowUnix()+86400)
	if Verify(fut, secret, "1.2.3.4", threeDays, threeDays, 18) {
		t.Fatalf("expected future-dated cookie to fail")
	}
}

func TestVerifySkewToleranceAcceptsSmallForwardDrift(t *testing.T) {
	const secret = "s"
	// A cookie issued 30 seconds in the future (= within the 60 s skew
	// tolerance) must still verify.
	skewed := issueValueAt(secret, "1.2.3.4", "captcha", nowUnix()+30)
	if !Verify(skewed, secret, "1.2.3.4", threeDays, threeDays, 18) {
		t.Fatalf("expected 30-second forward-skewed cookie to verify")
	}
}

// TestPowSeed_MatchesStandardHMAC pins PowSeed to a value computed by `openssl
// dgst -sha1 -hmac`, i.e. the standard HMAC-SHA1 the C plugin computes via
// HMAC(EVP_sha1(), ...).  If this passes, the Go admin (issuer) and the C plugin
// (native-mode verifier) derive byte-identical PoW seeds -- the load-bearing
// cross-language invariant for the IP/secret-bound PoW.
func TestPowSeed_MatchesStandardHMAC(t *testing.T) {
	// printf '%s' "1000000000:1.2.3.4:pow_seed" | openssl dgst -sha1 -hmac "testsecret"
	const want = "48352dfc4aa2a086a146ef9dba939ca5fdf2521e"
	got := PowSeed("testsecret", "1.2.3.4", 1000000000)
	if got != want {
		t.Fatalf("PowSeed diverged from standard HMAC-SHA1 (C plugin would mismatch):\n got=%s\nwant=%s", got, want)
	}
}

// TestPowSeedRoundTrip solves a low-difficulty PoW against the server-bound seed
// and confirms the cookie verifies for the issuing IP only -- and not from a
// different IP or under a different secret (the #1 fix: no cross-IP reuse, no
// offline precompute).
func TestPowSeedRoundTrip(t *testing.T) {
	const secret, ip = "s3cr3t", "9.9.9.9"
	issued := nowUnix()
	const diff = 10
	seed := PowSeed(secret, ip, issued)
	var nonce int64
	for nonce = 0; nonce < 1<<24; nonce++ {
		sum := sha256.Sum256([]byte(seed + ":" + strconv.FormatInt(nonce, 10)))
		if leadingZeroBits(sum[:]) >= diff {
			break
		}
	}
	cookie := strconv.FormatInt(issued, 10) + ".pow2." + strconv.FormatInt(nonce, 36) + ".0"
	if !Verify(cookie, secret, ip, 3600, 3600, diff) {
		t.Fatalf("PoW cookie should verify for the issuing IP (cookie=%s)", cookie)
	}
	if Verify(cookie, secret, "8.8.8.8", 3600, 3600, diff) {
		t.Fatal("PoW cookie must NOT verify from a different IP (cross-IP reuse)")
	}
	if Verify(cookie, "other-secret", ip, 3600, 3600, diff) {
		t.Fatal("PoW cookie must NOT verify under a different secret (offline precompute)")
	}
}
