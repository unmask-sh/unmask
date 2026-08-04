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

// host is the vhost the cookie is bound to.  Verification must reproduce the
// same value or the signature won't match (= the site-binding).
const host = "example.com"

func TestRoundtrip(t *testing.T) {
	const secret = "test-secret-please-change"
	v := IssueValue(secret, "1.2.3.4", host, "captcha")
	if !Verify(v, secret, "1.2.3.4", host, threeDays, threeDays, 18) {
		t.Fatalf("expected freshly-issued cookie to verify; got %q", v)
	}
}

func TestVerifyRejectsDifferentIP(t *testing.T) {
	const secret = "test-secret"
	v := IssueValue(secret, "1.2.3.4", host, "captcha")
	if Verify(v, secret, "9.9.9.9", host, threeDays, threeDays, 18) {
		t.Fatalf("verify should fail for different IP")
	}
}

// TestVerifyRejectsDifferentHost is the site-binding: a cookie minted while
// solving site A's challenge must NOT verify on site B (different host).
func TestVerifyRejectsDifferentHost(t *testing.T) {
	const secret = "test-secret"
	v := IssueValue(secret, "1.2.3.4", "shop.example.com", "captcha")
	if Verify(v, secret, "1.2.3.4", "blog.example.com", threeDays, threeDays, 18) {
		t.Fatal("verify should fail for a different host (cross-site cookie reuse)")
	}
	if !Verify(v, secret, "1.2.3.4", "shop.example.com", threeDays, threeDays, 18) {
		t.Fatal("verify should still succeed for the issuing host")
	}
}

func TestVerifyRejectsTampered(t *testing.T) {
	const secret = "test-secret"
	v := IssueValue(secret, "1.2.3.4", host, "captcha")
	parts := strings.SplitN(v, ".", 3)
	// flip a hex digit in the signature
	sigBytes := []byte(parts[1])
	sigBytes[0] = sigBytes[0] ^ 1
	tampered := parts[0] + "." + string(sigBytes) + "." + parts[2]
	if Verify(tampered, secret, "1.2.3.4", host, threeDays, threeDays, 18) {
		t.Fatalf("verify should fail for tampered signature")
	}
}

func TestVerifyRejectsMalformed(t *testing.T) {
	const secret = "s"
	cases := []string{"", "bogus", "20000", "20000.sig", "abc.def.ghi"}
	for _, c := range cases {
		if Verify(c, secret, "1.2.3.4", host, threeDays, threeDays, 18) {
			t.Errorf("expected reject for %q", c)
		}
	}
}

func TestVerifyExpiry(t *testing.T) {
	const secret = "s"
	// Manually construct a cookie 10 days in the past.
	old := issueValueAt(secret, "1.2.3.4", host, "captcha", nowUnix()-86400*10)
	if Verify(old, secret, "1.2.3.4", host, threeDays, threeDays, 18) {
		t.Fatalf("expected expired cookie to fail")
	}
	// And a future-dated cookie well beyond the 60-second skew tolerance.
	fut := issueValueAt(secret, "1.2.3.4", host, "captcha", nowUnix()+86400)
	if Verify(fut, secret, "1.2.3.4", host, threeDays, threeDays, 18) {
		t.Fatalf("expected future-dated cookie to fail")
	}
}

func TestVerifySkewToleranceAcceptsSmallForwardDrift(t *testing.T) {
	const secret = "s"
	// A cookie issued 30 seconds in the future (= within the 60 s skew
	// tolerance) must still verify.
	skewed := issueValueAt(secret, "1.2.3.4", host, "captcha", nowUnix()+30)
	if !Verify(skewed, secret, "1.2.3.4", host, threeDays, threeDays, 18) {
		t.Fatalf("expected 30-second forward-skewed cookie to verify")
	}
}

// TestPowSeed_MatchesStandardHMAC pins PowSeed to a value computed by `openssl
// dgst -sha1 -hmac`, i.e. the standard HMAC-SHA1 the C plugin computes via
// HMAC(EVP_sha1(), ...).  If this passes, the Go admin (issuer) and the C plugin
// (native-mode verifier) derive byte-identical PoW seeds -- the load-bearing
// cross-language invariant for the IP/host/secret-bound PoW.
func TestPowSeed_MatchesStandardHMAC(t *testing.T) {
	// printf '%s' "1000000000:1.2.3.4:example.com:pow_seed" | openssl dgst -sha1 -hmac "testsecret"
	const want = "fac63d285bb4aa3f4b4e48d378d0af4479640e0b"
	got := PowSeed("testsecret", "1.2.3.4", "example.com", 1000000000)
	if got != want {
		t.Fatalf("PowSeed diverged from standard HMAC-SHA1 (C plugin would mismatch):\n got=%s\nwant=%s", got, want)
	}
}

// TestPowSeedRoundTrip solves a low-difficulty PoW against the server-bound seed
// and confirms the cookie verifies for the issuing IP + host only -- and not
// from a different IP, host, or secret.
func TestPowSeedRoundTrip(t *testing.T) {
	const secret, ip = "s3cr3t", "9.9.9.9"
	issued := nowUnix()
	const diff = 10
	seed := PowSeed(secret, ip, host, issued)
	// Keep solving until the nonce clears the issuing seed and clears NONE of
	// the three foreign ones.  A hash that satisfies one seed satisfies an
	// unrelated seed with probability 2^-diff, so taking the first solution
	// made each negative assertion below a 1-in-1024 coin flip -- three of
	// them, on a seed reseeded from the clock every run, which is a ~0.3%
	// failure that surfaces at random and reads as a real regression.  The
	// retry costs 1.003 solves on average and makes the outcome deterministic.
	// (The property under test is unchanged: this is the case a real client
	// produces 997 times in 1000.)
	foreign := []string{
		PowSeed(secret, "8.8.8.8", host, issued),
		PowSeed(secret, ip, "other.example.com", issued),
		PowSeed("other-secret", ip, host, issued),
	}
	clears := func(s string, nonce int64) bool {
		sum := sha256.Sum256([]byte(s + ":" + strconv.FormatInt(nonce, 10)))
		return leadingZeroBits(sum[:]) >= diff
	}
	var nonce int64
	for nonce = 0; nonce < 1<<24; nonce++ {
		if !clears(seed, nonce) {
			continue
		}
		ok := true
		for _, f := range foreign {
			if clears(f, nonce) {
				ok = false
				break
			}
		}
		if ok {
			break
		}
	}
	cookie := strconv.FormatInt(issued, 10) + ".pow2." + strconv.FormatInt(nonce, 36) + ".0"
	if !Verify(cookie, secret, ip, host, 3600, 3600, diff) {
		t.Fatalf("PoW cookie should verify for the issuing IP+host (cookie=%s)", cookie)
	}
	if Verify(cookie, secret, "8.8.8.8", host, 3600, 3600, diff) {
		t.Fatal("PoW cookie must NOT verify from a different IP (cross-IP reuse)")
	}
	if Verify(cookie, secret, ip, "other.example.com", 3600, 3600, diff) {
		t.Fatal("PoW cookie must NOT verify for a different host (cross-site reuse)")
	}
	if Verify(cookie, "other-secret", ip, host, 3600, 3600, diff) {
		t.Fatal("PoW cookie must NOT verify under a different secret (offline precompute)")
	}
}
