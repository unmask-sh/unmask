package cookies

import (
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
