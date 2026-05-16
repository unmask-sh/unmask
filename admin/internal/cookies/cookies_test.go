package cookies

import (
	"strings"
	"testing"
)

func TestRoundtrip(t *testing.T) {
	const secret = "test-secret-please-change"
	v := IssueValue(secret, "1.2.3.4", "captcha")
	if !Verify(v, secret, "1.2.3.4", 3, 18) {
		t.Fatalf("expected freshly-issued cookie to verify; got %q", v)
	}
}

func TestVerifyRejectsDifferentIP(t *testing.T) {
	const secret = "test-secret"
	v := IssueValue(secret, "1.2.3.4", "captcha")
	if Verify(v, secret, "9.9.9.9", 3, 18) {
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
	if Verify(tampered, secret, "1.2.3.4", 3, 18) {
		t.Fatalf("verify should fail for tampered signature")
	}
}

func TestVerifyRejectsMalformed(t *testing.T) {
	const secret = "s"
	cases := []string{"", "bogus", "20000", "20000.sig", "abc.def.ghi"}
	for _, c := range cases {
		if Verify(c, secret, "1.2.3.4", 3, 18) {
			t.Errorf("expected reject for %q", c)
		}
	}
}

func TestVerifyExpiry(t *testing.T) {
	const secret = "s"
	// Manually construct a cookie 10 days in the past.
	old := issueValueAt(secret, "1.2.3.4", "captcha", dayNow()-10)
	if Verify(old, secret, "1.2.3.4", 3, 18) {
		t.Fatalf("expected expired cookie to fail")
	}
	// And a future-dated cookie (= clock skew abuse).
	fut := issueValueAt(secret, "1.2.3.4", "captcha", dayNow()+1)
	if Verify(fut, secret, "1.2.3.4", 3, 18) {
		t.Fatalf("expected future-dated cookie to fail")
	}
}
