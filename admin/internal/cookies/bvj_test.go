package cookies

import (
	"strings"
	"testing"
)

const bvjSecret = "test-secret-please-change"

func TestBVJRoundtrip(t *testing.T) {
	ja4h := FingerprintHash("t13d1516h2_8daaf6152771_b186095e22b6")
	uah := FingerprintHash("Mozilla/5.0")
	v := IssueJValue(bvjSecret, ja4h, uah, "abcdef0123456789abcdef01", 13335, host, "captcha")
	c, ok := ParseJValue(v, bvjSecret, host, threeDays)
	if !ok {
		t.Fatalf("expected freshly-issued _bvj to parse; got %q", v)
	}
	if c.JA4Hash != ja4h || c.UAHash != uah || c.Lineage != "abcdef0123456789abcdef01" || c.ASN != 13335 || c.Kind != "captcha" {
		t.Fatalf("claims round-trip mismatch: %+v", c)
	}
}

func TestBVJRejectsDifferentHost(t *testing.T) {
	v := IssueJValue(bvjSecret, "aaaa", "bbbb", "lin", 100, host, "captcha")
	if _, ok := ParseJValue(v, bvjSecret, "other.example.org", threeDays); ok {
		t.Fatal("expected _bvj bound to one host to fail on another")
	}
}

func TestBVJRejectsWrongSecret(t *testing.T) {
	v := IssueJValue(bvjSecret, "aaaa", "bbbb", "lin", 100, host, "captcha")
	if _, ok := ParseJValue(v, "different-secret", host, threeDays); ok {
		t.Fatal("expected _bvj signed with one secret to fail under another")
	}
}

// A different ASN in the new IP must not pass: the signature is computed over
// the solve-time ASN, so flipping the asn segment breaks verification.  This is
// what makes the ASN veto unforgeable -- an attacker can't just rewrite the
// claimed ASN to match their datacenter.
func TestBVJRejectsTamperedASN(t *testing.T) {
	v := IssueJValue(bvjSecret, "aaaa", "bbbb", "lin", 100, host, "captcha")
	parts := strings.Split(v, ".")
	parts[4] = "999" // was "100"
	if _, ok := ParseJValue(strings.Join(parts, "."), bvjSecret, host, threeDays); ok {
		t.Fatal("expected tampered ASN segment to fail verification")
	}
}

func TestBVJExpiry(t *testing.T) {
	v := issueJValueAt(bvjSecret, "aaaa", "bbbb", "lin", 100, host, "captcha", nowUnix()-threeDays-100)
	if _, ok := ParseJValue(v, bvjSecret, host, threeDays); ok {
		t.Fatal("expected _bvj older than the validity window to fail")
	}
}

func TestBVJRejectsMalformed(t *testing.T) {
	for _, s := range []string{"", "a.b.c", "1.2.3.4.5.6", "1.2.3.4.5.6.7.8"} {
		if _, ok := ParseJValue(s, bvjSecret, host, threeDays); ok {
			t.Fatalf("expected malformed _bvj %q to fail", s)
		}
	}
}

func TestMatchingEntryKind(t *testing.T) {
	captchaV := IssueValue(bvjSecret, "1.2.3.4", host, "captcha")
	rebindV := IssueValue(bvjSecret, "1.2.3.4", host, "rebind")

	if k, ok := MatchingEntryKind(captchaV, bvjSecret, "1.2.3.4", host, threeDays, threeDays, 18); !ok || k != "captcha" {
		t.Fatalf("expected (captcha,true), got (%q,%v)", k, ok)
	}
	if k, ok := MatchingEntryKind(rebindV, bvjSecret, "1.2.3.4", host, threeDays, threeDays, 18); !ok || k != "rebind" {
		t.Fatalf("expected (rebind,true), got (%q,%v)", k, ok)
	}
	// "~"-list: the first VERIFYING entry decides the kind, regardless of an
	// unverifiable entry sorting ahead of it.
	staleFirst := IssueValue(bvjSecret, "9.9.9.9", host, "captcha") + "~" + rebindV
	if k, ok := MatchingEntryKind(staleFirst, bvjSecret, "1.2.3.4", host, threeDays, threeDays, 18); !ok || k != "rebind" {
		t.Fatalf("expected the verifying rebind entry to decide, got (%q,%v)", k, ok)
	}
	// Wrong IP -> no entry verifies.
	if _, ok := MatchingEntryKind(captchaV, bvjSecret, "5.6.7.8", host, threeDays, threeDays, 18); ok {
		t.Fatal("expected no match for a different IP")
	}
	if _, ok := MatchingEntryKind("", bvjSecret, "1.2.3.4", host, threeDays, threeDays, 18); ok {
		t.Fatal("expected no match for an empty value")
	}
}

// TestLineageOfIsTheSolves: the lineage of a pass is one value however often
// it is asked for, another for another pass, another on another host, and
// nothing a client can work out without the secret.
func TestLineageOfIsTheSolves(t *testing.T) {
	a := LineageOf("secret", "example.com", "0123456789abcdef")
	if len(a) != 24 || strings.Trim(a, "0123456789abcdef") != "" {
		t.Fatalf("expected 24 hex chars, got %q", a)
	}
	if b := LineageOf("secret", "example.com", "0123456789abcdef"); b != a {
		t.Errorf("the same pass named two lineages: %q and %q", a, b)
	}
	for what, other := range map[string]string{
		"another pass":   LineageOf("secret", "example.com", "fedcba9876543210"),
		"another host":   LineageOf("secret", "other.example", "0123456789abcdef"),
		"another secret": LineageOf("secret2", "example.com", "0123456789abcdef"),
	} {
		if other == a {
			t.Errorf("%s names the same lineage %q", what, a)
		}
	}
	if got := LineageOf("secret", "example.com", ""); got != "" {
		t.Errorf("a pass without an identity was given lineage %q", got)
	}
}

// TestIssuedPassIDIsTheVerifiersID: the identity read off a pass as it is
// issued is the one the verifier reports for it when it comes back, in each
// form the daemon signs in.
func TestIssuedPassIDIsTheVerifiersID(t *testing.T) {
	for _, h := range []SigHash{SigSHA1, SigSHA256, SigSHA256Wide} {
		val := IssueValueH(h, "secret", "203.0.113.7", "example.com", "captcha")
		_, _, id, _, ok := MatchingEntryID(val, "secret", "203.0.113.7", "example.com", 604800, 1209600, 18)
		if !ok {
			t.Fatalf("form %d: the pass just issued does not verify", h)
		}
		if got := IssuedPassID(val); got == "" || got != id {
			t.Errorf("form %d: IssuedPassID = %q, the verifier says %q", h, got, id)
		}
	}
	for _, v := range []string{"", "1785943030.pow2.aaaa.0", "1785943030.short.captcha", "no dots"} {
		if got := IssuedPassID(v); got != "" {
			t.Errorf("IssuedPassID(%q) = %q, want none", v, got)
		}
	}
}
