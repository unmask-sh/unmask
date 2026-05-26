package handlers

import (
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestBeaconTokenRoundtrip(t *testing.T) {
	const secret = "beacon-secret-please-change"
	tok := issueBeaconToken(secret, "1.2.3.4")
	if !verifyBeaconToken(tok, secret, "1.2.3.4") {
		t.Fatalf("freshly issued token should verify; got %q", tok)
	}
}

func TestBeaconTokenRejectsDifferentIP(t *testing.T) {
	const secret = "beacon-secret"
	tok := issueBeaconToken(secret, "1.2.3.4")
	if verifyBeaconToken(tok, secret, "9.9.9.9") {
		t.Fatalf("token bound to a different IP should fail")
	}
}

func TestBeaconTokenRejectsBadSecret(t *testing.T) {
	tok := issueBeaconToken("secret-A", "1.2.3.4")
	if verifyBeaconToken(tok, "secret-B", "1.2.3.4") {
		t.Fatalf("token signed by a different secret should fail")
	}
}

func TestBeaconTokenRejectsMalformed(t *testing.T) {
	const secret = "s"
	for _, c := range []string{"", "bogus", ".", "abc.", ".abc", "abc.def", "abc..ghi", "abc.def.", ".def.ghi"} {
		if verifyBeaconToken(c, secret, "1.2.3.4") {
			t.Errorf("expected reject for %q", c)
		}
	}
}

func TestBeaconTokenRejectsExpired(t *testing.T) {
	const secret = "s"
	// Forge a token issued well outside the TTL window.  Timestamps are in
	// nanoseconds since beacon_token.go switched to UnixNano precision.
	old := strconv.FormatInt(time.Now().Add(-2*beaconTokenTTL).UnixNano(), 36)
	const nonce = "deadbeef"
	tok := old + "." + nonce + "." + beaconSig(secret, old, nonce, "1.2.3.4")
	if verifyBeaconToken(tok, secret, "1.2.3.4") {
		t.Fatalf("expired token should fail")
	}
	// Future-dated beyond the 60s skew allowance.
	fut := strconv.FormatInt(time.Now().Add(10*time.Minute).UnixNano(), 36)
	tok = fut + "." + nonce + "." + beaconSig(secret, fut, nonce, "1.2.3.4")
	if verifyBeaconToken(tok, secret, "1.2.3.4") {
		t.Fatalf("future-dated token should fail")
	}
}

func TestBeaconTokenRejectsTampered(t *testing.T) {
	const secret = "s"
	tok := issueBeaconToken(secret, "1.2.3.4")
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3-segment token, got %q", tok)
	}
	sig := []byte(parts[2])
	sig[0] ^= 1
	tampered := parts[0] + "." + parts[1] + "." + string(sig)
	if verifyBeaconToken(tampered, secret, "1.2.3.4") {
		t.Fatalf("tampered signature should fail")
	}
}

// TestBeaconTokenUniqueness: tokens issued back-to-back for the same IP must
// differ even though the timestamp may collide -- the nonce is what carries
// the per-token entropy under a tight loop / multi-threaded bot burst.
func TestBeaconTokenUniqueness(t *testing.T) {
	const secret, ip = "s", "1.2.3.4"
	const n = 1000
	seen := make(map[string]bool, n)
	for i := 0; i < n; i++ {
		tok := issueBeaconToken(secret, ip)
		if seen[tok] {
			t.Fatalf("duplicate token after %d issues: %q", i, tok)
		}
		seen[tok] = true
	}
}
