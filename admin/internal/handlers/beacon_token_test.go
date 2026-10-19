package handlers

import (
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestBeaconTokenRoundtrip(t *testing.T) {
	const secret = "beacon-secret-please-change"
	tok := issueBeaconToken(secret)
	if !verifyBeaconToken(tok, secret) {
		t.Fatalf("freshly issued token should verify; got %q", tok)
	}
}

func TestBeaconTokenRejectsBadSecret(t *testing.T) {
	tok := issueBeaconToken("secret-A")
	if verifyBeaconToken(tok, "secret-B") {
		t.Fatalf("token signed by a different secret should fail")
	}
}

func TestBeaconTokenRejectsMalformed(t *testing.T) {
	const secret = "s"
	for _, c := range []string{"", "bogus", ".", "abc.", ".abc", "abc.def", "abc..ghi", "abc.def.", ".def.ghi"} {
		if verifyBeaconToken(c, secret) {
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
	tok := old + "." + nonce + "." + beaconSig(secret, old, nonce)
	if verifyBeaconToken(tok, secret) {
		t.Fatalf("expired token should fail")
	}
	// Future-dated beyond the 60s skew allowance.
	fut := strconv.FormatInt(time.Now().Add(10*time.Minute).UnixNano(), 36)
	tok = fut + "." + nonce + "." + beaconSig(secret, fut, nonce)
	if verifyBeaconToken(tok, secret) {
		t.Fatalf("future-dated token should fail")
	}
}

func TestBeaconTokenRejectsTampered(t *testing.T) {
	const secret = "s"
	tok := issueBeaconToken(secret)
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3-segment token, got %q", tok)
	}
	sig := []byte(parts[2])
	sig[0] ^= 1
	tampered := parts[0] + "." + parts[1] + "." + string(sig)
	if verifyBeaconToken(tampered, secret) {
		t.Fatalf("tampered signature should fail")
	}
}

// TestBeaconTokenUniqueness: tokens issued back-to-back must differ even
// though the timestamp may collide -- the nonce is what carries the per-token
// entropy under a tight loop / multi-threaded bot burst.
func TestBeaconTokenUniqueness(t *testing.T) {
	const secret = "s"
	const n = 1000
	seen := make(map[string]bool, n)
	for i := 0; i < n; i++ {
		tok := issueBeaconToken(secret)
		if seen[tok] {
			t.Fatalf("duplicate token after %d issues: %q", i, tok)
		}
		seen[tok] = true
	}
}
