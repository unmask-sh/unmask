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
	for _, c := range []string{"", "bogus", ".", "abc.", ".abc", "abc.def.ghi"} {
		if verifyBeaconToken(c, secret, "1.2.3.4") {
			t.Errorf("expected reject for %q", c)
		}
	}
}

func TestBeaconTokenRejectsExpired(t *testing.T) {
	const secret = "s"
	// Forge a token issued well outside the TTL window.
	old := strconv.FormatInt(time.Now().Add(-2*beaconTokenTTL).Unix(), 36)
	tok := old + "." + beaconSig(secret, old, "1.2.3.4")
	if verifyBeaconToken(tok, secret, "1.2.3.4") {
		t.Fatalf("expired token should fail")
	}
	// Future-dated beyond the 60s skew allowance.
	fut := strconv.FormatInt(time.Now().Add(10*time.Minute).Unix(), 36)
	tok = fut + "." + beaconSig(secret, fut, "1.2.3.4")
	if verifyBeaconToken(tok, secret, "1.2.3.4") {
		t.Fatalf("future-dated token should fail")
	}
}

func TestBeaconTokenRejectsTampered(t *testing.T) {
	const secret = "s"
	tok := issueBeaconToken(secret, "1.2.3.4")
	dot := strings.IndexByte(tok, '.')
	sig := []byte(tok[dot+1:])
	sig[0] ^= 1
	if verifyBeaconToken(tok[:dot+1]+string(sig), secret, "1.2.3.4") {
		t.Fatalf("tampered signature should fail")
	}
}
