package handlers

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"time"
)

// beacon token: short-lived signed token issued when serving the challenge page
// and embedded in challenge.html.  challenge.js echoes it back in the bt field
// of the _bcDebug payload, and DebugBeacon verifies it.  Purpose: reject blind
// POSTs to /api/debug and expired replays (= bots capturing an old beacon
// payload and replaying it infinitely to inflate phase counts).
//
// format: "<issued_unix_b36>.<hmac16>"
//   hmac16 = HMAC-SHA256("<issued_unix_b36>:<remote_ip>", CaptchaSecretBase) hex[:16]
//
// IP binding: both the issuer (ServeChallenge) and verifier (DebugBeacon) use
// clientIP() from the same admin handler, so there is no mismatch (= unlike
// the JA4 binding problem on the captcha _bv cookie).

// beaconTokenTTL: grace period from challenge page delivery to beacon submit.
// Set generously (= 15 min) to allow for humans solving CAPTCHA slowly or
// leaving the tab open.
const beaconTokenTTL = 15 * time.Minute

func beaconSig(secret, issued, ip string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(issued + ":" + ip))
	return hex.EncodeToString(mac.Sum(nil))[:16]
}

// issueBeaconToken returns a fresh signed token bound to ip.
func issueBeaconToken(secret, ip string) string {
	issued := strconv.FormatInt(time.Now().Unix(), 36)
	return issued + "." + beaconSig(secret, issued, ip)
}

// verifyBeaconToken returns true iff token is signed by secret, bound to ip,
// and was issued within beaconTokenTTL.
func verifyBeaconToken(token, secret, ip string) bool {
	if token == "" || secret == "" {
		return false
	}
	dot := strings.IndexByte(token, '.')
	if dot <= 0 || dot >= len(token)-1 {
		return false
	}
	issuedStr, sig := token[:dot], token[dot+1:]
	issued, err := strconv.ParseInt(issuedStr, 36, 64)
	if err != nil || issued <= 0 {
		return false
	}
	now := time.Now().Unix()
	// Future timestamps (= clock-skew abuse) tolerated only up to 60s.  Past
	// timestamps allowed up to the TTL ceiling.
	if issued > now+60 || now-issued > int64(beaconTokenTTL/time.Second) {
		return false
	}
	return hmac.Equal([]byte(sig), []byte(beaconSig(secret, issuedStr, ip)))
}
