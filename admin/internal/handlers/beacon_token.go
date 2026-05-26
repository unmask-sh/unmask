package handlers

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
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
// format: "<issued_unix_nano_b36>.<nonce64_b36>.<hmac16>"
//   hmac16 = HMAC-SHA256("<issued>:<nonce>:<remote_ip>", CaptchaSecretBase) hex[:16]
//
// Nanosecond timestamp + a 64-bit crypto/rand nonce together guarantee that
// every issued token is unique even when a multi-threaded bot bursts requests
// inside the same nanosecond from the same IP.  The hunt UI groups rows by
// bt; collisions would fold unrelated challenges into one pseudo-session and
// obscure how often a hot bot was actually re-served.
//
// IP binding: both the issuer (ServeChallenge) and verifier (DebugBeacon) use
// clientIP() from the same admin handler, so there is no mismatch (= unlike
// the JA4 binding problem on the captcha _bv cookie).

// beaconTokenTTL: grace period from challenge page delivery to beacon submit.
// Set generously (= 15 min) to allow for humans solving CAPTCHA slowly or
// leaving the tab open.
const beaconTokenTTL = 15 * time.Minute

func beaconSig(secret, issued, nonce, ip string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(issued + ":" + nonce + ":" + ip))
	return hex.EncodeToString(mac.Sum(nil))[:16]
}

// beaconNonce returns a fresh 64-bit base36 nonce.  crypto/rand failures are
// vanishingly rare on a running server; fall back to the nanosecond clock so
// the token still gets *some* per-request randomness rather than crashing.
func beaconNonce() string {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err == nil {
		return strconv.FormatUint(binary.BigEndian.Uint64(buf[:]), 36)
	}
	return strconv.FormatInt(time.Now().UnixNano(), 36)
}

// issueBeaconToken returns a fresh signed token bound to ip.
func issueBeaconToken(secret, ip string) string {
	issued := strconv.FormatInt(time.Now().UnixNano(), 36)
	nonce := beaconNonce()
	return issued + "." + nonce + "." + beaconSig(secret, issued, nonce, ip)
}

// verifyBeaconToken returns true iff token is signed by secret, bound to ip,
// and was issued within beaconTokenTTL.
func verifyBeaconToken(token, secret, ip string) bool {
	if token == "" || secret == "" {
		return false
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return false
	}
	issuedStr, nonce, sig := parts[0], parts[1], parts[2]
	issued, err := strconv.ParseInt(issuedStr, 36, 64)
	if err != nil || issued <= 0 {
		return false
	}
	now := time.Now().UnixNano()
	// Future timestamps (= clock-skew abuse) tolerated only up to 60s.  Past
	// timestamps allowed up to the TTL ceiling.
	if issued > now+int64(60*time.Second) || now-issued > int64(beaconTokenTTL) {
		return false
	}
	return hmac.Equal([]byte(sig), []byte(beaconSig(secret, issuedStr, nonce, ip)))
}
