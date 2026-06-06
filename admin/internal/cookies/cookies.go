// Package cookies: issue and verify the _bv cookie.
//
// Format:
//
//	"<issued_unix>.<sig>.<kind>"        // kind is a free-form ASCII string (e.g. "captcha")
//	sig = first 16 hex chars of HMAC-SHA1("<issued_unix>:<remote_ip>:<kind>", BV_SECRET)
//
// The first segment is the issuance unix timestamp in seconds (= second
// granularity).  Previously this was floor(unix/86400) (= day buckets), but
// per-second resolution lets the admin set arbitrary validity windows (= 5
// minutes, 12 hours, 8 days, ...) instead of being rounded up to whole days.
//
// To keep the client's wall clock out of the loop (= clock skew used to be
// absorbed by the 1-day bucket), the issuance time is always SERVER-side:
// the challenge HTML injects window.UNMASK.issued_at = server.Now().Unix(),
// and challenge.js uses that as the cookie's first segment + the PoW seed.
// The admin's /verify endpoint uses time.Now().Unix() at issuance time for
// the CAPTCHA path.  No code path uses the client's Date.now().
//
// JA4 is NOT in the HMAC input.  Behind an L7 LB / proxy, the JA4 that the
// issuer (admin) sees (= the real client JA4 forwarded via header) and the
// JA4 the verifier (nginx plugin) sees (= the LB <-> nginx handshake JA4)
// will differ, so verification would always fail.  Replay protection is
// handled by the remote_ip binding (= once realip module has run, both
// sides see the real client IP).
//
// The PoW path (= cookie issued by challenge.js) is the 4-segment SHA-256 form:
//
//	"<issued_unix>.pow2.<nonce_b36>.<flags_b36>"  (parts[1]="pow2" marker)
//
// We compute SHA-256 of seed = "<issued_unix>_unmask" + ":" + nonce and verify
// that leading-zero-bits >= difficulty.  difficulty is
// settings.Challenge.ResolvedPowDifficulty().
package cookies

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"time"
)

// futureSkewToleranceSeconds: a cookie whose issued_unix is up to this many
// seconds in the future is still accepted.  Server clocks (admin + nginx +
// PoW seed) are normally within ms of each other, but NTP slewing or a small
// drift between the admin host and an external nginx box could put issuance
// a few seconds ahead of verification.  60 s is plenty.
const futureSkewToleranceSeconds = 60

// nowUnix returns time.Now().Unix() (= isolated for tests via build tag if
// ever needed, for now plain).
func nowUnix() int64 { return time.Now().Unix() }

// IssueValue computes the cookie value for `Set-Cookie: _bv=<value>`.  Uses
// the server's current unix time as the issuance timestamp.
func IssueValue(bvSecret, remoteIP, kind string) string {
	return issueValueAt(bvSecret, remoteIP, kind, nowUnix())
}

func issueValueAt(bvSecret, remoteIP, kind string, issued int64) string {
	if kind == "" {
		kind = "captcha"
	}
	msg := strconv.FormatInt(issued, 10) + ":" + remoteIP + ":" + kind
	mac := hmac.New(sha1.New, []byte(bvSecret))
	mac.Write([]byte(msg))
	sig := hex.EncodeToString(mac.Sum(nil))[:16]
	return strconv.FormatInt(issued, 10) + "." + sig + "." + kind
}

// Verify returns true iff `value` is a valid signature signed within the
// kind-specific validity window for remoteIP.
//
// Two formats are accepted:
//  1. CAPTCHA path  : "<issued_unix>.<HMAC-SHA1 16hex>.<kind>"        (3 segments. issued by server)
//  2. SHA-256 PoW   : "<issued_unix>.pow2.<nonce_b36>.<flags_b36>"    (4 segments. issued by challenge.js)
//
// In the PoW path the client computes the hash in JS and issues the cookie
// itself, so bv_secret is not passed to the server (= the seed challenge.js
// computes is the fixed value issued + "_unmask").  The issued_unix is
// server-supplied (= window.UNMASK.issued_at), so the client's wall clock
// has no effect on either the seed or the validity window.
//
// powValidSeconds / captchaValidSeconds let the server tune the two paths
// independently down to the second.  Browser-side cookie Max-Age is
// decoupled (= fixed at 1 year) so a settings change here takes effect on
// the next request instead of waiting for in-flight cookies to expire.
//
// powDifficulty is the SHA-256 PoW target leading-zero-bits
// (= settings.Challenge.ResolvedPowDifficulty()).
func Verify(value, bvSecret, remoteIP string, powValidSeconds, captchaValidSeconds, powDifficulty int) bool {
	if value == "" {
		return false
	}
	parts := strings.Split(value, ".")
	// PoW format: 4 segments with parts[1]="pow2" marker.
	if len(parts) == 4 && parts[1] == "pow2" {
		return verifyPowSHA256(parts, powValidSeconds, powDifficulty)
	}
	// CAPTCHA format: 3 segments.  Verify via HMAC.
	if len(parts) != 3 {
		return false
	}
	issued, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return false
	}
	kind := parts[2]
	if !withinWindow(issued, captchaValidSeconds) {
		return false
	}
	expected := issueValueAt(bvSecret, remoteIP, kind, issued)
	return hmac.Equal([]byte(expected), []byte(value))
}

// withinWindow: true iff issued is no further in the future than the small
// skew tolerance AND not older than validSeconds.
func withinWindow(issued int64, validSeconds int) bool {
	now := nowUnix()
	if issued > now+futureSkewToleranceSeconds {
		return false
	}
	if now-issued > int64(validSeconds) {
		return false
	}
	return true
}

// verifyPowSHA256: verify the SHA-256 PoW cookie issued by challenge.js.
//
// challenge.js generation logic (= matches sha256() + the solve loop in challenge.js):
//
//	issued = window.UNMASK.issued_at  (= server-supplied unix seconds)
//	seed   = issued + "_unmask"
//	Iterate nonce 0..N and pick the first nonce where the leading zero bits
//	of SHA-256(seed + ":" + nonce) >= pow_difficulty.
//	cookie = issued + ".pow2." + nonce.toString(36) + "." + flags.toString(36)
//
// The server recomputes SHA-256 with the same seed and accepts if
// leading-zero-bits >= powDifficulty.  Falls back to default 18 if
// powDifficulty is invalid (= 0 etc.).
func verifyPowSHA256(parts []string, validSeconds, powDifficulty int) bool {
	if powDifficulty < 8 || powDifficulty > 24 {
		powDifficulty = 18
	}
	issuedStr, nonceB36 := parts[0], parts[2]
	// parts[3] = flags (not verified).  parts[1] = "pow2" already detected.
	issued, err := strconv.ParseInt(issuedStr, 10, 64)
	if err != nil {
		return false
	}
	if !withinWindow(issued, validSeconds) {
		return false
	}
	nonce, err := strconv.ParseInt(nonceB36, 36, 64)
	if err != nil || nonce < 0 {
		return false
	}
	seed := strconv.FormatInt(issued, 10) + "_unmask"
	input := seed + ":" + strconv.FormatInt(nonce, 10)
	sum := sha256.Sum256([]byte(input))
	return leadingZeroBits(sum[:]) >= powDifficulty
}

// leadingZeroBits: count the number of leading zero bits from the MSB end of
// the byte slice.  Matches the same-name function in challenge.js
// (= big-endian, counts from the MSB of byte 0).
func leadingZeroBits(b []byte) int {
	bits := 0
	for _, v := range b {
		if v == 0 {
			bits += 8
			continue
		}
		// leading-zero count within the non-zero byte
		for mask := byte(0x80); mask != 0; mask >>= 1 {
			if v&mask != 0 {
				return bits
			}
			bits++
		}
		return bits
	}
	return bits
}
