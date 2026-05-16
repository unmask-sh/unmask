// Package cookies: issue and verify the _bv cookie.
//
// Format:
//
//	"<day>.<sig>.<kind>"        // kind is a free-form ASCII string (e.g. "captcha")
//	sig = first 16 hex chars of HMAC-SHA1("<day>:<remote_ip>:<kind>", BV_SECRET)
//
// JA4 is NOT in the HMAC input.  Behind an L7 LB / proxy, the JA4 that the
// issuer (admin) sees (= the real client JA4 forwarded via header) and the
// JA4 the verifier (nginx plugin) sees (= the LB <-> nginx handshake JA4)
// will differ, so verification would always fail.  Replay protection is
// instead handled by the remote_ip binding (= once realip module has run,
// both sides see the real client IP).
//
// day is floor(time.Unix() / 86400).  By reproducing the same logic on the
// nginx side, the cookie alone is enough to skip the challenge.  Validity
// is config.cookie_days (default 3 days).
//
// The PoW path (= cookie issued by challenge.js) is the 4-segment form with
// two variants:
//   legacy djb2 : "<day>.<djb2-hex>.<target_b36>.<flags_b36>"   (= v0.0, deprecated)
//   SHA-256     : "<day>.pow2.<nonce_b36>.<flags_b36>"          (= v0.1+, parts[1]="pow2" marker)
// For SHA-256 we compute SHA-256 of seed = "<day>_uic" + ":" + nonce and
// verify that leading-zero-bits >= difficulty.  difficulty is
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

// dayNow returns floor(unix / 86400).
func dayNow() int64 { return time.Now().Unix() / 86400 }

// IssueValue computes the cookie value for `Set-Cookie: _bv=<value>`.
func IssueValue(bvSecret, remoteIP, kind string) string {
	return issueValueAt(bvSecret, remoteIP, kind, dayNow())
}

func issueValueAt(bvSecret, remoteIP, kind string, day int64) string {
	if kind == "" {
		kind = "captcha"
	}
	msg := strconv.FormatInt(day, 10) + ":" + remoteIP + ":" + kind
	mac := hmac.New(sha1.New, []byte(bvSecret))
	mac.Write([]byte(msg))
	sig := hex.EncodeToString(mac.Sum(nil))[:16]
	return strconv.FormatInt(day, 10) + "." + sig + "." + kind
}

// Verify returns true iff `value` is a valid signature signed within
// validDays days for remoteIP.
//
// Three formats are accepted:
//   1. CAPTCHA path  : "<day>.<HMAC-SHA1 16hex>.<kind>"             (3 segments. issued by server)
//   2. SHA-256 PoW   : "<day>.pow2.<nonce_b36>.<flags_b36>"         (4 segments. v0.1+ challenge.js)
//   3. legacy djb2   : "<day>.<djb2 hex>.<target_b36>.<flags_b36>"  (4 segments. v0.0, deprecated)
//
// In the PoW path the client computes the hash in JS and issues the cookie
// itself, so bv_secret is not passed to the server (= the seed
// challenge.js computes is the fixed value dayNum + "_uic").  This must
// match challenge.js's hash logic exactly.
//
// powDifficulty is the SHA-256 PoW target leading-zero-bits
// (= settings.Challenge.ResolvedPowDifficulty()).  Unused for the legacy
// djb2 path.
func Verify(value, bvSecret, remoteIP string, validDays, powDifficulty int) bool {
	if value == "" {
		return false
	}
	parts := strings.Split(value, ".")
	// PoW format: 4 segments.
	if len(parts) == 4 {
		// parts[1]="pow2" marker -> SHA-256 verify.  Otherwise -> legacy djb2 (= deprecated).
		if parts[1] == "pow2" {
			return verifyPowSHA256(parts, validDays, powDifficulty)
		}
		return verifyPoW(parts, validDays)
	}
	// CAPTCHA format: 3 segments.  Verify via HMAC.
	if len(parts) != 3 {
		return false
	}
	day, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return false
	}
	kind := parts[2]
	today := dayNow()
	if day > today || today-day > int64(validDays) {
		return false
	}
	expected := issueValueAt(bvSecret, remoteIP, kind, day)
	return hmac.Equal([]byte(expected), []byte(value))
}

// verifyPoW: verify the _bv cookie issued by challenge.js after PoW completion.
//
// challenge.js generation logic:
//
//	day  = Math.floor(Date.now() / 86400000)
//	seed = day + "_uic"
//	Search for nonce in 0..N where djb2(seed + "_" + nonce) & 0xFFF === 0.
//	Call that nonce `target`.
//	proof = djb2(seed + "_" + target)
//	v = Math.abs(proof).toString(36)   // the sig part of the cookie
//	cookie = day + "." + v + "." + target.toString(36) + "." + flags.toString(36)
//
// The server reproduces the same logic to compute proof and accepts on match.
func verifyPoW(parts []string, validDays int) bool {
	dayStr, sigB36, targetB36 := parts[0], parts[1], parts[2]
	// parts[3] is flags.  Not needed for verification.
	day, err := strconv.ParseInt(dayStr, 10, 64)
	if err != nil {
		return false
	}
	today := dayNow()
	if day > today || today-day > int64(validDays) {
		return false
	}
	target, err := strconv.ParseInt(targetB36, 36, 64)
	if err != nil {
		return false
	}
	seed := strconv.FormatInt(day, 10) + "_uic"
	proof := djb2(seed + "_" + strconv.FormatInt(target, 10))
	// JS Math.abs(int32) turns a negative into a positive.  Absorb that
	// via Go int32 -> uint32 -> big int.
	if proof < 0 {
		// Reproduce JS Math.abs(-2147483648) = 2147483648 (= 0x80000000).
		// Abs the Go int32 -X and represent as uint32.
		proof = -proof
	}
	expectedSig := strconv.FormatInt(proof, 36)
	return expectedSig == sigB36
}

// djb2: the same hash logic challenge.js uses.  32-bit signed arithmetic.
//
//	JS: h = ((h<<5) + h) + str.charCodeAt(i); h |= 0;
//	         (= int32 wrap)
func djb2(s string) int64 {
	var h int32 = 5381
	for i := 0; i < len(s); i++ {
		h = (h << 5) + h + int32(s[i])
	}
	return int64(h)
}

// verifyPowSHA256: verify the SHA-256 PoW cookie issued by challenge.js v0.1+.
//
// challenge.js generation logic (= matches sha256() + the solve loop in challenge.js):
//
//	day    = Math.floor(Date.now() / 86400000)
//	seed   = day + "_uic"
//	Iterate nonce 0..N and pick the first nonce where the leading zero bits
//	of SHA-256(seed + ":" + nonce) >= pow_difficulty.
//	cookie = day + ".pow2." + nonce.toString(36) + "." + flags.toString(36)
//
// The server recomputes SHA-256 with the same seed and accepts if
// leading-zero-bits >= powDifficulty.  Falls back to default 18 if
// powDifficulty is invalid (= 0 etc.).
func verifyPowSHA256(parts []string, validDays, powDifficulty int) bool {
	if powDifficulty < 8 || powDifficulty > 24 {
		powDifficulty = 18
	}
	dayStr, nonceB36 := parts[0], parts[2]
	// parts[3] = flags (not verified).  parts[1] = "pow2" already detected.
	day, err := strconv.ParseInt(dayStr, 10, 64)
	if err != nil {
		return false
	}
	today := dayNow()
	if day > today || today-day > int64(validDays) {
		return false
	}
	nonce, err := strconv.ParseInt(nonceB36, 36, 64)
	if err != nil || nonce < 0 {
		return false
	}
	seed := strconv.FormatInt(day, 10) + "_uic"
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
