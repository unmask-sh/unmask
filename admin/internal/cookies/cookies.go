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
// We compute SHA-256 of seed = PowSeed(bvSecret, remoteIP, issued) + ":" + nonce
// and verify that leading-zero-bits >= difficulty.  difficulty is
// settings.Challenge.ResolvedPowDifficulty().
package cookies

import (
	"crypto/hmac"
	"crypto/rand"
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
//
// host binds the cookie to the requested host: the HMAC input includes it, so a
// cookie minted while solving site A's challenge fails verification on site B
// (different host -> different signature).  Without it one solve passed every
// vhost of the install.  Pass the lowercased request host; "" leaves an empty
// host segment (= effectively unbound, for a no-Host request).  MUST stay
// byte-identical to the C plugin's CAPTCHA HMAC input.
func IssueValue(bvSecret, remoteIP, host, kind string) string {
	return issueValueAt(bvSecret, remoteIP, host, kind, nowUnix())
}

func issueValueAt(bvSecret, remoteIP, host, kind string, issued int64) string {
	if kind == "" {
		kind = "captcha"
	}
	msg := strconv.FormatInt(issued, 10) + ":" + remoteIP + ":" + host + ":" + kind
	mac := hmac.New(sha1.New, []byte(bvSecret))
	mac.Write([]byte(msg))
	sig := hex.EncodeToString(mac.Sum(nil))[:16]
	return strconv.FormatInt(issued, 10) + "." + sig + "." + kind
}

// DefaultBVMaxEntries is the default roaming cap -- how many per-IP signatures
// one _bv accumulates (= how many networks a roaming client stays verified on at
// once) when the operator hasn't configured one.  The cap is configurable via
// settings (Rebind.MaxEntries) and clamped to [1, maxVerifyEntries]; the issuer
// (CAPTCHA path here, PoW path in challenge.js) prepends the newest and drops the
// oldest past the cap.  challenge.js reads the same cap from window.UNMASK.
const DefaultBVMaxEntries = 16

// maxVerifyEntries bounds how many ~-joined entries the verifier inspects, so an
// oversized hostile cookie can't force unbounded HMAC/SHA-256 hashing.  It is
// also the hard ceiling for the configurable issuer cap: raising the cap past it
// would also need the native C plugin's matching `n < 16` loop bumped (an atomic
// issuer+plugin redeploy), so AppendEntry and settings both clamp to it.
const maxVerifyEntries = 16

// Verify returns true iff ANY entry in the "~"-delimited _bv list verifies for
// remoteIP within its kind-specific window.  A single-entry value (no "~") is a
// one-element list, so this stays backward compatible.  The any-match lets a
// roaming client hold one signature per IP it verified on (5G / wifi / office),
// so switching networks doesn't re-challenge; the issuer caps the list at the
// configured roaming cap, and a botnet rotating thousands of IPs gains nothing
// because it rarely revisits the same IP (each still costs a fresh solve).
func Verify(value, bvSecret, remoteIP, host string, powValidSeconds, captchaValidSeconds, powDifficulty int) bool {
	if value == "" {
		return false
	}
	for i, entry := range strings.Split(value, "~") {
		if i >= maxVerifyEntries {
			break
		}
		if verifyOne(entry, bvSecret, remoteIP, host, powValidSeconds, captchaValidSeconds, powDifficulty) {
			return true
		}
	}
	return false
}

// MatchingEntryKind returns the kind of the first entry in the "~"-delimited
// _bv list that verifies for remoteIP -- the 3rd segment for the server-issued
// form ("captcha", "rebind", ...), "pow2" for the JS PoW form -- and ok=false
// when none do.  /api/bvj uses the kind to refuse seeding a fresh rebind
// budget off an entry that was itself minted by a rebind (kind "rebind"):
// without that check, every rebound node could mint a fresh lineage at its new
// IP and the per-lineage cap would never accumulate.
func MatchingEntryKind(value, bvSecret, remoteIP, host string, powValidSeconds, captchaValidSeconds, powDifficulty int) (string, bool) {
	if value == "" {
		return "", false
	}
	for i, entry := range strings.Split(value, "~") {
		if i >= maxVerifyEntries {
			break
		}
		if !verifyOne(entry, bvSecret, remoteIP, host, powValidSeconds, captchaValidSeconds, powDifficulty) {
			continue
		}
		parts := strings.Split(entry, ".")
		if len(parts) == 4 {
			return "pow2", true
		}
		return parts[2], true
	}
	return "", false
}

// AppendEntry prepends entry to the "~"-delimited _bv list, keeping at most
// `max` entries (newest first, oldest dropped); blank entries and an exact dup of
// the just-added entry are skipped.  `max` is clamped to [1, maxVerifyEntries] so
// a bad config can't push the list past what the verifier inspects.  Used by the
// CAPTCHA issuer (Go) and mirrored by challenge.js for the PoW path so a roaming
// client accumulates one signature per IP instead of overwriting the previous
// network's.
func AppendEntry(existing, entry string, max int) string {
	if max < 1 {
		max = 1
	} else if max > maxVerifyEntries {
		max = maxVerifyEntries
	}
	entry = strings.TrimSpace(entry)
	if entry == "" {
		return existing
	}
	out := []string{entry}
	for _, e := range strings.Split(existing, "~") {
		if len(out) >= max {
			break
		}
		if e = strings.TrimSpace(e); e == "" || e == entry {
			continue
		}
		out = append(out, e)
	}
	return strings.Join(out, "~")
}

// verifyOne returns true iff `value` is a valid single-entry signature signed
// within the kind-specific validity window for remoteIP.
//
// Two formats are accepted:
//  1. CAPTCHA path  : "<issued_unix>.<HMAC-SHA1 16hex>.<kind>"        (3 segments. issued by server)
//  2. SHA-256 PoW   : "<issued_unix>.pow2.<nonce_b36>.<flags_b36>"    (4 segments. issued by challenge.js)
//
// In the PoW path the client computes the hash in JS and issues the cookie
// itself, but the SEED is server-supplied: window.UNMASK.pow_seed =
// PowSeed(bvSecret, remoteIP, issued).  Binding the seed to the secret + IP is
// what makes the PoW unforgeable (no offline precompute) and non-transferable
// (no cross-IP reuse).  The issued_unix is also server-supplied
// (= window.UNMASK.issued_at), so the client's wall clock has no effect on the
// seed or the validity window.
//
// powValidSeconds / captchaValidSeconds let the server tune the two paths
// independently down to the second.  Browser-side cookie Max-Age is
// decoupled (= fixed at 1 year) so a settings change here takes effect on
// the next request instead of waiting for in-flight cookies to expire.
//
// powDifficulty is the SHA-256 PoW target leading-zero-bits
// (= settings.Challenge.ResolvedPowDifficulty()).
func verifyOne(value, bvSecret, remoteIP, host string, powValidSeconds, captchaValidSeconds, powDifficulty int) bool {
	if value == "" {
		return false
	}
	parts := strings.Split(value, ".")
	// PoW format: 4 segments with parts[1]="pow2" marker.
	if len(parts) == 4 && parts[1] == "pow2" {
		return verifyPowSHA256(parts, bvSecret, remoteIP, host, powValidSeconds, powDifficulty)
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
	// host is folded into the HMAC input, so re-issuing for the CURRENT host
	// reproduces the signature only if the cookie was minted for this same host.
	expected := issueValueAt(bvSecret, remoteIP, host, kind, issued)
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
//	seed   = window.UNMASK.pow_seed   (= server-supplied; see PowSeed)
//	Iterate nonce 0..N and pick the first nonce where the leading zero bits
//	of SHA-256(seed + ":" + nonce) >= pow_difficulty.
//	cookie = issued + ".pow2." + nonce.toString(36) + "." + flags.toString(36)
//
// The server recomputes the seed via PowSeed(bvSecret, remoteIP, issued) and
// re-runs SHA-256, accepting if leading-zero-bits >= powDifficulty.  Because the
// seed binds the BV secret + client IP, the cookie cannot be precomputed offline
// nor reused from another IP.  Falls back to default difficulty 18 if invalid.
// PowSeed derives the server-bound PoW seed for an issuance time + client IP.
// challenge.js receives it (window.UNMASK.pow_seed) and brute-forces a nonce
// over SHA-256(seed + ":" + nonce); the verifier (here, and the C plugin in
// native mode) recomputes the same seed.  Binding the seed to the BV secret
// makes the PoW impossible to precompute offline (an attacker can't derive the
// seed without the secret -- it must fetch the challenge), and binding it to
// the client IP makes a solved cookie non-transferable to other IPs (= a botnet
// can't share one solve, and one solve no longer passes for the whole internet
// for the validity window).  HMAC-SHA1 mirrors the CAPTCHA path so the C plugin
// reuses the same primitive; MUST stay byte-identical to ngx_unmask_pow_seed().
func PowSeed(bvSecret, remoteIP, host string, issued int64) string {
	msg := strconv.FormatInt(issued, 10) + ":" + remoteIP + ":" + host + ":pow_seed"
	mac := hmac.New(sha1.New, []byte(bvSecret))
	mac.Write([]byte(msg))
	return hex.EncodeToString(mac.Sum(nil))
}

func verifyPowSHA256(parts []string, bvSecret, remoteIP, host string, validSeconds, powDifficulty int) bool {
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
	seed := PowSeed(bvSecret, remoteIP, host, issued)
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

// --------------------------------------------------------------------
// _bvj: the roaming-rebind companion cookie
// --------------------------------------------------------------------
//
// _bvj rides alongside _bv but is read ONLY by the admin -- the nginx C plugin
// parses _bv and ignores _bvj entirely.  Its job: when a roaming client whose
// IP changed (a 5G cell handoff hops to a new CGNAT address) lands on the
// challenge route because its _bv no longer verifies for the new IP, the admin
// re-binds a fresh _bv entry for that IP INSTEAD of issuing a PoW, provided the
// request still looks like the same client that solved earlier.
//
// Format (7 dot-separated segments):
//
//	"<issued_unix>.<ja4h>.<uah>.<lineage>.<asn>.<kind>.<sig>"
//	sig = first 16 hex of HMAC-SHA1(
//	        "<issued>:<ja4h>:<uah>:<lineage>:<asn>:<kind>:<host>:bvj", BV_SECRET)
//
// Segments:
//   - ja4h / uah : short hashes of the JA4 + User-Agent the admin saw at solve
//     time (X-Client-JA4 + UA header).  Recomputed from the same headers at
//     rebind time; a mismatch (a stolen cookie replayed by a client with a
//     different TLS stack / UA) refuses rebind.  Both issuer and verifier are
//     the admin reading the SAME headers, so unlike _bv (whose JA4 differs
//     across an L7 LB and is therefore left out of its HMAC) these compare
//     consistently in every deployment.
//   - lineage : random id keying the server-side rebind cap (db.RebindLineage)
//     -- bounds how many times / how fast one solve is re-bound, enforced
//     fleet-wide on a shared DB and across daemon restarts.
//   - asn : autonomous-system number of the IP at solve time (0 = unknown / no
//     ASN db).  Compared to the new IP's ASN at rebind time as a veto: a
//     datacenter replaying a residential solve mismatches and is refused.  With
//     no ASN db loaded the veto is skipped and the cap alone bounds replay
//     (see settings.RebindConfig).
//   - The "bvj" suffix domain-separates this HMAC from the _bv CAPTCHA HMAC
//     even though both key off BV_SECRET.
//
// The host binding mirrors _bv: a _bvj minted on site A can't drive a rebind on
// site B (different host -> different signature).

// JClaims is the validated payload of a _bvj cookie.
type JClaims struct {
	Issued  int64
	JA4Hash string
	UAHash  string
	Lineage string
	ASN     uint
	Kind    string
}

// FingerprintHash returns a short, stable, NON-secret hash of s (a JA4 string
// or a User-Agent) for embedding in _bvj.  It is a length reduction, not a
// security primitive: an attacker who can reproduce the victim's JA4 / UA
// reproduces this hash too.  _bvj's replay resistance comes from the signature,
// the ASN veto and the server-side cap -- never from this hash being secret.
func FingerprintHash(s string) string {
	sum := sha1.Sum([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}

// NewLineage returns a fresh random lineage id (24 hex chars) for a new solve.
func NewLineage() (string, error) {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// IssueJValue builds the _bvj cookie value.  asn is the solve-time ASN (0 if
// unknown / no ASN db).  Mirrors IssueValue's host binding.
func IssueJValue(bvSecret, ja4Hash, uaHash, lineage string, asn uint, host, kind string) string {
	return issueJValueAt(bvSecret, ja4Hash, uaHash, lineage, asn, host, kind, nowUnix())
}

func issueJValueAt(bvSecret, ja4Hash, uaHash, lineage string, asn uint, host, kind string, issued int64) string {
	if kind == "" {
		kind = "captcha"
	}
	asnS := strconv.FormatUint(uint64(asn), 10)
	issuedS := strconv.FormatInt(issued, 10)
	msg := issuedS + ":" + ja4Hash + ":" + uaHash + ":" + lineage + ":" + asnS + ":" + kind + ":" + host + ":bvj"
	mac := hmac.New(sha1.New, []byte(bvSecret))
	mac.Write([]byte(msg))
	sig := hex.EncodeToString(mac.Sum(nil))[:16]
	return issuedS + "." + ja4Hash + "." + uaHash + "." + lineage + "." + asnS + "." + kind + "." + sig
}

// ParseJValue validates a _bvj cookie's signature, host binding and age window,
// returning the claims iff valid.  validSeconds should track the _bv solve
// window so a _bvj never outlives the solve it represents.
func ParseJValue(value, bvSecret, host string, validSeconds int) (JClaims, bool) {
	var zero JClaims
	if value == "" {
		return zero, false
	}
	parts := strings.Split(value, ".")
	if len(parts) != 7 {
		return zero, false
	}
	issued, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return zero, false
	}
	if !withinWindow(issued, validSeconds) {
		return zero, false
	}
	ja4h, uah, lineage, asnS, kind := parts[1], parts[2], parts[3], parts[4], parts[5]
	asn64, err := strconv.ParseUint(asnS, 10, 32)
	if err != nil {
		return zero, false
	}
	expected := issueJValueAt(bvSecret, ja4h, uah, lineage, uint(asn64), host, kind, issued)
	if !hmac.Equal([]byte(expected), []byte(value)) {
		return zero, false
	}
	return JClaims{Issued: issued, JA4Hash: ja4h, UAHash: uah, Lineage: lineage, ASN: uint(asn64), Kind: kind}, true
}
