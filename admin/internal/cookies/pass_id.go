package cookies

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
)

// PassIDLen is the length of a pass's identity: the 16 hex digits of a
// CAPTCHA-form entry's signature, and as many of a proof-of-work's seed.
// MatchingEntryID derives it the way the plugin's $unmask_bv_id does -- the
// signature of a 3-segment entry, the first digits of the seed a
// proof-of-work entry answered (so every nonce that answers one seed is one
// pass) -- and the two MUST stay byte-identical: nginx counts the per-pass
// reuse cap by the one, the daemon reports by the other.
const PassIDLen = 16

// SigHash names the MAC the daemon signs with: the _bv entries it issues,
// the _bvj it issues, and the seed it hands the proof-of-work.  The
// verifier -- here and in the plugin -- accepts every SigHash, in the order
// of SigHashes, so an install can move its issuing from one to the other
// while the cookies signed before stay good for their window; the choice is
// settings.secret.sig_hash, and DefaultSigHash what an install that names
// none issues with.  The MAC is cut to 16 hex digits for a signature and to
// 40 for a seed whatever the hash, so the wire formats do not change.
type SigHash int

const (
	// SigSHA1: HMAC-SHA1, what every release so far signed with.  Sound as
	// an HMAC; kept so cookies in the wild verify through the move.
	SigSHA1 SigHash = iota
	// SigSHA256: HMAC-SHA256.
	SigSHA256
)

// SigHashes: every hash the verifier tries, the one issuing moves to first.
// MUST match the plugin's order (ngx_unmask_bv_verify_one, the PoW verifier).
var SigHashes = []SigHash{SigSHA256, SigSHA1}

// DefaultSigHash: the hash an install issues with when settings.secret.sig_hash
// names none.  SHA-1 in this release: an nginx whose plugin has not been
// restarted onto a build that verifies SHA-256 would refuse every cookie
// issued with it, so the default moves only once that build has shipped.
const DefaultSigHash = SigSHA1

// ParseSigHash reads settings.secret.sig_hash: "" and "sha1" are SigSHA1,
// "sha256" is SigSHA256; anything else is not a hash (ok=false).
func ParseSigHash(s string) (SigHash, bool) {
	switch s {
	case "", "sha1":
		return SigSHA1, true
	case "sha256":
		return SigSHA256, true
	}
	return SigSHA1, false
}

// String: the settings word.
func (h SigHash) String() string {
	if h == SigSHA256 {
		return "sha256"
	}
	return "sha1"
}

// mac: the hex of HMAC_h(key, msg), 40 digits for SHA-1 and 64 for SHA-256;
// the callers cut it to the width their format carries.
func (h SigHash) mac(key, msg string) string {
	f := sha1.New
	if h == SigSHA256 {
		f = sha256.New
	}
	m := hmac.New(f, []byte(key))
	m.Write([]byte(msg))
	return hex.EncodeToString(m.Sum(nil))
}
