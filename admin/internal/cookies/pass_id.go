package cookies

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
)

// PassIDLen is the length of a pass's identity: the first 16 hex digits of a
// CAPTCHA-form entry's signature (all of a 16-digit one), and as many of a
// proof-of-work's seed.  MatchingEntryID derives it the way the plugin's
// $unmask_bv_id does -- the head of a 3-segment entry's signature, the first
// digits of the seed a proof-of-work entry answered (so every nonce that
// answers one seed is one pass) -- and the two MUST stay byte-identical:
// nginx counts the per-pass reuse cap by the one, the daemon reports by the
// other.
const PassIDLen = 16

// SigHexLen and SigHexLenWide are the widths a signature comes in, in hex
// digits: the first 64 bits of the MAC, which is what every release before
// 0.1.58 issued, or the first 128 bits of HMAC-SHA256.  Nothing but its
// width says which form a signature is, so the verifier -- here and in the
// plugin (bv_parser.h: BV_SIG_HEX, BV_SIG_HEX_WIDE) -- takes these two
// widths and no other.
const (
	SigHexLen     = 16
	SigHexLenWide = 32
)

// SigHash names the form the daemon signs in: the MAC, and how much of it a
// signature carries -- for the _bv entries it issues and the _bvj it issues,
// and the MAC alone for the seed it hands the proof-of-work.  The verifier --
// here and in the plugin -- accepts every form, so an install can move its
// issuing from one to the next while the cookies signed before stay good for
// their window; the choice is settings.secret.sig_hash, and DefaultSigHash
// what an install that names none issues with.  A seed is the MAC's first 40
// hex digits whatever the form, so the proof-of-work's wire format does not
// change.
type SigHash int

const (
	// SigSHA1: HMAC-SHA1, a 16-digit signature -- what every release before
	// 0.1.53 signed with, and what an install that names no form still does.
	// Sound as an HMAC; kept so cookies in the wild verify through the move.
	SigSHA1 SigHash = iota
	// SigSHA256: HMAC-SHA256, a 16-digit signature.  Verified by the 0.1.53
	// module and every one since.
	SigSHA256
	// SigSHA256Wide: HMAC-SHA256, a 32-digit signature -- 128 bits, where the
	// two above carry 64.  Verified by the 0.1.58 module and every one since;
	// what `unmask config-init` writes for a new install.
	SigSHA256Wide
)

// SigHashes: the MACs the verifier tries for what has one width whatever the
// MAC -- a 16-digit signature, a proof-of-work seed -- the one issuing moved
// to first.  MUST match the plugin's order (ngx_unmask_sig_hashes).  A
// 32-digit signature is not in this list: it is HMAC-SHA256's alone
// (formsOfWidth).
var SigHashes = []SigHash{SigSHA256, SigSHA1}

// wideForms: the forms a 32-digit signature may be.
var wideForms = []SigHash{SigSHA256Wide}

// formsOfWidth: the forms whose signature is n hex digits, in the order the
// verifier tries them, and nil for a width no form has.  The entry's own
// width picks the list, so a 32-digit signature is never compared with the
// SHA-1 MAC and no entry costs more than two MACs to refuse -- as in the
// plugin (ngx_unmask_bv_verify_one).
func formsOfWidth(n int) []SigHash {
	switch n {
	case SigHexLen:
		return SigHashes
	case SigHexLenWide:
		return wideForms
	}
	return nil
}

// DefaultSigHash: the form an install issues in when settings.secret.sig_hash
// names none.  SHA-1 still: the daemon is replaced by the package at once and
// nginx runs the module it loaded until it is restarted, so a daemon that
// issued a form the running module does not verify would have every pass
// refused and every visitor challenged again.  The default moves only once
// the build that verifies the new form has shipped; a new install has no
// older module to wait for, and config-init names SigSHA256Wide for it.
const DefaultSigHash = SigSHA1

// ParseSigHash reads settings.secret.sig_hash: "" and "sha1" are SigSHA1,
// "sha256" is SigSHA256, "sha256-128" is SigSHA256Wide; anything else is not
// a form (ok=false).
func ParseSigHash(s string) (SigHash, bool) {
	switch s {
	case "", "sha1":
		return SigSHA1, true
	case "sha256":
		return SigSHA256, true
	case "sha256-128":
		return SigSHA256Wide, true
	}
	return SigSHA1, false
}

// String: the settings word.
func (h SigHash) String() string {
	switch h {
	case SigSHA256:
		return "sha256"
	case SigSHA256Wide:
		return "sha256-128"
	}
	return "sha1"
}

// sigHexLen: how many hex digits of the MAC a signature in this form carries.
func (h SigHash) sigHexLen() int {
	if h == SigSHA256Wide {
		return SigHexLenWide
	}
	return SigHexLen
}

// mac: the hex of HMAC_h(key, msg), 40 digits for SHA-1 and 64 for SHA-256;
// the callers cut it to the width their format carries.
func (h SigHash) mac(key, msg string) string {
	f := sha256.New
	if h == SigSHA1 {
		f = sha1.New
	}
	m := hmac.New(f, []byte(key))
	m.Write([]byte(msg))
	return hex.EncodeToString(m.Sum(nil))
}
