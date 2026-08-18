// feedsig.go: ed25519 signatures over the hub feeds.
//
// The bypass-IP feed is trust data -- an address inside it walks past the
// challenge -- so its integrity must not rest on the transport alone.  A
// detached signature published next to the document lets a daemon verify the
// bytes regardless of how they arrived: over TLS, over TLS it could not
// verify (legacy trust stores), or from a file carried in by hand.  That is
// what makes an insecure-transport escape hatch offerable at all: transport
// verification may be waived ONLY when content verification stands in.
//
// ed25519 over an OpenPGP dependency on purpose: crypto/ed25519 is the
// standard library, the signature is 64 bytes, and key rotation is "ship a
// release whose key list contains both".  The private key lives on the
// signing host, never on the host that serves the feed.
//
// Signature file format (one line, next to the document as <name>.sig):
//
//	ed25519:<keyid>:<base64 signature>
//
// keyid = first 16 hex chars of SHA-256(public key), so a verifier can pick
// the right key from its list and a mismatch reads as "unknown key", not
// "corrupt signature".
package nginxconf

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

// FeedSigSuffix: the detached signature sits next to the document.
const FeedSigSuffix = ".sig"

// feedSigningPubKeys: the keys this build trusts, by keyid.  Rotation: add
// the new key here, release, start signing with it, drop the old one a few
// releases later.
var feedSigningPubKeys = func() map[string]ed25519.PublicKey {
	out := map[string]ed25519.PublicKey{}
	for _, hexPub := range []string{
		// unmask.sh feed signing key v1 (2026-08, generated on the build host).
		feedPubKeyV1,
	} {
		if hexPub == "" {
			continue
		}
		raw, err := hex.DecodeString(hexPub)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			continue
		}
		pub := ed25519.PublicKey(raw)
		out[FeedKeyID(pub)] = pub
	}
	return out
}()

// FeedKeyID: first 16 hex chars of SHA-256(pub) -- stable, short, and enough
// to name a key in a signature line and a log message.
func FeedKeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])[:16]
}

// SignFeed produces the one-line signature for body.
func SignFeed(priv ed25519.PrivateKey, body []byte) string {
	sig := ed25519.Sign(priv, body)
	return fmt.Sprintf("ed25519:%s:%s", FeedKeyID(priv.Public().(ed25519.PublicKey)),
		base64.StdEncoding.EncodeToString(sig))
}

// VerifyFeedSignature checks sigLine against body using the trusted key list.
// A nil error means the bytes are exactly what a signing key holder signed.
func VerifyFeedSignature(body, sigLine []byte) error {
	parts := strings.SplitN(strings.TrimSpace(string(sigLine)), ":", 3)
	if len(parts) != 3 || parts[0] != "ed25519" {
		return fmt.Errorf("unrecognized signature format")
	}
	pub, ok := feedSigningPubKeys[parts[1]]
	if !ok {
		return fmt.Errorf("signed by unknown key %s (this build trusts: %s)",
			parts[1], strings.Join(trustedFeedKeyIDs(), ", "))
	}
	sig, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil || len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("malformed signature")
	}
	if !ed25519.Verify(pub, body, sig) {
		return fmt.Errorf("signature does not match the document")
	}
	return nil
}

func trustedFeedKeyIDs() []string {
	out := make([]string, 0, len(feedSigningPubKeys))
	for id := range feedSigningPubKeys {
		out = append(out, id)
	}
	return out
}

// addFeedSigningKeyForTests registers an extra trusted key and returns a
// restore func.  Tests sign with throwaway keys; the production list stays
// exactly the shipped one.
func addFeedSigningKeyForTests(pub ed25519.PublicKey) (restore func()) {
	id := FeedKeyID(pub)
	feedSigningPubKeys[id] = pub
	return func() { delete(feedSigningPubKeys, id) }
}
