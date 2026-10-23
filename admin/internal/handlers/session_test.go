package handlers

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/user"
)

// The session is signed with a key derived from bv_secret, not with
// bv_secret: that value is also in http.inc, which nginx's workers read, and
// a cookie signed with it directly -- the scheme until 0.1.53, and what a
// reader of that file can produce -- must not verify.
func TestSessionKeyIsDerivedFromTheSecret(t *testing.T) {
	const secret = "shared-with-http-inc"
	body := "42." + user.RoleSuperadmin + ".9999999999.0.0"
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(body))
	forged := body + "." + hex.EncodeToString(mac.Sum(nil))[:32]
	if verifySessionCookie(secret, forged) != nil {
		t.Fatal("a cookie signed with bv_secret itself verified")
	}
	key := sessionKey(secret)
	if len(key) != sha256.Size {
		t.Fatalf("the derived key is %d bytes, want %d", len(key), sha256.Size)
	}
	if bytes.Equal(key, []byte(secret)) || bytes.Contains(key, []byte(secret)) {
		t.Fatal("the derived key is the secret")
	}
	if !bytes.Equal(key, sessionKey(secret)) {
		t.Fatal("the derivation is not deterministic: a session would not outlive the request that issued it")
	}
	if bytes.Equal(key, sessionKey(secret+"x")) {
		t.Fatal("two secrets derived the same key")
	}
}

// TestSessionCookieRoundtrip guards sign/verify agreement: a cookie issued by
// issueSessionCookie must verify.  This caught the AUTH-3 regression where the
// signature was widened to 128 bits (32 hex) but verifySessionCookie's length
// gate stayed at 16, rejecting every cookie and breaking admin login.
func TestSessionCookieRoundtrip(t *testing.T) {
	const secret = "roundtrip-secret"
	c := issueSessionCookie(secret, 42, user.RoleSuperadmin, false, false, 0)
	pay := verifySessionCookie(secret, c.Value)
	if pay == nil {
		t.Fatal("a freshly issued session cookie must verify")
	}
	if pay.UserID != 42 || pay.Role != user.RoleSuperadmin {
		t.Errorf("roundtrip mismatch: got uid=%d role=%q", pay.UserID, pay.Role)
	}
	// A different secret must fail.
	if verifySessionCookie("other-secret", c.Value) != nil {
		t.Error("a cookie must not verify under a different secret")
	}
	// A tampered signature must fail.
	if verifySessionCookie(secret, c.Value+"x") != nil {
		t.Error("a tampered cookie must not verify")
	}
}
