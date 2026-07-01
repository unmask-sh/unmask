package handlers

import (
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/user"
)

// TestSessionCookieRoundtrip guards sign/verify agreement: a cookie issued by
// issueSessionCookie must verify.  This caught the AUTH-3 regression where the
// signature was widened to 128 bits (32 hex) but verifySessionCookie's length
// gate stayed at 16, rejecting every cookie and breaking admin login.
func TestSessionCookieRoundtrip(t *testing.T) {
	const secret = "roundtrip-secret"
	c := issueSessionCookie(secret, 42, user.RoleSuperadmin, false, false)
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
