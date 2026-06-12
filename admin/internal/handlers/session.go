// Session cookie for the admin dashboard.
//
// Format: "<user_id>.<role>.<exp_unix>.<remember>.<sig16>"
//
//	user_id  = unmask_user.id (= int64)
//	role     = "superadmin" | "admin" | "viewer"
//	exp_unix = expiry, unix seconds
//	remember = "1" (= auto-login) / "0".  Decides refresh extension width.
//	sig16    = HMAC-SHA256(secret, "<user_id>.<role>.<exp>.<remember>") hex[:16]
//
// Reuses settings.Secret.BVSecret as the secret (= rotating it invalidates all sessions).
// admin_token has been removed.  Since the user identifier is in the cookie,
// role changes and user deletion are reflected on the next access via DB lookup
// (= cookie content is a snapshot at issue time; acceptable for short-lived cookies).
package handlers

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const sessionCookieName = "unmask_admin_session"

// Session TTL (= 8 hours).  Brute-force resistance is the HMAC's job.
const sessionTTL = 8 * time.Hour

// Session TTL when "remember me" is checked (= 30 days).
const sessionTTLRemember = 30 * 24 * time.Hour

// SessionPayload: contents decoded from the cookie.
type SessionPayload struct {
	UserID   int64
	Role     string
	Exp      int64
	Remember bool
}

// sessionNeedsRefresh: true when less than half the TTL remains.
// A throttle to slide the session forward without Set-Cookie on every request.
func sessionNeedsRefresh(pay *SessionPayload) bool {
	ttl := sessionTTL
	if pay.Remember {
		ttl = sessionTTLRemember
	}
	return time.Until(time.Unix(pay.Exp, 0)) < ttl/2
}

// issueSessionCookie returns a Cookie carrying a fresh signed session for the user.
// remember=true (= "remember me" on the login form) extends TTL to 30 days.
func issueSessionCookie(secret string, userID int64, role string, secure, remember bool) *http.Cookie {
	ttl := sessionTTL
	rememberFlag := "0"
	if remember {
		ttl = sessionTTLRemember
		rememberFlag = "1"
	}
	exp := time.Now().Add(ttl)
	body := strconv.FormatInt(userID, 10) + "." + role + "." + strconv.FormatInt(exp.Unix(), 10) + "." + rememberFlag
	value := body + "." + sessionSign(secret, body)
	return &http.Cookie{
		Name:     sessionCookieName,
		Value:    value,
		Path:     "/",
		Expires:  exp,
		MaxAge:   int(ttl.Seconds()),
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	}
}

// clearSessionCookie returns a Cookie expiring the session.
func clearSessionCookie(secure bool) *http.Cookie {
	return &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	}
}

// verifySessionCookie: verify signature + check expiry.
// Returns the payload on success, nil on failure.
func verifySessionCookie(secret, value string) *SessionPayload {
	if secret == "" || value == "" {
		return nil
	}
	// rsplit "<userID>.<role>.<exp>.<remember>.<sig16>" (= each field is assumed to contain no ".")
	idx := strings.LastIndexByte(value, '.')
	if idx <= 0 || idx >= len(value)-1 {
		return nil
	}
	body := value[:idx]
	sig := value[idx+1:]
	if len(sig) != 16 {
		return nil
	}
	expected := sessionSign(secret, body)
	if !hmac.Equal([]byte(expected), []byte(sig)) {
		return nil
	}
	parts := strings.Split(body, ".")
	if len(parts) != 4 {
		return nil
	}
	uid, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || uid <= 0 {
		return nil
	}
	role := parts[1]
	if role == "" {
		return nil
	}
	exp, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil || exp <= 0 {
		return nil
	}
	if time.Now().Unix() > exp {
		return nil
	}
	return &SessionPayload{UserID: uid, Role: role, Exp: exp, Remember: parts[3] == "1"}
}

func sessionSign(secret, body string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(body))
	// 128-bit signature (32 hex chars).  Was 64-bit ([:16]); widened so a forged
	// session id resists offline brute force.  Both sign and verify route through
	// here, so any in-flight 64-bit cookie simply fails verification and the
	// operator re-logs in (acceptable pre-GA: single operator, no compat burden).
	return hex.EncodeToString(h.Sum(nil))[:32]
}
