// Session cookie for the admin dashboard.
//
// Format: "<user_id>.<role>.<exp_unix>.<remember>.<gen>.<sig>"
//
//	user_id  = unmask_user.id (= int64)
//	role     = "superadmin" | "admin" | "viewer"
//	exp_unix = expiry, unix seconds
//	remember = "1" (= auto-login) / "0".  Decides refresh extension width.
//	gen      = unmask_user.session_gen at issue.  AuthMiddleware refuses the
//	           cookie once the account's value differs: a password change and
//	           a suspension advance it, which is how a cookie with no server-
//	           side row gets revoked.  Added 2026-10 -- a cookie issued before
//	           then has one field fewer and fails verification, so the upgrade
//	           signs every operator out once.
//	sig      = HMAC-SHA256(sessionKey(bv_secret), "<user_id>.<role>.<exp>.<remember>.<gen>") hex[:32]
//
// The key is derived from settings.Secret.BVSecret (sessionKey), so rotating
// bv_secret invalidates all sessions; bv_secret itself signs nothing here.
// admin_token has been removed.  Since the user identifier is in the cookie,
// role changes and user deletion are reflected on the next access via DB lookup
// (= cookie content is a snapshot at issue time; acceptable for short-lived cookies).
package handlers

import (
	"crypto/hkdf"
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
	// Gen: the account's session generation the cookie was issued under
	// (user.User.SessionGen).
	Gen int64
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
// gen is the account's current session generation; the cookie is good only
// while the account keeps it.
func issueSessionCookie(secret string, userID int64, role string, secure, remember bool, gen int64) *http.Cookie {
	ttl := sessionTTL
	rememberFlag := "0"
	if remember {
		ttl = sessionTTLRemember
		rememberFlag = "1"
	}
	exp := time.Now().Add(ttl)
	body := strconv.FormatInt(userID, 10) + "." + role + "." + strconv.FormatInt(exp.Unix(), 10) + "." + rememberFlag + "." + strconv.FormatInt(gen, 10)
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
// Returns the payload on success, nil on failure.  The generation is NOT
// checked here -- that takes the account's row, which AuthMiddleware reads.
func verifySessionCookie(secret, value string) *SessionPayload {
	if secret == "" || value == "" {
		return nil
	}
	// rsplit "<userID>.<role>.<exp>.<remember>.<gen>.<sig>" (= each field is assumed to contain no ".")
	idx := strings.LastIndexByte(value, '.')
	if idx <= 0 || idx >= len(value)-1 {
		return nil
	}
	body := value[:idx]
	sig := value[idx+1:]
	// 32 hex chars = the 128-bit signature sessionSign emits.  (This length
	// gate was left at 16 when AUTH-3 widened the signature, which rejected
	// every cookie and broke login; sign and verify must agree.)
	if len(sig) != 32 {
		return nil
	}
	expected := sessionSign(secret, body)
	if !hmac.Equal([]byte(expected), []byte(sig)) {
		return nil
	}
	parts := strings.Split(body, ".")
	if len(parts) != 5 {
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
	gen, err := strconv.ParseInt(parts[4], 10, 64)
	if err != nil || gen < 0 {
		return nil
	}
	return &SessionPayload{UserID: uid, Role: role, Exp: exp, Remember: parts[3] == "1", Gen: gen}
}

// sessionKeyInfo labels the admin-session key among the keys derived from
// bv_secret; a key for another use takes another label.
const sessionKeyInfo = "unmask admin session v1"

// sessionKey derives the session-signing key from bv_secret (HKDF-SHA256,
// RFC 5869) instead of signing with bv_secret itself.  bv_secret is also
// written into http.inc, which nginx's workers read (0640, the nginx group),
// so until 0.1.53 whoever could read that file -- a process in the nginx
// group, a copy of /var/lib/unmask -- could sign a superadmin session with
// it.  The derivation is one way: the derived key signs sessions and nothing
// else, and holding it tells nothing about bv_secret or the _bv cookies.
// Derived on every call (three hashes) rather than cached, so a rotated
// bv_secret takes effect on the next request as before; a cookie signed
// under the old scheme fails verification once, like one from before the
// generation field.
func sessionKey(secret string) []byte {
	key, err := hkdf.Key(sha256.New, []byte(secret), nil, sessionKeyInfo, sha256.Size)
	if err != nil {
		// Only a length over 255 hashes fails, and this one is fixed; an
		// empty key still signs and verifies alike, so nobody is locked out.
		return nil
	}
	return key
}

func sessionSign(secret, body string) string {
	h := hmac.New(sha256.New, sessionKey(secret))
	h.Write([]byte(body))
	// 128-bit signature (32 hex chars).  Was 64-bit ([:16]); widened so a forged
	// session id resists offline brute force.  Both sign and verify route through
	// here, so any in-flight 64-bit cookie simply fails verification and the
	// operator re-logs in (acceptable pre-GA: single operator, no compat burden).
	return hex.EncodeToString(h.Sum(nil))[:32]
}

// reissueSessionAfterPasswordChange hands the session that just changed
// userID's password a cookie under the account's new generation.  SetPassword
// advanced the generation, which ends every session the account holds -- the
// point of it -- but the one that made the change would otherwise be sent to
// the login page by its own save.  Only that session gets a new cookie
// (the request's session must be the account's); the others end.
func (h *Handler) reissueSessionAfterPasswordChange(w http.ResponseWriter, r *http.Request, userID int64) {
	pay := SessionFromContext(r)
	if pay == nil || pay.UserID != userID || h.UserRepo == nil {
		return
	}
	u, err := h.UserRepo.GetByID(r.Context(), userID)
	if err != nil {
		return
	}
	secure := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
	http.SetCookie(w, issueSessionCookie(h.cfg().Secret.BVSecret, u.ID, u.Role, secure, pay.Remember, u.SessionGen))
}
