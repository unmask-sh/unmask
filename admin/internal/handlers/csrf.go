// CSRF protection for admin POST endpoints, double-submit cookie style.
//
// The admin session is a stateless HMAC-signed cookie (= no DB row to
// bind a token to), so we issue a separate, JS-readable cookie at
// login and require the same value back in a hidden form field on
// every authenticated POST.  The protection is that echo: a cross-site
// attacker cannot read the cookie to fill the field (same-origin
// policy), so the comparison fails whether or not the cookie itself
// rode along on the forged request.
//
// SameSite is Lax -- deliberately the SAME as the session cookie, NOT
// Strict.  Chrome withholds Strict cookies from every hop of a redirect
// chain whose initiator was cross-site (external link / bookmark, and
// any reload of the resulting error page) while still sending the Lax
// session cookie on those top-level GETs.  A Strict CSRF cookie
// therefore reads as "session present, CSRF absent" on every hop of
// such a chain -- the state that turned AuthMiddleware's backfill into
// a 303 self-redirect loop and locked an operator out of /unmask/admin/
// (web1-jp, 2026-07-10).  Lax only ever attaches the cookie to
// top-level GET navigations, which never mutate state here, so the
// double-submit property is unchanged.
//
// Login submit is intentionally exempt: there is no session yet, so
// nothing to bind a token against, and the handlers' own per-IP
// loginThrottle bounds credential stuffing.
package handlers

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	csrfCookieName = "unmask_admin_csrf"
	csrfFieldName  = "_csrf"
	csrfTokenLen   = 32 // bytes -> 64 hex chars
)

// newCSRFToken returns a fresh random token (= 32 random bytes, hex).
// Sourced from crypto/rand so it cannot be guessed.
func newCSRFToken() (string, error) {
	var b [csrfTokenLen]byte
	if _, err := io.ReadFull(rand.Reader, b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// issueCSRFCookie returns a Cookie carrying a fresh CSRF token.  The
// expiry matches the session's max TTL so an operator who picked
// "remember me" doesn't see the CSRF cookie expire first and lose
// their next POST to a 403.
func issueCSRFCookie(value string, secure, remember bool) *http.Cookie {
	ttl := sessionTTL
	if remember {
		ttl = sessionTTLRemember
	}
	exp := time.Now().Add(ttl)
	return &http.Cookie{
		Name:     csrfCookieName,
		Value:    value,
		Path:     "/",
		Expires:  exp,
		MaxAge:   int(ttl.Seconds()),
		HttpOnly: false, // readable by the (same-origin) JS that the form ships, but cross-origin reads are blocked by SOP regardless
		Secure:   secure,
		SameSite: http.SameSiteLaxMode, // match the session cookie; see the package comment
	}
}

// clearCSRFCookie returns a Cookie that expires the CSRF token.  Used
// from the logout path so a fresh login starts with a fresh token.
func clearCSRFCookie(secure bool) *http.Cookie {
	return &http.Cookie{
		Name:     csrfCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: false,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	}
}

// csrfIssuedCtxKey carries a CSRF token that THIS response just issued via
// Set-Cookie, for requests that arrived without the cookie.  AuthMiddleware's
// backfill stashes it so the page renders its forms with the token whose cookie
// is landing in the same response -- instead of self-redirecting to re-read the
// cookie, which has no terminating condition when the client does not return it
// (the 303 loop that locked an operator out of /unmask/admin/).
type csrfIssuedCtxKey struct{}

// withIssuedCSRFToken returns r with tok attached; CSRFTokenFromRequest falls
// back to it when the request carries no CSRF cookie.
func withIssuedCSRFToken(r *http.Request, tok string) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), csrfIssuedCtxKey{}, tok))
}

// CSRFTokenFromRequest returns the active CSRF token: the cookie value, or --
// when the request carries no cookie -- the token this response just issued
// (see withIssuedCSRFToken).  "" when neither exists.  Templates render this
// through the shared layout data so every form auto-embeds it.
func CSRFTokenFromRequest(r *http.Request) string {
	if r == nil {
		return ""
	}
	if c, err := r.Cookie(csrfCookieName); err == nil && c != nil && c.Value != "" {
		return c.Value
	}
	if tok, ok := r.Context().Value(csrfIssuedCtxKey{}).(string); ok {
		return tok
	}
	return ""
}

// csrfHeaderName is the request header fetch / XHR echo the token in.
// The global init_csrf shim (= partial_header_tools.html) adds it to every
// same-origin mutating fetch, so /admin/api/* JSON endpoints are covered
// without each call site threading a form field.
const csrfHeaderName = "X-CSRF-Token"

// verifyCSRF returns true when the request echoes the CSRF cookie back via
// any accepted channel: the X-CSRF-Token header (fetch / XHR), the _csrf
// form field (url-encoded native forms), or the _csrf URL query param
// (multipart native forms, whose body ParseForm does not read).  Missing
// cookie / missing echo / mismatch all collapse to one rejection so the
// response leaks nothing.
func verifyCSRF(r *http.Request) bool {
	cookieTok := CSRFTokenFromRequest(r)
	if cookieTok == "" {
		return false
	}
	// Header first: it needs no body parse, so it works for JSON-body
	// fetches where ParseForm read nothing.
	echo := strings.TrimSpace(r.Header.Get(csrfHeaderName))
	if echo == "" {
		echo = strings.TrimSpace(r.PostFormValue(csrfFieldName))
	}
	if echo == "" {
		// Multipart native forms: the field rides in the multipart body
		// (which ParseForm skips), so the shim mirrors it into the action
		// query where it is parse-free to read here.
		echo = strings.TrimSpace(r.URL.Query().Get(csrfFieldName))
	}
	if echo == "" {
		return false
	}
	if subtle.ConstantTimeCompare([]byte(cookieTok), []byte(echo)) != 1 {
		return false
	}
	return true
}

// RequireCSRF wraps a POST handler with a token check.  ParseForm is
// invoked before verifyCSRF so multipart bodies and url-encoded bodies
// both work; the wrapped handler reads the same form values normally.
// 403 + a short body is the only failure mode; this is intentional --
// "your session expired, reload the page" is the operator-facing
// recovery, and there is no point leaking which side mismatched.
func (h *Handler) RequireCSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "form parse error", http.StatusBadRequest)
			return
		}
		if !verifyCSRF(r) {
			http.Error(w, "csrf token mismatch (= reload the page and retry)", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RequireCSRFFunc is the http.HandlerFunc-shaped sibling of
// RequireCSRF, matching the wiring style used by routes that call
// HandleFunc directly.
func (h *Handler) RequireCSRFFunc(next http.HandlerFunc) http.HandlerFunc {
	wrapped := h.RequireCSRF(http.HandlerFunc(next))
	return func(w http.ResponseWriter, r *http.Request) {
		wrapped.ServeHTTP(w, r)
	}
}
