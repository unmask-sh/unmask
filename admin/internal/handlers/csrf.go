// CSRF protection for admin POST endpoints: a token derived from the session.
//
// The admin session is a stateless HMAC-signed cookie (= no DB row to bind
// a token to), so the token is derived from it: HMAC-SHA256, under a key of
// its own (csrfKey, from bv_secret by HKDF like the session key), over the
// session cookie's signature.  A request's token is right when it equals
// the one derived from the session cookie the request carries, and nothing
// else is compared.  The token reaches the page two ways: the layout embeds
// it in every form (CSRFTokenFromRequest), and a JS-readable cookie carries
// the same value for the global shim (partial_header_tools.html), which
// fills a hidden _csrf field on submit and an X-CSRF-Token header on fetch.
//
// Until 0.1.53 this was a double-submit cookie: a random token in the
// cookie, compared with the field.  A sibling host -- any name under the
// same registrable domain can set a cookie for the parent domain -- could
// plant both the cookie and the field's value and pass the check for a
// victim's session.  Derived from the session, the cookie has no say in the
// verdict: a planted cookie with a matching field still fails, since
// neither is the HMAC over the victim's session signature, which takes the
// key.
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
// top-level GET navigations, which never mutate state here.
//
// Login submit is intentionally exempt: there is no session yet, so
// nothing to derive a token from, and the handlers' own per-IP
// loginThrottle bounds credential stuffing.
package handlers

import (
	"context"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"strings"
	"time"
)

const (
	csrfCookieName = "unmask_admin_csrf"
	csrfFieldName  = "_csrf"
	// csrfKeyInfo labels the CSRF key among the keys derived from bv_secret
	// (sessionKeyInfo is the session's) and prefixes what the token signs.
	csrfKeyInfo = "unmask admin csrf v1"
)

// csrfKey derives the token-signing key from bv_secret (HKDF-SHA256), the
// way sessionKey does for the session, under its own label: holding one of
// the derived keys says nothing about the other or about bv_secret.
func csrfKey(secret string) []byte {
	key, err := hkdf.Key(sha256.New, []byte(secret), nil, csrfKeyInfo, sha256.Size)
	if err != nil {
		// Only a label over 255 hashes fails, and this one is fixed.
		return nil
	}
	return key
}

// csrfTokenFor returns the CSRF token of a session cookie value:
// hex(HMAC-SHA256(csrfKey, csrfKeyInfo + "|" + the value's signature part)).
// The signature is what makes the session the operator's -- it changes with
// every issue, so a refreshed session has a new token -- and the HMAC is
// what a page on another origin cannot compute.  "" for a value with no
// signature part.
func csrfTokenFor(secret, sessionValue string) string {
	i := strings.LastIndexByte(sessionValue, '.')
	if i < 0 || i >= len(sessionValue)-1 {
		return ""
	}
	h := hmac.New(sha256.New, csrfKey(secret))
	h.Write([]byte(csrfKeyInfo + "|" + sessionValue[i+1:]))
	return hex.EncodeToString(h.Sum(nil))
}

// csrfTokenOf: the token for the session cookie r carries, "" without one.
func csrfTokenOf(secret string, r *http.Request) string {
	c, err := r.Cookie(sessionCookieName)
	if err != nil || c.Value == "" {
		return ""
	}
	return csrfTokenFor(secret, c.Value)
}

// issueCSRFCookie returns a Cookie carrying the CSRF token for the shim to
// read, on the admin's own path (adminCookiePath).  The expiry matches the
// session's max TTL so an operator who picked "remember me" doesn't see the
// CSRF cookie expire first and lose their next POST to a 403.
func issueCSRFCookie(value, path string, secure, remember bool) *http.Cookie {
	ttl := sessionTTL
	if remember {
		ttl = sessionTTLRemember
	}
	exp := time.Now().Add(ttl)
	return &http.Cookie{
		Name:     csrfCookieName,
		Value:    value,
		Path:     path,
		Expires:  exp,
		MaxAge:   int(ttl.Seconds()),
		HttpOnly: false, // readable by the (same-origin) JS that the form ships, but cross-origin reads are blocked by SOP regardless
		Secure:   secure,
		SameSite: http.SameSiteLaxMode, // match the session cookie; see the package comment
	}
}

// clearCSRFCookie returns a Cookie that expires the CSRF token on path (a
// cookie is only replaced by one on the same path).  Used from the logout
// path so a fresh login starts with a fresh token.
func clearCSRFCookie(path string, secure bool) *http.Cookie {
	return &http.Cookie{
		Name:     csrfCookieName,
		Value:    "",
		Path:     path,
		MaxAge:   -1,
		HttpOnly: false,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	}
}

// csrfIssuedCtxKey carries the CSRF token AuthMiddleware derived for this
// request: the one for the session cookie the client holds after this
// response (the refreshed one, when the session slid).  The page renders its
// forms with it -- instead of self-redirecting to re-read the cookie, which
// has no terminating condition when the client does not return it (the 303
// loop that locked an operator out of /unmask/admin/).
type csrfIssuedCtxKey struct{}

// withIssuedCSRFToken returns r with tok attached; CSRFTokenFromRequest
// reads it first.
func withIssuedCSRFToken(r *http.Request, tok string) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), csrfIssuedCtxKey{}, tok))
}

// CSRFTokenFromRequest returns the token this request's forms must carry:
// the one AuthMiddleware derived for it (withIssuedCSRFToken) or -- on a
// page outside AuthMiddleware, the setup wizard's reconfigure -- the cookie's
// value, which is the token of the session it was issued with.  "" when
// neither exists.  Templates render this through the shared layout data so
// every form auto-embeds it.
func CSRFTokenFromRequest(r *http.Request) string {
	if r == nil {
		return ""
	}
	if tok, ok := r.Context().Value(csrfIssuedCtxKey{}).(string); ok && tok != "" {
		return tok
	}
	if c, err := r.Cookie(csrfCookieName); err == nil && c != nil && c.Value != "" {
		return c.Value
	}
	return ""
}

// csrfHeaderName is the request header fetch / XHR echo the token in.
// The global init_csrf shim (= partial_header_tools.html) adds it to every
// same-origin mutating fetch, so /admin/api/* JSON endpoints are covered
// without each call site threading a form field.
const csrfHeaderName = "X-CSRF-Token"

// verifyCSRF returns true when the request carries, via an accepted
// channel, the token derived from the session cookie it was sent with
// (csrfTokenOf under secret = bv_secret).  The channels: the X-CSRF-Token
// header (fetch / XHR) or the _csrf form field (native forms; read from the
// multipart body for an upload form, whose body ParseForm does not read).
// The URL query is not one: the shim used to mirror the field into a
// multipart form's action query, and a token in the request line is a token
// in every access log and Referer on the way.  The CSRF cookie is not read:
// it only carries the token to the shim.  No session / missing echo /
// mismatch all collapse to one rejection so the response leaks nothing.
func verifyCSRF(secret string, r *http.Request) bool {
	expected := csrfTokenOf(secret, r)
	if expected == "" {
		return false
	}
	// Header first: it needs no body parse, so it works for JSON-body
	// fetches where ParseForm read nothing.
	echo := strings.TrimSpace(r.Header.Get(csrfHeaderName))
	if echo == "" {
		echo = strings.TrimSpace(r.PostFormValue(csrfFieldName))
	}
	if echo == "" && strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "multipart/form-data") {
		// Multipart native forms: the field rides in the multipart body,
		// which ParseForm skips, so parse that here.  Same memory bound the
		// upload handlers use; their later ParseMultipartForm is a no-op.
		if err := r.ParseMultipartForm(4 << 20); err == nil {
			echo = strings.TrimSpace(r.PostForm.Get(csrfFieldName))
		}
	}
	if echo == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(expected), []byte(echo)) == 1
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
		if !verifyCSRF(h.cfg().Secret.BVSecret, r) {
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
