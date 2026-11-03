package handlers

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"html/template"
	"net/http"
)

// The admin's inline JavaScript under a nonce.
//
// adminCSP closes the holes that need no nonce (framing, <base>, plugins,
// form targets) and leaves script execution alone, because the admin pages
// carry their JavaScript inline: a script-src that named only 'self' would
// stop every page working.  The way to a script-src is a nonce: the
// middleware draws one per response, the response header names it, and every
// <script> the templates emit carries it as an attribute -- a script injected
// through an escaping mistake does not know the nonce and does not run.
//
// This is the plumbing for that, with the policy published in REPORT-ONLY
// form (Content-Security-Policy-Report-Only).  A report-only policy blocks
// nothing; the browser reports each script it would have refused on the
// console, which is the inventory of what still has to move under the nonce
// before the directive can join the enforced header.  The partials shared by
// every page carry the nonce already (nonceAttr); the pages' own <script>
// blocks and their inline on* handlers are the remaining work, and the
// enforced policy waits for them.

// cspNonceKey is the request-context key of the response's script nonce.
type cspNonceKey struct{}

// newCSPNonce draws the nonce for one response: 128 bits, base64, which is
// the character set the CSP grammar takes without quoting.
func newCSPNonce() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// No randomness, no nonce: the header then names no nonce and the
		// report-only policy reports every inline script, which is the
		// truthful reading of a response whose scripts cannot be told apart.
		return ""
	}
	return base64.StdEncoding.EncodeToString(b[:])
}

// withCSPNonce draws a nonce for the response to r and returns the request
// that carries it (context), with the nonce itself for the header.
func withCSPNonce(r *http.Request) (*http.Request, string) {
	nonce := newCSPNonce()
	return r.WithContext(context.WithValue(r.Context(), cspNonceKey{}, nonce)), nonce
}

// CSPNonceFromRequest is the nonce the middleware drew for this response, ""
// outside the middlewares (tests that call a handler directly, the setup
// wizard's pre-gate routes): the templates then emit no nonce attribute.
func CSPNonceFromRequest(r *http.Request) string {
	if r == nil {
		return ""
	}
	n, _ := r.Context().Value(cspNonceKey{}).(string)
	return n
}

// cspScriptReportOnly is the report-only policy for the response's nonce:
// scripts from this origin and inline scripts carrying the nonce.  Only
// script-src: the admin's inline styles are a separate pass, and a
// default-src here would bury the script reports under style ones.
func cspScriptReportOnly(nonce string) string {
	if nonce == "" {
		return "script-src 'self'"
	}
	return "script-src 'self' 'nonce-" + nonce + "'"
}

// nonceAttr is the template function that puts the response's nonce on a
// <script> tag: `<script{{ nonceAttr . }}>`.  It reads the Nonce entry of
// the page's data map (addMeToData puts it there), and renders nothing for
// data that is not that map -- a partial handed a sub-value, a nil dot --
// so a template never fails for want of a nonce; its script is then one the
// report-only policy reports, which is the intended signal.
func nonceAttr(v any) template.HTMLAttr {
	m, ok := v.(map[string]any)
	if !ok {
		return ""
	}
	n, _ := m["Nonce"].(string)
	if n == "" {
		return ""
	}
	// Base64 only (newCSPNonce): nothing to escape inside the quotes.
	return template.HTMLAttr(` nonce="` + n + `"`)
}
