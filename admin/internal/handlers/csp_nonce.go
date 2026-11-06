package handlers

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"html/template"
	"net/http"
)

// The admin's script policy.
//
// The admin pages carry their JavaScript inline, in the same HTML that shows
// values a visitor chose -- the User-Agent and the path of an access-log
// line -- so one escaping mistake would run a script in an operator's
// session.  The policy stands behind the escaping: the middleware draws a
// nonce per response, the Content-Security-Policy header names it
// (script-src 'self' 'nonce-...'), and every <script> the templates emit
// carries it as an attribute (nonceAttr).  A script injected into the page
// does not know the nonce and does not run.  Neither does an inline on*
// attribute or a javascript: URL, which cannot carry one: the templates wire
// their handlers with addEventListener, and a test keeps both that way
// (csp_templates_test.go).
//
// What the browser refuses it reports to {base}/admin/csp-report
// (csp_report.go), one log line each.

// cspNonceKey is the request-context key of the response's script nonce.
type cspNonceKey struct{}

// newCSPNonce draws the nonce for one response: 128 bits, base64, which is
// the character set the CSP grammar takes without quoting.
func newCSPNonce() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// No randomness, no nonce: the header then names none and the page's
		// inline scripts do not run, which is the safe reading of a response
		// whose scripts cannot be told from an injected one.
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
// outside the middlewares (a test that calls a handler directly, the public
// test pages): the response then carries no policy, and the templates emit no
// nonce attribute.
func CSPNonceFromRequest(r *http.Request) string {
	if r == nil {
		return ""
	}
	n, _ := r.Context().Value(cspNonceKey{}).(string)
	return n
}

// cspScriptSrc is the script directive for the response's nonce: scripts
// from this origin (popover-pin.js) and inline scripts carrying the nonce.
// No 'unsafe-inline', no 'unsafe-eval'.  'report-sample' loosens nothing: it
// has the browser put the first characters of what it refused in the report,
// which is what tells an operator's own stray handler from an injected script.
func cspScriptSrc(nonce string) string {
	if nonce == "" {
		return "script-src 'self' 'report-sample'"
	}
	return "script-src 'self' 'nonce-" + nonce + "' 'report-sample'"
}

// nonceAttr is the template function that puts the response's nonce on a
// <script> tag: `<script{{ nonceAttr . }}>` at a template's top level,
// `<script{{ nonceAttr $ }}>` inside a range or with, where the dot is no
// longer the page.  It reads the Nonce entry of the page's data map
// (addMeToData puts it there), and renders nothing for anything else -- a
// sub-value, a nil dot -- so a template never fails for want of a nonce; its
// script then does not run under the policy, and the browser reports it.
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
