package handlers

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"strings"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// cspNonce: 128 random bits, base64, for one serve of the challenge page.
func cspNonce() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		binary.BigEndian.PutUint64(b[:8], uint64(time.Now().UnixNano()))
	}
	return base64.StdEncoding.EncodeToString(b[:])
}

// providerCSP: what an external CAPTCHA provider's widget needs allowed, per
// provider -- its script, the frame it renders in, and what it talks to.
// From each provider's own CSP guidance.
type providerCSP struct{ script, frame, connect []string }

var providerCSPs = map[string]providerCSP{
	"turnstile": {
		script:  []string{"https://challenges.cloudflare.com"},
		frame:   []string{"https://challenges.cloudflare.com"},
		connect: []string{"https://challenges.cloudflare.com"},
	},
	"hcaptcha": {
		script:  []string{"https://js.hcaptcha.com", "https://*.hcaptcha.com"},
		frame:   []string{"https://*.hcaptcha.com"},
		connect: []string{"https://*.hcaptcha.com"},
	},
	"recaptcha": {
		script:  []string{"https://www.google.com/recaptcha/", "https://www.gstatic.com/recaptcha/"},
		frame:   []string{"https://www.google.com/recaptcha/", "https://recaptcha.google.com/recaptcha/"},
		connect: []string{"https://www.google.com/recaptcha/"},
	},
}

// challengeCSP is the challenge page's Content-Security-Policy for one serve.
//
// Scripts: the page's own, by this serve's nonce (the two inline blocks and
// the inlined challenge.js), the daemon's own origin for the external
// fallback, and the chosen CAPTCHA provider's.  The proof-of-work runs in a
// blob: worker.  Styles are inline (the page's own <style> and attributes,
// and the provider widgets' injected ones); images and fonts may come from
// the site's origin or any https: origin, so an operator's copy of the page
// that pulls a web font or a hosted logo keeps working.  No <base>
// retargeting, no plugins, and a form may post only to the daemon.
//
// The policy is deliberately not the admin's: that one restricts framing
// (frame-ancestors), and the settings page frames this one for its previews.
func challengeCSP(nonce string, cc settings.Captcha) string {
	script := []string{"'self'", "'nonce-" + nonce + "'"}
	frame := []string{"'self'"}
	connect := []string{"'self'"}
	// Only a provider the page will actually show: the same test that
	// decides whether the widget is injected (captchaInjectJSON).
	if captchaInjectJSON(cc) != "null" {
		if p, ok := providerCSPs[cc.Provider]; ok {
			script = append(script, p.script...)
			frame = append(frame, p.frame...)
			connect = append(connect, p.connect...)
		}
	}
	return strings.Join([]string{
		"default-src 'self'",
		"script-src " + strings.Join(script, " "),
		"style-src 'self' 'unsafe-inline' https:",
		"img-src 'self' data: https:",
		"font-src 'self' data: https:",
		"connect-src " + strings.Join(connect, " "),
		"frame-src " + strings.Join(frame, " "),
		"worker-src blob:",
		"child-src blob: " + strings.Join(frame[1:], " "),
		"base-uri 'none'",
		"object-src 'none'",
		"form-action 'self'",
	}, "; ")
}
