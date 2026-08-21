package handlers

import (
	"crypto/tls"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestHeaderDecide pins the header-integrity axis (v0.2 #2): it fires ONLY when
// a Chromium UA over https/h2h3 carries no Sec-CH-UA, is silent on every
// precondition failure (the FP fence), and is clamped to a challenge severity
// -- never deny.
func TestHeaderDecide(t *testing.T) {
	const chrome = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	const firefox = "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"

	on := settings.GlobalConfig{HeaderIntegrity: true}
	off := settings.GlobalConfig{HeaderIntegrity: false}

	cases := []struct {
		name       string
		ua         string
		secChUA    string
		scheme     string
		modern     bool
		g          settings.GlobalConfig
		wantOK     bool
		wantSev    axisSeverity
		wantReason string
	}{
		{"chromium https h2 no CH -> fire the chain", chrome, "", "https", true, on, true, sevPoWThenCaptcha, "header:no_sch_ua"},
		{"axis off -> silent", chrome, "", "https", true, off, false, sevPass, ""},
		{"CH present -> silent", chrome, `"Chromium";v="120"`, "https", true, on, false, sevPass, ""},
		{"http (not https) -> silent", chrome, "", "http", true, on, false, sevPass, ""},
		{"h1 (not modern) -> silent", chrome, "", "https", false, on, false, sevPass, ""},
		{"firefox -> silent (not chromium)", firefox, "", "https", true, on, false, sevPass, ""},
		{"empty ua -> silent", "", "", "https", true, on, false, sevPass, ""},
		// Sec-CH-UA shipped in Chromium 89: below it the header is legitimately
		// absent, so the axis must stay silent.  It used to fire, and because the
		// missing header is permanent, solving the challenge did not help: an
		// aging WebView could clear the CAPTCHA and be re-challenged on its very
		// next request, forever.
		{"chromium 55 (pre-CH) -> silent", strings.Replace(chrome, "Chrome/120.", "Chrome/55.", 1), "", "https", true, on, false, sevPass, ""},
		{"chromium 88 (pre-CH) -> silent", strings.Replace(chrome, "Chrome/120.", "Chrome/88.", 1), "", "https", true, on, false, sevPass, ""},
		{"chromium 89 (first CH major) -> fire", strings.Replace(chrome, "Chrome/120.", "Chrome/89.", 1), "", "https", true, on, true, sevPoWThenCaptcha, "header:no_sch_ua"},
		{"chromium 125 -> fire", strings.Replace(chrome, "Chrome/120.", "Chrome/125.", 1), "", "https", true, on, true, sevPoWThenCaptcha, "header:no_sch_ua"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d, ok := headerDecide(c.ua, c.secChUA, c.scheme, c.modern, c.g)
			if ok != c.wantOK {
				t.Fatalf("ok=%v, want %v (d=%+v)", ok, c.wantOK, d)
			}
			if !ok {
				return
			}
			if d.sev != c.wantSev || d.reason != c.wantReason {
				t.Errorf("d=(sev=%d reason=%q), want (sev=%d reason=%q)", d.sev, d.reason, c.wantSev, c.wantReason)
			}
		})
	}

	// The operator's action tunes the severity, but deny can never be reached:
	// HeaderIntegrityResolvedAction clamps a stored "deny" to the unset default.
	denyish := settings.GlobalConfig{HeaderIntegrity: true, HeaderIntegrityAction: settings.RateChallengeDeny}
	if d, ok := headerDecide(chrome, "", "https", true, denyish); !ok || d.sev == sevDeny {
		t.Errorf("a stored deny action must clamp to a challenge, got sev=%d ok=%v", d.sev, ok)
	}
	powish := settings.GlobalConfig{HeaderIntegrity: true, HeaderIntegrityAction: settings.RateChallengePoWOnly}
	if d, _ := headerDecide(chrome, "", "https", true, powish); d.sev != sevPoWOnly {
		t.Errorf("pow_only action -> sevPoWOnly, got %d", d.sev)
	}
	// pow_then_captcha is a valid (non-deny) escalation and must round-trip
	// through severity to the pow_then_captcha chMode, not collapse to captcha.
	chainish := settings.GlobalConfig{HeaderIntegrity: true, HeaderIntegrityAction: settings.RateChallengePoWThenCaptcha}
	if d, _ := headerDecide(chrome, "", "https", true, chainish); d.sev != sevPoWThenCaptcha || d.chMode != settings.RateChallengePoWThenCaptcha {
		t.Errorf("pow_then_captcha action -> sevPoWThenCaptcha/chMode pow_then_captcha, got sev=%d chMode=%q", d.sev, d.chMode)
	}
}

// TestHeaderDecideForServe covers the serve-time input extraction that feeds the
// force_reason="header" attribution: forward-auth reads the X-Original-* mirror
// the snippet forwards (the live headers are the proxy's), native reads the live
// request headers directly.
func TestHeaderDecideForServe(t *testing.T) {
	const chrome = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	on := settings.GlobalConfig{HeaderIntegrity: true}

	// forward-auth: inputs ride the X-Original-* mirror, no live TLS/UA.
	fa := httptest.NewRequest("GET", "/unmask/challenge/", nil)
	fa.Header.Set("X-Original-UA", chrome)
	fa.Header.Set("X-Original-Scheme", "https")
	fa.Header.Set("X-Original-HTTP2", "1")
	if _, ok := headerDecideForServe(fa, on); !ok {
		t.Error("forward-auth mirror (Chromium, https, h2, no Sec-CH-UA) must fire the header axis")
	}
	// a Sec-CH-UA present over the mirror -> consistent -> silent.
	fa.Header.Set("X-Original-Sec-CH-UA", `"Chromium";v="120"`)
	if _, ok := headerDecideForServe(fa, on); ok {
		t.Error("a present Sec-CH-UA (via mirror) must be silent")
	}

	// native: no mirror, the daemon reads the live request headers + TLS.
	nat := httptest.NewRequest("GET", "/unmask/challenge/", nil)
	nat.Header.Set("User-Agent", chrome)
	nat.ProtoMajor = 2
	nat.TLS = &tls.ConnectionState{}
	if _, ok := headerDecideForServe(nat, on); !ok {
		t.Error("native live headers (Chromium, h2, https, no Sec-CH-UA) must fire the header axis")
	}
	// plain HTTP (no TLS) native -> Sec-CH-UA legitimately absent -> silent.
	plain := httptest.NewRequest("GET", "/unmask/challenge/", nil)
	plain.Header.Set("User-Agent", chrome)
	plain.ProtoMajor = 2
	if _, ok := headerDecideForServe(plain, on); ok {
		t.Error("plain HTTP (no TLS) must be silent -- Sec-CH-UA is legitimately absent")
	}

	// LB-fronted: behind a TLS-terminating LB the daemon sees http/1.1
	// (ProtoMajor=1, no TLS), but X-Forwarded-Proto=https marks a modern secure
	// visitor -- the axis must still fire (this is the case that was silently
	// dead behind the GCP LB, where $server_protocol is always h1).
	lb := httptest.NewRequest("GET", "/unmask/challenge/", nil)
	lb.Header.Set("User-Agent", chrome)
	lb.Header.Set("X-Forwarded-Proto", "https")
	lb.ProtoMajor = 1
	if _, ok := headerDecideForServe(lb, on); !ok {
		t.Error("LB-fronted (XFP=https, h1 backend hop, no Sec-CH-UA) must fire the header axis")
	}
	// XFP=http (insecure visitor) -> Sec-CH-UA legitimately absent -> silent.
	lb.Header.Set("X-Forwarded-Proto", "http")
	if _, ok := headerDecideForServe(lb, on); ok {
		t.Error("LB-fronted XFP=http must be silent")
	}
}

// TestHeaderAxisFiresForServe: native trusts the nginx-computed X-Header-Mismatch
// signal (unspoofable -- proxy_set_header overwrites any client value), the axis
// is off entirely when disabled, and forward-auth falls back to re-derivation.
func TestHeaderAxisFiresForServe(t *testing.T) {
	const chrome = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	on := settings.GlobalConfig{HeaderIntegrity: true}
	off := settings.GlobalConfig{HeaderIntegrity: false}

	// native: nginx already decided -> trust the signal (no live headers needed).
	nat := httptest.NewRequest("GET", "/unmask/challenge/", nil)
	nat.Header.Set("X-Header-Mismatch", "1")
	if !headerAxisFiresForServe(nat, on) {
		t.Error("X-Header-Mismatch=1 must fire the axis (native trusts the nginx signal)")
	}
	// axis disabled -> never fires, even with the signal present.
	if headerAxisFiresForServe(nat, off) {
		t.Error("axis disabled must not fire regardless of the signal")
	}
	// no signal, nothing to re-derive -> false.
	bare := httptest.NewRequest("GET", "/unmask/challenge/", nil)
	if headerAxisFiresForServe(bare, on) {
		t.Error("no signal and no derivable mismatch must not fire")
	}
	// no signal but a re-derivable forward-auth mirror -> fires via fallback.
	fa := httptest.NewRequest("GET", "/unmask/challenge/", nil)
	fa.Header.Set("X-Original-UA", chrome)
	fa.Header.Set("X-Original-Scheme", "https")
	fa.Header.Set("X-Original-HTTP2", "1")
	if !headerAxisFiresForServe(fa, on) {
		t.Error("forward-auth mirror must fire via the re-derivation fallback")
	}
}
