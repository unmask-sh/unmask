package handlers

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestSeverityFromAction: action string -> severity mapping.  Verifies that
// the pass / skip / pow / captcha / chain / deny ordering matches the
// pickStrongest contract.
func TestSeverityFromAction(t *testing.T) {
	cases := []struct {
		in   string
		want axisSeverity
	}{
		{"", sevPass},
		{"pass", sevPass},
		{settings.GeoActionSkip, sevPass},
		{settings.RateChallengePoWOnly, sevPoWOnly},
		{settings.RateChallengeCaptchaOnly, sevCaptchaOnly},
		{settings.RateChallengePoWThenCaptcha, sevPoWThenCaptcha},
		{settings.RateChallengeDeny, sevDeny},
		{"garbage", sevPass}, // unknown falls back to floor
	}
	for _, c := range cases {
		got := severityFromAction(c.in)
		if got != c.want {
			t.Errorf("severityFromAction(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

// TestChModeFromSeverity: severity -> canonical chMode string.  Pass/deny
// intentionally return "" because no chain is needed.
func TestChModeFromSeverity(t *testing.T) {
	cases := []struct {
		sev  axisSeverity
		want string
	}{
		{sevPass, ""},
		{sevPoWOnly, settings.RateChallengePoWOnly},
		{sevCaptchaOnly, settings.RateChallengeCaptchaOnly},
		{sevPoWThenCaptcha, settings.RateChallengePoWThenCaptcha},
		{sevDeny, ""},
	}
	for _, c := range cases {
		if got := chModeFromSeverity(c.sev); got != c.want {
			t.Errorf("chModeFromSeverity(%d) = %q, want %q", c.sev, got, c.want)
		}
	}
}

// TestPickStrongest: max-severity over a slice of decisions.  Covers empty,
// pass-only, single, mixed, and suppressed-list construction.
func TestPickStrongest(t *testing.T) {
	d := func(s axisSeverity, r string) axisDecision { return axisDecision{sev: s, reason: r} }

	cases := []struct {
		name          string
		in            []axisDecision
		wantWinnerSev axisSeverity
		wantWinnerR   string
		wantSupp      []string
	}{
		{"empty", nil, sevPass, "", nil},
		{"all-pass", []axisDecision{d(sevPass, "ua:human"), d(sevPass, "ua:search_ai")}, sevPass, "", nil},
		{"single-captcha", []axisDecision{d(sevCaptchaOnly, "ja4:bot")}, sevCaptchaOnly, "ja4:bot", []string{}},
		{
			"geo-pow + ja4-captcha -> captcha wins",
			[]axisDecision{d(sevPoWOnly, "geo:JP:pow_only"), d(sevCaptchaOnly, "ja4:bot")},
			sevCaptchaOnly, "ja4:bot",
			[]string{"geo:JP:pow_only"},
		},
		{
			"deny beats everything",
			[]axisDecision{d(sevPoWOnly, "geo:JP:pow_only"), d(sevDeny, "ban:custom"), d(sevCaptchaOnly, "ja4:bot")},
			sevDeny, "ban:custom",
			[]string{"geo:JP:pow_only", "ja4:bot"},
		},
		{
			"pass alongside challenge - pass omitted from suppressed",
			[]axisDecision{d(sevPass, "ua:human"), d(sevPoWOnly, "ua:browser:pow_only")},
			sevPoWOnly, "ua:browser:pow_only",
			[]string{}, // pass-severity entries are filtered out
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			winner, supp := pickStrongest(c.in)
			if winner.sev != c.wantWinnerSev || winner.reason != c.wantWinnerR {
				t.Errorf("winner=(sev=%d, reason=%q), want (sev=%d, reason=%q)",
					winner.sev, winner.reason, c.wantWinnerSev, c.wantWinnerR)
			}
			if !equalStrSlice(supp, c.wantSupp) {
				t.Errorf("suppressed=%v, want %v", supp, c.wantSupp)
			}
		})
	}
}

// TestGeoDecideForCountry: per-country policy resolution.  Covers default
// fallback, rule override, the "skip" no-op, and the "deny" hard 403.
func TestGeoDecideForCountry(t *testing.T) {
	rules := []settings.GeoRule{
		{Country: "JP", Action: settings.RateChallengePoWOnly, Enabled: true},
		{Country: "CN", Action: settings.RateChallengeDeny, Enabled: true},
		{Country: "DE", Action: settings.GeoActionSkip, Enabled: true},
		{Country: "RU", Action: settings.RateChallengeCaptchaOnly, Enabled: false}, // disabled -> no opinion
		{Country: "FR", Action: ""}, // inherit default
	}
	geoSkipDefault := settings.GeoConfig{DefaultAction: settings.GeoActionSkip, Rules: rules}
	geoDenyDefault := settings.GeoConfig{DefaultAction: settings.RateChallengeDeny, Rules: rules}

	cases := []struct {
		name    string
		country string
		geo     settings.GeoConfig
		wantOK  bool
		wantSev axisSeverity
		wantR   string
	}{
		{"empty country -> silent", "", geoSkipDefault, false, sevPass, ""},
		{"JP rule pow_only", "JP", geoSkipDefault, true, sevPoWOnly, "geo:JP:pow_only"},
		{"CN rule deny", "CN", geoSkipDefault, true, sevDeny, "geo:CN:deny"},
		{"DE rule explicit skip -> silent", "DE", geoSkipDefault, false, sevPass, ""},
		{"RU disabled rule -> falls to default skip -> silent", "RU", geoSkipDefault, false, sevPass, ""},
		{"FR inherit default skip -> silent", "FR", geoSkipDefault, false, sevPass, ""},
		{"FR inherit default deny -> deny", "FR", geoDenyDefault, true, sevDeny, "geo:FR:deny"},
		{"unlisted GB with default skip -> silent", "GB", geoSkipDefault, false, sevPass, ""},
		{"unlisted GB with default deny -> deny", "GB", geoDenyDefault, true, sevDeny, "geo:GB:deny"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d, ok := geoDecideForCountry(c.country, c.geo)
			if ok != c.wantOK {
				t.Fatalf("ok=%v, want %v (decision=%+v)", ok, c.wantOK, d)
			}
			if !ok {
				return
			}
			if d.sev != c.wantSev || d.reason != c.wantR {
				t.Errorf("decision=(sev=%d, reason=%q), want (sev=%d, reason=%q)",
					d.sev, d.reason, c.wantSev, c.wantR)
			}
		})
	}
}

// TestBanDecideFromSource: source-string -> action mapping.  Honeypot honors
// Honeypot.DefaultAction; other sources are hard 403.
func TestBanDecideFromSource(t *testing.T) {
	cfgHpDeny := settings.Settings{Nginx: settings.Nginx{Honeypot: settings.HoneypotConfig{DefaultAction: settings.RateChallengeDeny}}}
	cfgHpPoWCap := settings.Settings{Nginx: settings.Nginx{Honeypot: settings.HoneypotConfig{DefaultAction: settings.RateChallengePoWThenCaptcha}}}
	cfgHpEmpty := settings.Settings{}

	cases := []struct {
		name    string
		src     string
		cfg     settings.Settings
		wantSev axisSeverity
		wantR   string
	}{
		{"honeypot + DefaultAction=deny", "honeypot", cfgHpDeny, sevDeny, "ban:honeypot:deny"},
		{"honeypot + DefaultAction=pow_then_captcha", "honeypot", cfgHpPoWCap, sevPoWThenCaptcha, "ban:honeypot:pow_then_captcha"},
		{"honeypot + empty -> default pow_then_captcha", "honeypot", cfgHpEmpty, sevPoWThenCaptcha, "ban:honeypot:pow_then_captcha"},
		{"manual ban + empty default -> captcha_only", "manual", cfgHpEmpty, sevCaptchaOnly, "ban:manual:captcha_only"},
		{"community_bans ban + empty default -> captcha_only", "community_bans", cfgHpEmpty, sevCaptchaOnly, "ban:community_bans:captcha_only"},
		{"unknown source -> hard deny", "future_src", cfgHpEmpty, sevDeny, "ban:future_src:deny"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d, ok := banDecideFromSource(c.src, c.cfg)
			if !ok {
				t.Fatalf("ok=false, want true")
			}
			if d.sev != c.wantSev || d.reason != c.wantR {
				t.Errorf("decision=(sev=%d, reason=%q), want (sev=%d, reason=%q)",
					d.sev, d.reason, c.wantSev, c.wantR)
			}
		})
	}
}

// TestJA4Decide: bot verdict -> captcha; non-bot -> silent.
func TestJA4Decide(t *testing.T) {
	cases := []struct {
		name    string
		action  string
		verdict string
		wantOK  bool
		wantSev axisSeverity
		wantR   string
		wantChM string
	}{
		{"bot -> captcha", "bot", "t13d3515h2_bfa", true, sevCaptchaOnly, "ja4:t13d3515h2_bfa", settings.RateChallengeCaptchaOnly},
		{"ok -> silent", "ok", "t13d1516h2_abc", false, 0, "", ""},
		{"empty action -> silent", "", "", false, 0, "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d, ok := ja4Decide(c.action, c.verdict)
			if ok != c.wantOK {
				t.Fatalf("ok=%v, want %v", ok, c.wantOK)
			}
			if !ok {
				return
			}
			if d.sev != c.wantSev || d.reason != c.wantR || d.chMode != c.wantChM {
				t.Errorf("decision=%+v, want sev=%d reason=%q chMode=%q",
					d, c.wantSev, c.wantR, c.wantChM)
			}
		})
	}
}

// TestProtectedDecide: URI matches the protected regex slice -> challenge
// with the rate-limit default chMode.
func TestProtectedDecide(t *testing.T) {
	matchers := pathMatchers{
		protected: []*regexp.Regexp{regexp.MustCompile(`^/admin/`)},
	}
	cfgCaptcha := settings.Settings{RateLimit: settings.RateLimitConfig{
		Default: settings.RateLimitValues{ChallengeMode: settings.RateChallengeCaptchaOnly},
	}}
	cfgDeny := settings.Settings{RateLimit: settings.RateLimitConfig{
		Default: settings.RateLimitValues{ChallengeMode: settings.RateChallengeDeny},
	}}

	t.Run("non-matching uri -> silent", func(t *testing.T) {
		_, ok := protectedDecide("/public/", matchers, cfgCaptcha, "")
		if ok {
			t.Error("expected silent for non-matching uri")
		}
	})
	t.Run("/admin/ + chMode=captcha", func(t *testing.T) {
		d, ok := protectedDecide("/admin/dashboard", matchers, cfgCaptcha, "")
		if !ok || d.sev != sevCaptchaOnly || d.chMode != settings.RateChallengeCaptchaOnly {
			t.Errorf("got %+v ok=%v, want captcha", d, ok)
		}
	})
	t.Run("/admin/ + chMode=deny -> deny severity", func(t *testing.T) {
		d, ok := protectedDecide("/admin/dashboard", matchers, cfgDeny, "")
		if !ok || d.sev != sevDeny {
			t.Errorf("got %+v ok=%v, want deny", d, ok)
		}
	})
}

// equalStrSlice: order-sensitive equality with nil/empty conflation.
func equalStrSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestPeerIsTrustedProxy: r.RemoteAddr host vs the trusted-proxy CIDR list.
// This is the trust anchor for forward-auth JA4 — it must match the proxy
// connection, not the visitor.
func TestPeerIsTrustedProxy(t *testing.T) {
	loopback := []string{"127.0.0.0/8", "::1/128"}
	cases := []struct {
		name       string
		remoteAddr string
		cidrs      []string
		want       bool
	}{
		{"loopback v4 in default", "127.0.0.1:54321", loopback, true},
		{"loopback v6 in default", "[::1]:54321", loopback, true},
		{"public v4 rejected", "203.0.113.7:443", loopback, false},
		{"private v4 not in loopback set", "10.0.0.4:8080", loopback, false},
		{"private v4 in explicit /8", "10.0.0.4:8080", []string{"10.0.0.0/8"}, true},
		{"docker-range peer in /12", "172.18.0.5:9477", []string{"172.16.0.0/12"}, true},
		{"no port still parses", "127.0.0.1", loopback, true},
		{"garbage addr", "not-an-ip", loopback, false},
		{"empty addr", "", loopback, false},
		{"empty cidr list rejects all", "127.0.0.1:1", nil, false},
		{"malformed cidr skipped, valid one still matches", "127.0.0.1:1", []string{"bogus", "127.0.0.0/8"}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := peerIsTrustedProxy(c.remoteAddr, c.cidrs); got != c.want {
				t.Errorf("peerIsTrustedProxy(%q, %v) = %v, want %v", c.remoteAddr, c.cidrs, got, c.want)
			}
		})
	}
}

// TestResolveForwardedJA4: the forward-auth JA4 trust gate. The header is
// honored when the connection peer is inside the trusted-LB list (loopback
// is part of that list by default) and the value is well-formed (safeJA4).
// Anything else yields "".
func TestResolveForwardedJA4(t *testing.T) {
	// alnum + underscore, within safeJA4RE's 8-40 length bound.
	const goodJA4 = "t13d1516h2_e2etestfp01"
	const fallbackJA4 = "t13other_fallback99"

	mk := func(extra []settings.TrustedLBExtra, remoteAddr, clientJA4, originalJA4 string) (*http.Request, settings.Settings) {
		r := httptest.NewRequest(http.MethodGet, "/unmask/api/check", nil)
		r.RemoteAddr = remoteAddr
		if clientJA4 != "" {
			r.Header.Set("X-Client-JA4", clientJA4)
		}
		if originalJA4 != "" {
			r.Header.Set("X-Original-JA4", originalJA4)
		}
		// Extra peer CIDRs ride along via the native-mode LB-trust extra
		// list -- the same knob operators configure for LB header trust.
		// TrustForwardedJA4 is on so these cases exercise the peer logic; the
		// default-deny (flag off) is covered separately below.
		cfg := settings.Settings{Nginx: settings.Nginx{TrustedLBExtra: extra, TrustForwardedJA4: true}}
		return r, cfg
	}
	extraCIDR := func(cidr string) []settings.TrustedLBExtra {
		if cidr == "" {
			return nil
		}
		return []settings.TrustedLBExtra{{ID: "test", CIDRs: []string{cidr}, Header: "$http_x_client_ja4"}}
	}
	cases := []struct {
		name        string
		extra       []settings.TrustedLBExtra
		remoteAddr  string
		clientJA4   string
		originalJA4 string
		want        string
	}{
		{"loopback peer -> honored", nil, "127.0.0.1:5", goodJA4, "", goodJA4},
		{"v6 loopback peer -> honored", nil, "[::1]:5", goodJA4, "", goodJA4},
		{"public peer with no LB trust -> dropped", nil, "203.0.113.9:5", goodJA4, "", ""},
		{"LB-trust CIDR -> honored", extraCIDR("172.16.0.0/12"), "172.20.0.3:5", goodJA4, "", goodJA4},
		{"LB-trust CIDR, peer outside -> loopback still honored", extraCIDR("172.16.0.0/12"), "127.0.0.1:5", goodJA4, "", goodJA4},
		{"no header -> empty", nil, "127.0.0.1:5", "", "", ""},
		{"malformed JA4 -> empty", nil, "127.0.0.1:5", "'; DROP TABLE", "", ""},
		{"X-Original-JA4 fallback", nil, "127.0.0.1:5", "", goodJA4, goodJA4},
		{"X-Client-JA4 wins over fallback", nil, "127.0.0.1:5", goodJA4, fallbackJA4, goodJA4},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, cfg := mk(c.extra, c.remoteAddr, c.clientJA4, c.originalJA4)
			if got := resolveForwardedJA4(r, cfg); got != c.want {
				t.Errorf("resolveForwardedJA4 = %q, want %q", got, c.want)
			}
		})
	}

	// Default-deny (the round-4 spoof fix): without TrustForwardedJA4, a
	// client-supplied X-Client-JA4 is dropped even from a loopback peer, so a
	// client can't inject a benign JA4 to evade ja4:bot.
	t.Run("flag off -> dropped even from loopback", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/unmask/api/check", nil)
		r.RemoteAddr = "127.0.0.1:5"
		r.Header.Set("X-Client-JA4", goodJA4)
		cfg := settings.Settings{} // TrustForwardedJA4 defaults false
		if got := resolveForwardedJA4(r, cfg); got != "" {
			t.Errorf("expected drop without TrustForwardedJA4, got %q", got)
		}
	})
}

// TestIsSearchBotUA locks the search/AI-crawler detection that the forward-auth
// veto-pass relies on (= the rescue that must beat geo/ja4/protected/honeypot).
func TestIsSearchBotUA(t *testing.T) {
	var n settings.Nginx
	cases := []struct {
		ua   string
		want bool
	}{
		{"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", true},
		{"Mozilla/5.0 (compatible; ClaudeBot/1.0; +claudebot@anthropic.com)", true},
		{"Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)", true},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36", false},
		{"curl/8.0", false},
		{"", false},
	}
	for _, c := range cases {
		if got := isSearchBotUA(c.ua, "", n); got != c.want {
			t.Errorf("isSearchBotUA(%q) = %v, want %v", c.ua, got, c.want)
		}
	}
}
