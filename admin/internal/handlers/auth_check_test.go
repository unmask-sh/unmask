package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/nginxconf"
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
		{Country: "FR", Action: ""},                // disabled (Enabled unset) -> no opinion, falls to default
		{Country: "IT", Action: "", Enabled: true}, // ENABLED registered rule, blank action -> inherits DefaultRuleAction
	}
	geoSkipDefault := settings.GeoConfig{DefaultAction: settings.GeoActionSkip, Rules: rules}
	geoDenyDefault := settings.GeoConfig{DefaultAction: settings.RateChallengeDeny, Rules: rules}
	geoRuleDeny := settings.GeoConfig{DefaultAction: settings.GeoActionSkip, DefaultRuleAction: settings.RateChallengeDeny, Rules: rules}

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
		{"FR disabled row -> falls to default skip -> silent", "FR", geoSkipDefault, false, sevPass, ""},
		{"FR disabled row -> falls to default deny -> deny", "FR", geoDenyDefault, true, sevDeny, "geo:FR:deny"},
		// A REGISTERED (enabled) rule with a blank action inherits
		// DefaultRuleAction (default pow_then_captcha) -- NOT the
		// unmatched-country DefaultAction, even when that is skip.
		{"IT registered blank action -> inherits rule default pow_then_captcha", "IT", geoSkipDefault, true, sevPoWThenCaptcha, "geo:IT:pow_then_captcha"},
		{"IT registered blank action + rule default deny -> deny", "IT", geoRuleDeny, true, sevDeny, "geo:IT:deny"},
		// The rate leg of the return value is pinned separately below.
		{"unlisted GB with default skip -> silent", "GB", geoSkipDefault, false, sevPass, ""},
		{"unlisted GB with default deny -> deny", "GB", geoDenyDefault, true, sevDeny, "geo:GB:deny"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d, _, ok := geoDecideForCountry(c.country, c.geo)
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

	// The rate leg: a matched rule surfaces its effective RatePerMin (inherit /
	// explicit), an unmatched country never carries one.
	rate30 := 30
	geoRated := settings.GeoConfig{
		DefaultAction:     settings.RateChallengeDeny,
		DefaultRatePerMin: 100,
		Rules: []settings.GeoRule{
			{Country: "CN", Action: settings.RateChallengeDeny, Enabled: true},                      // nil -> inherit 100
			{Country: "BR", Action: settings.RateChallengeDeny, RatePerMin: &rate30, Enabled: true}, // explicit 30
		},
	}
	if _, rate, ok := geoDecideForCountry("CN", geoRated); !ok || rate != 100 {
		t.Errorf("CN should inherit rate 100, got rate=%d ok=%v", rate, ok)
	}
	if _, rate, _ := geoDecideForCountry("BR", geoRated); rate != 30 {
		t.Errorf("BR explicit rate 30, got %d", rate)
	}
	if _, rate, ok := geoDecideForCountry("GB", geoRated); !ok || rate != 0 {
		t.Errorf("unmatched GB rides the default action with NO rate, got rate=%d ok=%v", rate, ok)
	}
}

// TestBanDecideFromSource: source-string -> action mapping.  Honeypot honors
// Honeypot.DefaultAction; other sources are hard 403.
func TestBanDecideFromSource(t *testing.T) {
	cfgHpDeny := settings.Settings{Nginx: settings.Nginx{Honeypot: settings.HoneypotConfig{DefaultAction: settings.RateChallengeDeny}}}
	cfgHpPoWCap := settings.Settings{Nginx: settings.Nginx{Honeypot: settings.HoneypotConfig{DefaultAction: settings.RateChallengePoWThenCaptcha}}}
	cfgHpEmpty := settings.Settings{}

	cases := []struct {
		name      string
		rowAction string // per-row action override ("" = use source default)
		src       string
		cfg       settings.Settings
		wantSev   axisSeverity
		wantR     string
	}{
		{"honeypot + DefaultAction=deny", "", "honeypot", cfgHpDeny, sevDeny, "ban:honeypot:deny"},
		{"honeypot + DefaultAction=pow_then_captcha", "", "honeypot", cfgHpPoWCap, sevPoWThenCaptcha, "ban:honeypot:pow_then_captcha"},
		{"honeypot + empty -> default pow_then_captcha", "", "honeypot", cfgHpEmpty, sevPoWThenCaptcha, "ban:honeypot:pow_then_captcha"},
		{"manual ban + empty default -> the chain", "", "manual", cfgHpEmpty, sevPoWThenCaptcha, "ban:manual:pow_then_captcha"},
		{"unknown source -> hard deny", "", "future_src", cfgHpEmpty, sevDeny, "ban:future_src:deny"},
		// The community feed is NOT a ban source: its entries are never copied
		// into unmask_ban (ban.Manager.Start deletes any legacy rows), and its
		// action lives on CommunityBans.Action, resolved by communityBansDecide.
		// A row claiming that source therefore reaches this resolver only by
		// hand, and is treated like any other unrecognised source.
		{"community_bans is not a ban source -> hard deny", "", "community_bans", cfgHpEmpty, sevDeny, "ban:community_bans:deny"},
		// per-row action override wins over the source default (B1): a manual ban
		// explicitly set to "deny" must hard-403 even though manual's default is
		// captcha_only -- matching native's EffectiveAction precedence.
		{"manual + per-row action=deny overrides the default", "deny", "manual", cfgHpEmpty, sevDeny, "ban:manual:deny"},
		{"manual + per-row action=pow_only overrides the default", "pow_only", "manual", cfgHpEmpty, sevPoWOnly, "ban:manual:pow_only"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d, ok := banDecideFromSource(c.rowAction, c.src, c.cfg)
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

// TestJA4Decide: the axis runs the operator's configured chain, resolved the
// same way the native serve path resolves it (tab default -> preset -> row),
// else inheriting the operating default chain (pow_then_captcha on a fresh
// install).  It used to hardcode captcha_only and never take settings at all,
// so every action picked in the JA4 tab applied on native and did nothing
// behind a load balancer -- and `deny`, which the UI offers, could not be
// reached on either wire.  The old test pinned that hardcoding, which is why
// it never caught it.
func TestJA4Decide(t *testing.T) {
	cfg := func(def string, extraVerdict, extraAct string) settings.Settings {
		var s settings.Settings
		s.Nginx.JA4Verdicts.DefaultAction = def
		if extraVerdict != "" {
			s.Nginx.JA4Verdicts.Extra = []settings.JA4VerdictExtraRule{{Verdict: extraVerdict}}
			s.Nginx.JA4Verdicts.ExtraAction = []string{extraAct}
		}
		return s
	}
	const v = "t13d3515h2_bfa"
	cases := []struct {
		name    string
		action  string
		verdict string
		n       settings.Settings
		wantOK  bool
		wantSev axisSeverity
		wantChM string
	}{
		{"unconfigured inherits the operating default (pow_then_captcha)", "bot", v, cfg("", "", ""),
			true, sevPoWThenCaptcha, settings.RateChallengePoWThenCaptcha},
		{"tab default applies", "bot", v, cfg(settings.RateChallengePoWOnly, "", ""),
			true, sevPoWOnly, settings.RateChallengePoWOnly},
		{"a row override beats the tab default", "bot", v,
			cfg(settings.RateChallengePoWOnly, v, settings.RateChallengePoWThenCaptcha),
			true, sevPoWThenCaptcha, settings.RateChallengePoWThenCaptcha},
		{"deny is terminal, with no chain to serve", "bot", v, cfg(settings.RateChallengeDeny, "", ""),
			true, sevDeny, ""},
		{"a row can deny on its own", "bot", v, cfg("", v, settings.RateChallengeDeny),
			true, sevDeny, ""},
		{"ok -> silent", "ok", "t13d1516h2_abc", cfg(settings.RateChallengeDeny, "", ""), false, 0, ""},
		{"empty action -> silent", "", "", cfg("", "", ""), false, 0, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d, ok := ja4Decide(c.action, c.verdict, c.n)
			if ok != c.wantOK {
				t.Fatalf("ok=%v, want %v", ok, c.wantOK)
			}
			if !ok {
				return
			}
			if d.sev != c.wantSev || d.chMode != c.wantChM {
				t.Errorf("decision=%+v, want sev=%d chMode=%q", d, c.wantSev, c.wantChM)
			}
			if !strings.Contains(d.reason, c.verdict) {
				t.Errorf("reason %q should name the verdict", d.reason)
			}
		})
	}
}

// TestProtectedDecide: URI matches the protected regex slice -> challenge with
// the matched path's OWN mode (mode == action), never the rate-limit default
// and never a deny (protected mode is pow / captcha / pow_then_captcha only).
func TestProtectedDecide(t *testing.T) {
	matchers := pathMatchers{
		protected: []*regexp.Regexp{
			regexp.MustCompile(`^/pow/`),
			regexp.MustCompile(`^/cap/`),
			regexp.MustCompile(`^/chain/`),
		},
	}
	var cfg settings.Settings
	cfg.Nginx.ProtectedPaths.Paths = []settings.ProtectedPath{
		{Path: `^/pow/`, Mode: "pow"},
		{Path: `^/cap/`, Mode: "captcha"},
		{Path: `^/chain/`, Mode: "pow_then_captcha"},
	}

	t.Run("non-matching uri -> silent", func(t *testing.T) {
		if _, ok := protectedDecide("/public/", matchers, cfg, ""); ok {
			t.Error("expected silent for non-matching uri")
		}
	})
	t.Run("pow mode -> pow_only", func(t *testing.T) {
		d, ok := protectedDecide("/pow/x", matchers, cfg, "")
		if !ok || d.sev != sevPoWOnly || d.chMode != settings.RateChallengePoWOnly {
			t.Errorf("got %+v ok=%v, want pow_only", d, ok)
		}
	})
	t.Run("captcha mode -> captcha_only", func(t *testing.T) {
		d, ok := protectedDecide("/cap/x", matchers, cfg, "")
		if !ok || d.sev != sevCaptchaOnly || d.chMode != settings.RateChallengeCaptchaOnly {
			t.Errorf("got %+v ok=%v, want captcha_only", d, ok)
		}
	})
	t.Run("pow_then_captcha mode -> the chain", func(t *testing.T) {
		d, ok := protectedDecide("/chain/x", matchers, cfg, "")
		if !ok || d.sev != sevPoWThenCaptcha || d.chMode != settings.RateChallengePoWThenCaptcha {
			t.Errorf("got %+v ok=%v, want pow_then_captcha", d, ok)
		}
	})
}

// TestHoneypotDecidePerPreset: the immediate honeypot decision honors a per-rule
// action override (= honeypotRule.action, sourced from PresetAction[group] /
// HoneypotURL.Action) ahead of Honeypot.DefaultAction; an empty override
// inherits the default; first matching rule wins.  banMgr is nil so only the
// decision half runs (the ban-persist half stamps the same raw override and is
// covered by the ban package's file test).  This is the knob that lets an
// operator make a high-risk trap demand captcha (which filters PoW-passing bots
// while a mis-routed human can still recover) without changing the global
// honeypot default.
func TestHoneypotDecidePerPreset(t *testing.T) {
	rule := func(pat, action string) honeypotRule {
		return honeypotRule{re: regexp.MustCompile(pat), action: action}
	}
	cfg := func(def string) settings.Settings {
		var s settings.Settings
		s.Nginx.Honeypot.DefaultAction = def
		return s
	}
	cases := []struct {
		name    string
		rules   []honeypotRule
		uri     string
		cfg     settings.Settings
		wantOK  bool
		wantSev axisSeverity
		wantChM string
		wantR   string
	}{
		{"no match -> silent", []honeypotRule{rule(`/wp-login`, "")}, "/index.html", cfg(settings.RateChallengeCaptchaOnly), false, 0, "", ""},
		{"override captcha_only beats default pow_only", []honeypotRule{rule(`/wp-login`, settings.RateChallengeCaptchaOnly)}, "/wp-login.php", cfg(settings.RateChallengePoWOnly), true, sevCaptchaOnly, settings.RateChallengeCaptchaOnly, "honeypot:captcha_only"},
		{"empty override inherits DefaultAction", []honeypotRule{rule(`/wp-login`, "")}, "/wp-login.php", cfg(settings.RateChallengeCaptchaOnly), true, sevCaptchaOnly, settings.RateChallengeCaptchaOnly, "honeypot:captcha_only"},
		{"empty override + empty default -> pow_then_captcha", []honeypotRule{rule(`/trap`, "")}, "/trap", cfg(""), true, sevPoWThenCaptcha, settings.RateChallengePoWThenCaptcha, "honeypot:pow_then_captcha"},
		{"override deny -> deny severity, no chMode", []honeypotRule{rule(`/trap`, settings.RateChallengeDeny)}, "/trap", cfg(settings.RateChallengePoWOnly), true, sevDeny, "", "honeypot:deny"},
		{"first matching rule wins", []honeypotRule{rule(`/a`, settings.RateChallengeCaptchaOnly), rule(`/a`, settings.RateChallengePoWOnly)}, "/a", cfg(""), true, sevCaptchaOnly, settings.RateChallengeCaptchaOnly, "honeypot:captcha_only"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := pathMatchers{honeypot: c.rules}
			d, ok := honeypotDecide(context.Background(), c.uri, m, c.cfg, nil, "203.0.113.9", "example.test")
			if ok != c.wantOK {
				t.Fatalf("ok=%v, want %v (decision=%+v)", ok, c.wantOK, d)
			}
			if !ok {
				return
			}
			if d.sev != c.wantSev || d.chMode != c.wantChM || d.reason != c.wantR {
				t.Errorf("decision=(sev=%d, chMode=%q, reason=%q), want (sev=%d, chMode=%q, reason=%q)",
					d.sev, d.chMode, d.reason, c.wantSev, c.wantChM, c.wantR)
			}
		})
	}
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
		// list -- the same shared knob that gates both native and forward-auth
		// JA4 trust (no separate toggle).  loopback is always in the trusted set.
		cfg := settings.Settings{Nginx: settings.Nginx{TrustedLBExtra: extra}}
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

	// Spoof defense (the round-4 fix) moved into nginx: forward-auth-lbtrust.conf
	// overwrites a direct visitor's X-Client-JA4 with "" before the subrequest,
	// so the daemon never sees a non-LB JA4.  At the daemon the gate is the peer
	// check -- a header arriving from a peer outside the trusted set is dropped
	// (the "public peer with no LB trust -> dropped" case above), while a value
	// relayed by the local nginx (loopback, in the trusted set by default) is
	// honored because nginx already gated it.
}

// TestResolveForwardedJA4ConnPeerGate covers the Apache forward-auth path: the
// JA4 is honored only when X-Unmask-Conn-Peer (the real connecting peer the lua
// reports) is a trusted LB.  The immediate peer is loopback (the apache->admin
// call), which clears the first gate; the conn-peer is the second gate.
func TestResolveForwardedJA4ConnPeerGate(t *testing.T) {
	const goodJA4 = "t13d1516h2_e2etestfp01"
	lbExtra := []settings.TrustedLBExtra{{ID: "lb", CIDRs: []string{"203.0.113.0/24"}, Header: "$http_x_client_ja4"}}
	run := func(extra []settings.TrustedLBExtra, connPeer string) string {
		r := httptest.NewRequest(http.MethodGet, "/unmask/api/check", nil)
		r.RemoteAddr = "127.0.0.1:5" // loopback = the apache->admin call, clears the peer gate
		r.Header.Set("X-Client-JA4", goodJA4)
		if connPeer != "" {
			r.Header.Set("X-Unmask-Conn-Peer", connPeer)
		}
		return resolveForwardedJA4(r, settings.Settings{Nginx: settings.Nginx{TrustedLBExtra: extra}})
	}
	if got := run(lbExtra, "203.0.113.7"); got != goodJA4 {
		t.Errorf("conn-peer in trusted LB: expected %q, got %q", goodJA4, got)
	}
	if got := run(lbExtra, "198.51.100.9"); got != "" {
		t.Errorf("conn-peer outside trusted LB: expected drop, got %q", got)
	}
	if got := run(nil, "203.0.113.7"); got != "" {
		t.Errorf("conn-peer with empty trusted-LB list: expected drop, got %q", got)
	}
	if got := run(nil, ""); got != goodJA4 {
		t.Errorf("no conn-peer (nginx path): expected %q, got %q", goodJA4, got)
	}
}

// TestUaDecideStaleBrowser: the forward-auth UA axis escalates a stale-Chrome
// UA to the operator's stale action (unset -> pow_then_captcha) even when the
// Global known-browser action would pass, and leaves a current browser alone.
func TestUaDecideStaleBrowser(t *testing.T) {
	scraper := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.7258.5 Safari/537.36"
	current := "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36"

	var cfg settings.Settings
	cfg.Global.KnownBrowserAction = "pass" // the incident posture: real browsers pass
	cfg.Global.StaleBrowserChallenge = true
	cfg.Global.CurrentChromeMajor = 150
	cfg.Global.StaleBrowserLag = 11

	// Stale UA: even though known browsers PASS, the scraper is escalated --
	// to the chain, which is what an unset stale action resolves to.
	d, ok := uaDecide(scraper, "", cfg, nil)
	if !ok || d.sev != sevPoWThenCaptcha {
		t.Fatalf("stale scraper: sev=%v ok=%v, want pow_then_captcha", d.sev, ok)
	}
	if d.chMode != settings.RateChallengePoWThenCaptcha {
		t.Errorf("stale scraper chMode=%q want pow_then_captcha", d.chMode)
	}
	if !strings.HasPrefix(d.reason, "ua:stale_browser:") {
		t.Errorf("stale scraper reason=%q want ua:stale_browser prefix", d.reason)
	}

	// Current browser: still passes (known-browser action honoured).
	if d, _ := uaDecide(current, "", cfg, nil); d.sev != sevPass {
		t.Errorf("current browser: sev=%v want pass", d.sev)
	}

	// The stale action REPLACES the base pick rather than being max()'d with
	// it -- an operator who picks captcha_only for stale UAs, to skip a PoW leg
	// the scraper solves for free anyway, gets captcha_only even though the
	// base is the nominally-higher-severity chain.  Driven with the action set
	// explicitly, since the default is now that same chain and would not tell
	// "replaced" from "inherited" apart.
	cfg.Global.StaleBrowserAction = settings.RateChallengeCaptchaOnly
	cfg.Global.KnownBrowserAction = "pow_then_captcha"
	if d, _ := uaDecide(scraper, "", cfg, nil); d.sev != sevCaptchaOnly {
		t.Errorf("stale over pow_then_captcha base: sev=%v want captcha_only (stale action must win)", d.sev)
	}
	cfg.Global.StaleBrowserAction = ""

	// ...but a deny base is never softened to a captcha.
	cfg.Global.KnownBrowserAction = "deny"
	if d, _ := uaDecide(scraper, "", cfg, nil); d.sev != sevDeny {
		t.Errorf("stale over deny base: sev=%v want deny (never soften a hard block)", d.sev)
	}

	// Feature off: the scraper passes like any known browser.
	cfg.Global.KnownBrowserAction = "pass"
	cfg.Global.StaleBrowserChallenge = false
	if d, _ := uaDecide(scraper, "", cfg, nil); d.sev != sevPass {
		t.Errorf("tier off: stale scraper sev=%v want pass", d.sev)
	}

	// Firefox rides the same tier over its own built-in baseline
	// (CurrentFirefoxMajor unset -> DefaultCurrentFirefoxMajor); the current
	// ESR major is exempt — a supported release that legitimately trails.
	cfg.Global.StaleBrowserChallenge = true
	ffScraper := "Mozilla/5.0 (X11; Linux x86_64; rv:115.0) Gecko/20100101 Firefox/115.0"
	ffESRUA := "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0"
	if d, _ := uaDecide(ffScraper, "", cfg, nil); d.sev != sevPoWThenCaptcha {
		t.Errorf("stale Firefox: sev=%v want pow_then_captcha", d.sev)
	}
	if d, _ := uaDecide(ffESRUA, "", cfg, nil); d.sev != sevPass {
		t.Errorf("Firefox ESR: sev=%v want pass (exempt)", d.sev)
	}
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
		// nil rangeVerifiedUA = no range preset enabled -> pure UA rescue.
		if got := isSearchBotUA(c.ua, "", n, nil); got != c.want {
			t.Errorf("isSearchBotUA(%q, nil) = %v, want %v", c.ua, got, c.want)
		}
	}
}

// TestIsSearchBotUARangeVerified: with every range preset enabled, crawler UAs
// backed by an official IP range are NOT rescued by their UA string (the
// bypass-IP veto carries the genuine article; a surviving match is a spoof),
// while range-less crawlers (YandexBot) keep the UA rescue.  An operator
// Extra row rescues a range-verified UA regardless (explicit wins).
func TestIsSearchBotUARangeVerified(t *testing.T) {
	allOn := make([]string, 0, len(nginxconf.BypassIPGroups))
	for i := range nginxconf.BypassIPGroups {
		allOn = append(allOn, nginxconf.BypassIPGroups[i].ID)
	}
	n := settings.Nginx{BypassIPEnabledPresets: allOn, SeenVersion: "v0.1.7"}
	pats := nginxconf.SortedUpstreamUAOff(n)
	if len(pats) == 0 {
		t.Fatal("expected UA-off patterns with all presets on")
	}
	re := regexp.MustCompile("(?i)(?:" + strings.Join(pats, ")|(?:") + ")")

	cases := []struct {
		ua   string
		want bool
	}{
		{"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", false},
		{"Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)", false},
		{"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; GPTBot/1.0", false},
		{"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Amazonbot/0.1)", false},
		// ClaudeBot used to sit on the "no published range" side of this
		// table, until Anthropic published bots.json -- with the claude
		// preset on, a UA-only ClaudeBot is a spoof like any other.
		{"Mozilla/5.0 (compatible; ClaudeBot/1.0; +claudebot@anthropic.com)", false},
		// No published range -> UA rescue stays.
		{"Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)", true},
	}
	for _, c := range cases {
		if got := isSearchBotUA(c.ua, "", n, re); got != c.want {
			t.Errorf("isSearchBotUA(%q, rangeVerified) = %v, want %v", c.ua, got, c.want)
		}
	}

	// Operator Extra row: explicit UA-only rescue wins over the inversion.
	n.SearchBots.Extra = []string{`Googlebot\/`}
	ua := "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
	if !isSearchBotUA(ua, "", n, re) {
		t.Error("operator Extra row must rescue a range-verified UA")
	}
}

// A honeypot ban's reason is read months after the trip, often by someone
// deciding whether to lift it.  It has to say which host was probed: on a
// multi-site install /cgi-bin/ exists on every vhost that has one, and a path
// alone cannot answer "which site is being scanned".  Both wires build it here
// so the two cannot drift into two spellings of the same event.
func TestHoneypotReason(t *testing.T) {
	long := "/cgi-bin/x?" + strings.Repeat("a", 400)
	for _, tc := range []struct{ name, host, uri, want string }{
		{"host and path", "www.example.com", "/cgi-bin/test?cmd=id", "hit www.example.com/cgi-bin/test?cmd=id"},
		{"no host still names the path", "", "/cgi-bin/test", "hit /cgi-bin/test"},
		{"no path still names the host", "www.example.com", "", "honeypot on www.example.com"},
		{"neither", "", "", "honeypot"},
		{"whitespace is not a value", "  ", "  ", "honeypot"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := honeypotReason(tc.host, tc.uri); got != tc.want {
				t.Errorf("honeypotReason(%q, %q) = %q, want %q", tc.host, tc.uri, got, tc.want)
			}
		})
	}
	// Both halves are attacker-supplied, so both are bounded.  The reason
	// column is VARCHAR(255); a scanner that sends a kilobyte of path must not
	// be able to decide how much of the row survives the insert.
	got := honeypotReason(strings.Repeat("h", 200), long)
	if len(got) > reasonMaxLen {
		t.Errorf("reason is %d chars, past what the column holds: %q", len(got), got[:80])
	}
}
