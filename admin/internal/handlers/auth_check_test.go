package handlers

import (
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
		name         string
		in           []axisDecision
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
		{Country: "FR", Action: ""},                                                 // inherit default
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
		{"manual ban source -> hard deny", "manual", cfgHpEmpty, sevDeny, "ban:manual"},
		{"shared_feed ban -> hard deny", "shared_feed", cfgHpEmpty, sevDeny, "ban:shared_feed"},
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
		name      string
		action    string
		verdict   string
		wantOK    bool
		wantSev   axisSeverity
		wantR     string
		wantChM   string
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
		Default: settings.RateZone{ChallengeMode: settings.RateChallengeCaptchaOnly},
	}}
	cfgDeny := settings.Settings{RateLimit: settings.RateLimitConfig{
		Default: settings.RateZone{ChallengeMode: settings.RateChallengeDeny},
	}}

	t.Run("non-matching uri -> silent", func(t *testing.T) {
		_, ok := protectedDecide("/public/", matchers, cfgCaptcha)
		if ok {
			t.Error("expected silent for non-matching uri")
		}
	})
	t.Run("/admin/ + chMode=captcha", func(t *testing.T) {
		d, ok := protectedDecide("/admin/dashboard", matchers, cfgCaptcha)
		if !ok || d.sev != sevCaptchaOnly || d.chMode != settings.RateChallengeCaptchaOnly {
			t.Errorf("got %+v ok=%v, want captcha", d, ok)
		}
	})
	t.Run("/admin/ + chMode=deny -> deny severity", func(t *testing.T) {
		d, ok := protectedDecide("/admin/dashboard", matchers, cfgDeny)
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
