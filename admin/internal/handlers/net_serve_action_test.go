package handlers

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/ipgeo"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// A network rule's action has to reach the screen the visitor is shown, not
// just the decision to show one.
//
// The serve path names the axis that escalated a request so the funnel can
// attribute it.  It named geo / asn and then applied nothing: the chain fell
// through to the default, and the grade backstop -- seeing a chain that did not
// end in a CAPTCHA while the rule demanded a CAPTCHA-grade pass -- escalated it
// to pow_then_captcha.  That is deliberately the safe escalation, since it
// keeps the proof-of-work leg and can never be weaker than what was picked.
//
// But the proof-of-work leg is exactly what an operator choosing captcha_only
// is declining to offer.  Against a network whose clients run JavaScript the
// leg is free to solve, so serving it back is not "not weaker" -- it hands the
// automation a step it can pass and charges the wait to everyone else.  The
// attribution and the chain now come from one lookup, so they cannot disagree.
func TestNetChallengeReasonCarriesTheRulesChain(t *testing.T) {
	// 203.0.113.10 -> AS132203 (an ASN rule);  198.51.100.20 -> country CN
	// with no ASN;  192.0.2.5 -> neither.
	t.Setenv("UNMASK_TEST_GEO_OVERRIDE", "203.0.113.10:SG:132203,198.51.100.20:CN,192.0.2.5:US")
	h := &Handler{IPGeo: ipgeo.Open("", "")}

	cfg := settings.Settings{}
	cfg.Nginx.Asn = settings.AsnConfig{
		Rules: []settings.AsnRule{
			{ASN: 132203, Action: settings.RateChallengeCaptchaOnly, Enabled: true},
		},
	}
	cfg.Nginx.Geo = settings.GeoConfig{
		Rules: []settings.GeoRule{
			{Country: "CN", Action: settings.RateChallengePoWOnly, Enabled: true},
		},
	}

	for _, tc := range []struct{ name, ip, wantReason, wantChain string }{
		{"an ASN rule serves its own chain", "203.0.113.10", "asn", settings.RateChallengeCaptchaOnly},
		{"a country rule serves its own chain", "198.51.100.20", "geo", settings.RateChallengePoWOnly},
		{"a client no rule matches escalates nothing", "192.0.2.5", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reason, chain := h.netChallengeReason(tc.ip, cfg)
			if reason != tc.wantReason {
				t.Errorf("reason = %q, want %q", reason, tc.wantReason)
			}
			if chain != tc.wantChain {
				t.Errorf("chain = %q, want %q -- the rule's action did not reach the serve", chain, tc.wantChain)
			}
		})
	}
}

// A rate-gated rule is served through the rate-limit path, which resolves its
// own action; naming it here as well would attribute the same request twice.
func TestNetChallengeReasonLeavesRateRulesAlone(t *testing.T) {
	t.Setenv("UNMASK_TEST_GEO_OVERRIDE", "203.0.113.10:SG:132203")
	h := &Handler{IPGeo: ipgeo.Open("", "")}

	r60 := 60
	cfg := settings.Settings{}
	cfg.Nginx.Asn = settings.AsnConfig{
		Rules: []settings.AsnRule{
			{ASN: 132203, Action: settings.RateChallengeCaptchaOnly, RatePerMin: &r60, Enabled: true},
		},
	}
	if reason, chain := h.netChallengeReason("203.0.113.10", cfg); reason != "" || chain != "" {
		t.Errorf("a rate-mode rule was attributed to the direct path: reason=%q chain=%q", reason, chain)
	}
}

// End to end through the serve: an ASN rule set to captcha_only has to put a
// CAPTCHA on the screen, not a proof of work followed by one.
//
// This is the failure as an operator meets it.  The rule was applied -- the
// request was challenged and attributed to the ASN axis -- so the settings page
// and the funnel both looked right, while the visitor was handed a chain the
// operator had explicitly not chosen.
func TestASNRuleServesItsOwnChain(t *testing.T) {
	t.Setenv("UNMASK_TEST_GEO_OVERRIDE", "203.0.113.10:SG:132203,192.0.2.5:US")
	h := newTestHandler(t)
	h.IPGeo = ipgeo.Open("", "")
	cur := h.snapshotSettings()
	cur.Server.BasePath = "/unmask"
	// The base posture an untargeted visitor gets: a proof of work, no CAPTCHA.
	cur.Global.KnownBrowserAction = settings.RateChallengePoWOnly
	cur.Global.UnknownUAAction = settings.RateChallengePoWOnly
	cur.Nginx.Asn = settings.AsnConfig{
		Rules: []settings.AsnRule{
			{ASN: 132203, Action: settings.RateChallengeCaptchaOnly, Enabled: true},
		},
	}
	h.SetSettings(cur)

	const ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36"
	serve := func(ip string) (reason, chain string) {
		req := httptest.NewRequest(http.MethodGet, "/unmask/challenge/?u=%2F", nil)
		req.Header.Set("User-Agent", ua)
		req.RemoteAddr = ip + ":40000"
		rr := httptest.NewRecorder()
		h.ServeChallenge(rr, req)
		body := rr.Body.String()
		fr := regexp.MustCompile(`/\*__CAPTCHA_FORCE__\*/"([a-z_]*)"`).FindStringSubmatch(body)
		cm := regexp.MustCompile(`/\*__CHMODE__\*/"([a-z_]*)"`).FindStringSubmatch(body)
		if fr == nil || cm == nil {
			t.Fatalf("serve produced no force reason / chain (status %d)", rr.Code)
		}
		return fr[1], cm[1]
	}

	reason, chain := serve("203.0.113.10")
	if reason != "asn" {
		t.Errorf("force_reason = %q, want asn", reason)
	}
	if chain != settings.RateChallengeCaptchaOnly {
		t.Errorf("served chain = %q, want captcha_only -- the rule's action did not reach the visitor", chain)
	}

	// And a client the rule does not match keeps the site's ordinary posture,
	// so the branch cannot be passing by applying the rule to everyone.
	if reason, chain := serve("192.0.2.5"); reason == "asn" || chain == settings.RateChallengeCaptchaOnly {
		t.Errorf("an unmatched client got the ASN rule's treatment: reason=%q chain=%q", reason, chain)
	}
}
