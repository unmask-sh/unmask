package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// serveChain is the order in which the tiers of a challenge serve override
// one another.  ServeChallenge's own tests go through the whole page; these
// hold the order itself, tier by tier, on the function alone.

const chainTestChrome = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"

func chainRequest(target, ua string, headers map[string]string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, target, nil)
	if ua != "" {
		r.Header.Set("User-Agent", ua)
	}
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

func TestServeChainOrder(t *testing.T) {
	const (
		pow     = settings.RateChallengePoWOnly
		captcha = settings.RateChallengeCaptchaOnly
		both    = settings.RateChallengePoWThenCaptcha
		deny    = settings.RateChallengeDeny
	)
	for _, tc := range []struct {
		name    string
		mutate  func(*settings.Settings)
		target  string
		ua      string
		headers map[string]string
		in      serveChainInputs
		want    string
	}{
		{
			name: "a plain serve takes the operating mode's pick for a known browser",
			mutate: func(s *settings.Settings) {
				s.Global.KnownBrowserAction = captcha
				s.Global.UnknownUAAction = both
			},
			ua: chainTestChrome, in: serveChainInputs{forceReason: "none"}, want: captcha,
		},
		{
			name: "and the other bucket's for a client that is not one",
			mutate: func(s *settings.Settings) {
				s.Global.KnownBrowserAction = captcha
				s.Global.UnknownUAAction = both
			},
			ua: "curl/8.5.0", in: serveChainInputs{forceReason: "none"}, want: both,
		},
		{
			name: "an unset bucket is the strict default, proof-of-work",
			ua:   chainTestChrome, in: serveChainInputs{forceReason: "none"}, want: pow,
		},
		{
			name: "a protected path serves its own mode",
			ua:   chainTestChrome, in: serveChainInputs{forceReason: "protected", ppMode: "captcha"}, want: captcha,
		},
		{
			name: "a network rule serves its own action",
			ua:   chainTestChrome, in: serveChainInputs{forceReason: "asn", netChMode: captcha}, want: captcha,
		},
		{
			name: "a reused pass is answered with a CAPTCHA only",
			ua:   chainTestChrome, in: serveChainInputs{forceReason: "reuse_limit"}, want: captcha,
		},
		{
			name:   "the honeypot tab's default action",
			mutate: func(s *settings.Settings) { s.Nginx.Honeypot.DefaultAction = captcha },
			ua:     chainTestChrome, in: serveChainInputs{forceReason: "honeypot"}, want: captcha,
		},
		{
			name: "a listed User-Agent takes the black list's default, and its own row's chain over that",
			mutate: func(s *settings.Settings) {
				s.Nginx.ChallengeTargets.DefaultAction = both
			},
			ua: chainTestChrome, in: serveChainInputs{forceReason: "ua_target", uaListed: true, uaRowAction: captcha}, want: captcha,
		},
		{
			name: "a community-list hit replaces the axis's chain",
			mutate: func(s *settings.Settings) {
				s.CommunityBans.Action = captcha
			},
			ua: chainTestChrome, in: serveChainInputs{forceReason: "protected", ppMode: "pow", cbHitKind: "ip"}, want: captcha,
		},
		{
			name:    "a custom rule's action replaces the chain the tiers chose",
			ua:      chainTestChrome,
			headers: map[string]string{"X-Unmask-Rule-Action": captcha},
			in:      serveChainInputs{forceReason: "custom_rule"}, want: captcha,
		},
		{
			name:    "but never softens a deny",
			mutate:  func(s *settings.Settings) { s.Nginx.Honeypot.DefaultAction = deny },
			ua:      chainTestChrome,
			headers: map[string]string{"X-Unmask-Rule-Action": pow},
			in:      serveChainInputs{forceReason: "honeypot"}, want: deny,
		},
		{
			name:    "and is never a deny itself",
			ua:      chainTestChrome,
			headers: map[string]string{"X-Unmask-Rule-Action": deny},
			in:      serveChainInputs{forceReason: "protected", ppMode: "captcha"}, want: captcha,
		},
		{
			name:    "?chm= is taken when nginx says the request came from a page",
			target:  "/unmask/challenge/?chm=" + captcha,
			ua:      chainTestChrome,
			headers: map[string]string{"X-Original-URI": "/article/1"},
			in:      serveChainInputs{forceReason: "none"}, want: captcha,
		},
		{
			name:   "and ignored on a direct hit, where the query is the visitor's own",
			target: "/unmask/challenge/?chm=" + captcha,
			ua:     chainTestChrome,
			in:     serveChainInputs{forceReason: "none"}, want: pow,
		},
		{
			name: "a request the gate will ask a CAPTCHA-grade pass of never gets a chain without one",
			mutate: func(s *settings.Settings) {
				s.Nginx.ProtectedPaths.Paths = []settings.ProtectedPath{{Path: "^/login", Mode: "captcha"}}
			},
			ua:      chainTestChrome,
			headers: map[string]string{"X-Original-URI": "/login"},
			in:      serveChainInputs{forceReason: "none"}, want: both,
		},
		{
			name:   "?_force= on a test route wins over all of it, a deny included",
			mutate: func(s *settings.Settings) { s.Nginx.Honeypot.DefaultAction = deny },
			ua:     chainTestChrome,
			in:     serveChainInputs{forceReason: "honeypot", forceQuery: "pow"}, want: pow,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var s settings.Settings
			s.Server.BasePath = "/unmask"
			if tc.mutate != nil {
				tc.mutate(&s)
			}
			h := &Handler{}
			h.SetSettings(s)
			target := tc.target
			if target == "" {
				target = "/unmask/challenge/"
			}
			if got := h.serveChain(chainRequest(target, tc.ua, tc.headers), tc.in); got != tc.want {
				t.Errorf("chain = %q, want %q", got, tc.want)
			}
		})
	}
}

// With nothing attributed and nothing configured, the chain is the rate-limit
// default: what every path starts from.
func TestServeChainFallsBackToTheRateLimitDefault(t *testing.T) {
	var s settings.Settings
	s.Server.BasePath = "/unmask"
	h := &Handler{}
	h.SetSettings(s)
	want := s.RateLimit.Default.ResolvedChallengeMode()
	got := h.serveChain(chainRequest("/unmask/_rl/x", chainTestChrome, nil), serveChainInputs{forceReason: "rate_limit"})
	if got != want {
		t.Errorf("chain = %q, want the rate-limit default %q", got, want)
	}
}
