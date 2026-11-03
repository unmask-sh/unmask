package handlers

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/cookies"
	"github.com/unmask-sh/unmask/admin/internal/ipgeo"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

const (
	postureBrowserUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36"
	postureStaleUA   = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.0.0 Safari/537.36"
	postureOtherUA   = "SomeClient/1.0"
)

// Which UAs the global posture puts behind a CAPTCHA requirement.  The
// posture is the decision of last resort, so it answers only for a UA no
// rule of the UA axis names: a listed UA takes its row's chain, a stale UA
// the tier's.
func TestPostureNeedsCaptchaGrade(t *testing.T) {
	posture := func(known, unknown string) settings.Settings {
		var s settings.Settings
		s.Global.KnownBrowserAction = known
		s.Global.UnknownUAAction = unknown
		return s
	}
	for _, c := range []struct {
		name string
		cfg  settings.Settings
		ua   string
		want bool
	}{
		{"known bucket ends in a CAPTCHA", posture(settings.RateChallengePoWThenCaptcha, ""), postureBrowserUA, true},
		{"the unknown bucket is unset: pow_only", posture(settings.RateChallengePoWThenCaptcha, ""), postureOtherUA, false},
		{"unknown bucket captcha_only", posture(settings.RateChallengePoWOnly, settings.RateChallengeCaptchaOnly), postureOtherUA, true},
		{"a known browser on pow_only is not swept in", posture(settings.RateChallengePoWOnly, settings.RateChallengeCaptchaOnly), postureBrowserUA, false},
		{"no UA falls in the unknown bucket", posture(settings.RateChallengePoWOnly, settings.RateChallengeCaptchaOnly), "", true},
		{"pass demands nothing", posture("pass", "pass"), postureBrowserUA, false},
		{"deny is enforced ahead of the cookie", posture(settings.RateChallengeDeny, settings.RateChallengeDeny), postureBrowserUA, false},
	} {
		if got := postureNeedsCaptchaGrade(c.ua, c.cfg); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}

	// A UA on the black list takes its row's chain: the posture has no say,
	// whichever way the row and the bucket differ.
	listed := posture(settings.RateChallengePoWThenCaptcha, settings.RateChallengePoWThenCaptcha)
	listed.Nginx.ChallengeTargets.Extra = []string{"contains:SomeClient"}
	listed.Nginx.ChallengeTargets.ExtraAction = []string{settings.RateChallengePoWOnly}
	if postureNeedsCaptchaGrade(postureOtherUA, listed) {
		t.Error("a listed UA on a pow_only row must not inherit the posture's demand")
	}

	// The stale tier replaces the pick with its own screen, so the demand
	// follows the tier's chain for a stale UA: a pow_only tier under a
	// captcha-ending posture demands nothing, a captcha tier under a pow_only
	// posture demands the grade.
	stale := func(posture, tier string) settings.Settings {
		var s settings.Settings
		s.Global.KnownBrowserAction = posture
		s.Global.StaleBrowserChallenge = true
		s.Global.CurrentChromeMajor = 150
		s.Global.StaleBrowserLag = 35
		s.Global.StaleBrowserAction = tier
		return s
	}
	if postureNeedsCaptchaGrade(postureStaleUA, stale(settings.RateChallengePoWThenCaptcha, settings.RateChallengePoWOnly)) {
		t.Error("a stale UA handed the tier's proof of work must not be asked for a CAPTCHA grade")
	}
	if !postureNeedsCaptchaGrade(postureBrowserUA, stale(settings.RateChallengePoWThenCaptcha, settings.RateChallengePoWOnly)) {
		t.Error("the pow_only tier must not soften the posture for a fresh browser")
	}
	if !postureNeedsCaptchaGrade(postureStaleUA, stale(settings.RateChallengePoWOnly, settings.RateChallengeCaptchaOnly)) {
		t.Error("a stale UA handed the tier's CAPTCHA owes that grade")
	}
}

// uaDecide and the posture's demand resolve the pick through one function,
// so the chain the UA axis votes with is the chain whose grade is demanded.
func TestPosturePickMatchesUADecide(t *testing.T) {
	var cfg settings.Settings
	cfg.Global.KnownBrowserAction = settings.RateChallengePoWThenCaptcha
	cfg.Global.StaleBrowserChallenge = true
	cfg.Global.CurrentChromeMajor = 150
	cfg.Global.StaleBrowserLag = 35
	cfg.Global.StaleBrowserAction = settings.RateChallengeCaptchaOnly
	for _, ua := range []string{postureBrowserUA, postureStaleUA, postureOtherUA} {
		pick, _ := posturePick(ua, cfg.Global)
		d, _ := uaDecide(ua, "", cfg, nil)
		if d.chMode != pick {
			t.Errorf("%q: uaDecide votes %q, posturePick says %q", ua, d.chMode, pick)
		}
	}
}

// Forward-auth: a proof-of-work cookie does not pass a posture that ends in
// a CAPTCHA; a CAPTCHA-grade cookie does, a pow_only posture takes the
// proof-of-work cookie as before, and the known-browser bucket is read apart
// from the unknown one.  The challenge the refusal falls through to is the
// posture's own chain, which ends in the CAPTCHA the refusal asks for.
func TestAuthCheck_PostureDemandsItsGrade(t *testing.T) {
	const ip = "203.0.113.71"
	const host = "shop.example.com"
	cfg := func(known, unknown string) settings.Settings {
		s := settings.Settings{Secret: settings.Secret{BVSecret: "test-secret"}}
		s.Global.KnownBrowserAction = known
		s.Global.UnknownUAAction = unknown
		return s
	}
	drive := func(h *Handler, ua, kind string) (action, chain string) {
		r := httptest.NewRequest(http.MethodGet, "/unmask/api/check", nil)
		r.Header.Set("X-Original-URI", "/article/1")
		r.Header.Set("X-Original-IP", ip)
		r.Header.Set("X-Original-Host", host)
		r.Header.Set("User-Agent", ua)
		if kind != "" {
			r.AddCookie(&http.Cookie{Name: "_bv", Value: cookies.IssueValue("test-secret", ip, host, kind)})
		}
		w := httptest.NewRecorder()
		h.AuthCheck(w, r)
		return w.Result().Header.Get("X-Unmask-Action"), w.Result().Header.Get("X-Unmask-Chmode")
	}
	h := &Handler{}

	h.SetSettings(cfg(settings.RateChallengePoWThenCaptcha, settings.RateChallengePoWThenCaptcha))
	if action, chain := drive(h, postureBrowserUA, "pow"); action != "challenge" || chain != settings.RateChallengePoWThenCaptcha {
		t.Errorf("browser with a proof-of-work cookie on a pow_then_captcha posture: %s / %q, want challenge / pow_then_captcha", action, chain)
	}
	if action, _ := drive(h, postureBrowserUA, "captcha"); action != "pass" {
		t.Errorf("browser with a CAPTCHA cookie: %s, want pass", action)
	}
	if action, _ := drive(h, postureBrowserUA, "rebind"); action != "challenge" {
		t.Errorf("a re-bound credential does not satisfy the posture's CAPTCHA: %s, want challenge", action)
	}
	if action, _ := drive(h, postureOtherUA, "pow"); action != "challenge" {
		t.Errorf("unknown UA with a proof-of-work cookie: %s, want challenge", action)
	}

	h.SetSettings(cfg(settings.RateChallengePoWOnly, settings.RateChallengePoWOnly))
	if action, _ := drive(h, postureBrowserUA, "pow"); action != "pass" {
		t.Errorf("browser with a proof-of-work cookie on a pow_only posture: %s, want pass", action)
	}

	// Known browsers transparent, the rest behind a CAPTCHA: the browser's
	// proof-of-work cookie is untouched by the unknown bucket's demand.
	h.SetSettings(cfg(settings.RateChallengePoWOnly, settings.RateChallengeCaptchaOnly))
	if action, _ := drive(h, postureBrowserUA, "pow"); action != "pass" {
		t.Errorf("known browser on pow_only beside a captcha_only unknown bucket: %s, want pass", action)
	}
	if action, chain := drive(h, postureOtherUA, "pow"); action != "challenge" || chain != settings.RateChallengeCaptchaOnly {
		t.Errorf("unknown UA on captcha_only with a proof-of-work cookie: %s / %q, want challenge / captcha_only", action, chain)
	}

	// The stale tier's screen replaces the posture's for a stale UA: set to
	// pow_only, its proof-of-work cookie keeps passing (the tier mints
	// exactly that), so the client is never caught between the two.
	tiered := cfg(settings.RateChallengePoWThenCaptcha, settings.RateChallengePoWThenCaptcha)
	tiered.Global.StaleBrowserChallenge = true
	tiered.Global.CurrentChromeMajor = 150
	tiered.Global.StaleBrowserLag = 35
	tiered.Global.StaleBrowserAction = settings.RateChallengePoWOnly
	h.SetSettings(tiered)
	if action, _ := drive(h, postureStaleUA, "pow"); action != "pass" {
		t.Errorf("stale browser with the pow_only tier's cookie: %s, want pass", action)
	}
	if action, _ := drive(h, postureBrowserUA, "pow"); action != "challenge" {
		t.Errorf("fresh browser under the pow_then_captcha posture: %s, want challenge", action)
	}
}

// The rebind gate: a proof-of-work lineage is not carried onto a new address
// where the posture ends in a CAPTCHA -- the gate would refuse the re-bound
// credential and the challenge route re-bind it again, forever.  A lineage
// born of a CAPTCHA still roams, and a pow_only posture re-binds as before.
func TestTryRebind_PostureRefusesAProofOfWorkLineage(t *testing.T) {
	const ja4 = "t13d1516h2_8daaf6152771_d8a2da3f94cd"
	uah := cookies.FingerprintHash(postureBrowserUA)
	mk := func(posture, grade string) (*Handler, *httptest.ResponseRecorder, *http.Request) {
		h := newRebindTestHandler(t)
		s := h.snapshotSettings()
		s.Global.KnownBrowserAction = posture
		h.SetSettings(s)
		req := httptest.NewRequest(http.MethodGet, "https://example.com/unmask/challenge/", nil)
		req.Host = "example.com"
		req.Header.Set("X-Real-IP", "203.0.113.5")
		req.Header.Set("User-Agent", postureBrowserUA)
		req.Header.Set("X-Client-JA4", ja4)
		req.AddCookie(&http.Cookie{Name: "_bvj", Value: cookies.IssueJValue("test-secret", cookies.FingerprintHash(ja4), uah,
			"linposture00000000000000", 0, "example.com", grade)})
		return h, httptest.NewRecorder(), req
	}
	bvIssued := func(rr *httptest.ResponseRecorder) bool {
		for _, c := range rr.Result().Cookies() {
			if c.Name == "_bv" {
				return true
			}
		}
		return false
	}
	if h, rr, req := mk(settings.RateChallengePoWThenCaptcha, "pow"); h.tryRebind(rr, req, "default", "bt-test") || bvIssued(rr) {
		t.Error("a proof-of-work lineage was re-bound under a posture that ends in a CAPTCHA")
	}
	if h, rr, req := mk(settings.RateChallengePoWThenCaptcha, "captcha"); !h.tryRebind(rr, req, "default", "bt-test") || !bvIssued(rr) {
		t.Error("a CAPTCHA lineage must still roam under a pow_then_captcha posture")
	}
	if h, rr, req := mk(settings.RateChallengePoWOnly, "pow"); !h.tryRebind(rr, req, "default", "bt-test") || !bvIssued(rr) {
		t.Error("a proof-of-work lineage must still roam under a pow_only posture")
	}
}

// The serve names the network axis only where it decided the request.  A
// country rule the request's path is exempt from is left out by the conf
// ($geo_challenge_eff) and the posture decides; the serve used to attribute
// the rule anyway and hand out its chain, which was merely a mislabelled
// screen until the posture demanded a grade that chain cannot mint.
func TestServeLeavesAnExemptNetworkAxisToThePosture(t *testing.T) {
	t.Setenv("UNMASK_TEST_GEO_OVERRIDE", "198.51.100.20:CN")
	h := newTestHandler(t)
	h.IPGeo = ipgeo.Open("", "")
	cur := h.snapshotSettings()
	cur.Server.BasePath = "/unmask"
	cur.Global.KnownBrowserAction = settings.RateChallengePoWThenCaptcha
	cur.Nginx.Geo = settings.GeoConfig{
		Rules:       []settings.GeoRule{{Country: "CN", Action: settings.RateChallengePoWOnly, Enabled: true}},
		ExemptPaths: []settings.BypassPath{{Path: `^/feed/`}},
	}
	h.SetSettings(cur)

	serve := func(orig string) (reason, chain string) {
		req := httptest.NewRequest(http.MethodGet, "/unmask/challenge/?u=%2F", nil)
		req.Header.Set("User-Agent", postureBrowserUA)
		req.Header.Set("X-Original-URI", orig)
		req.RemoteAddr = "198.51.100.20:40000"
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
	if reason, chain := serve("/article/1"); reason != "geo" || chain != settings.RateChallengePoWOnly {
		t.Errorf("on a path the rule covers: %s / %q, want geo / pow_only", reason, chain)
	}
	if reason, chain := serve("/feed/atom.xml"); reason != "none" || chain != settings.RateChallengePoWThenCaptcha {
		t.Errorf("on a geo-exempt path: %s / %q, want none / pow_then_captcha (the posture's own chain)", reason, chain)
	}
}
