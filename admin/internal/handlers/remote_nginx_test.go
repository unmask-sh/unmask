package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/cookies"
	"github.com/unmask-sh/unmask/admin/internal/ipgeo"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// nginx and the daemon on separate hosts (nginx.upstream_addr names the
// daemon): nginx connects from its own address, a peer outside loopback and
// the trusted-LB ranges, and names the visitor in X-Real-IP -- its
// $remote_addr, the address its geo maps match the country and ASN rules on.
// Whatever the daemon decides by the visitor's network has to be looked up on
// that same address, or the page and the gate in front of it answer for two
// different clients.
const (
	// remoteNginx: nginx's address on the network between the two hosts.
	remoteNginx = "10.0.0.4:40000"
	// cloudNginx: nginx's address where the hosts talk over public
	// addresses, inside the network the test's ASN rule targets.
	cloudNginx = "203.0.113.60:40000"
)

// The chain a challenge serves comes from the visitor's network.  It came
// from the connection's peer, so behind a remote nginx a visitor whose ASN or
// country rule ends in a CAPTCHA was served the posture's proof of work:
// nginx's gate, keyed on the visitor's address, asked that visitor for a
// CAPTCHA-grade pass, refused the one the proof of work minted, and sent the
// visitor back to the same proof of work, for good.  Where nginx's own
// address fell under a rule, every visitor sent to the page was served that
// rule's chain.
func TestServeChainUsesTheVisitorBehindARemoteNginx(t *testing.T) {
	t.Setenv("UNMASK_TEST_GEO_OVERRIDE", "203.0.113.10:SG:132203,198.51.100.20:CN,192.0.2.5:US,203.0.113.60:US:132203")
	h := newTestHandler(t)
	h.IPGeo = ipgeo.Open("", "")
	cur := h.snapshotSettings()
	cur.Server.BasePath = "/unmask"
	// The posture an untargeted visitor gets: a proof of work, no CAPTCHA.
	cur.Global.KnownBrowserAction = settings.RateChallengePoWOnly
	cur.Global.UnknownUAAction = settings.RateChallengePoWOnly
	cur.Nginx.Asn = settings.AsnConfig{Rules: []settings.AsnRule{
		{ASN: 132203, Action: settings.RateChallengeCaptchaOnly, Enabled: true},
	}}
	cur.Nginx.Geo = settings.GeoConfig{Rules: []settings.GeoRule{
		{Country: "CN", Action: settings.RateChallengePoWThenCaptcha, Enabled: true},
	}}
	h.SetSettings(cur)

	const ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36"
	for _, c := range []struct {
		name, peer, visitor  string
		reason, chain, entry string
	}{
		// One host: nginx on the loopback or the unix socket, as before.
		{"loopback nginx, an ASN rule", "127.0.0.1:40000", "203.0.113.10", "asn", settings.RateChallengeCaptchaOnly, "AS132203"},
		{"socket nginx, a country rule", "@", "198.51.100.20", "geo", settings.RateChallengePoWThenCaptcha, "CN"},
		// Two hosts.
		{"remote nginx, an ASN rule", remoteNginx, "203.0.113.10", "asn", settings.RateChallengeCaptchaOnly, "AS132203"},
		{"remote nginx, a country rule", remoteNginx, "198.51.100.20", "geo", settings.RateChallengePoWThenCaptcha, "CN"},
		{"remote nginx, no rule", remoteNginx, "192.0.2.5", "none", settings.RateChallengePoWOnly, ""},
		{"nginx's own network under a rule", cloudNginx, "192.0.2.5", "none", settings.RateChallengePoWOnly, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/unmask/challenge/?u=%2F", nil)
			req.Header.Set("User-Agent", ua)
			req.RemoteAddr = c.peer
			req.Header.Set("X-Real-IP", c.visitor)
			rr := httptest.NewRecorder()
			h.ServeChallenge(rr, req)
			body := rr.Body.String()
			reason := injectedString(t, body, "/*__CAPTCHA_FORCE__*/")
			chain := injectedString(t, body, "/*__CHMODE__*/")
			entry := injectedString(t, body, "/*__FORCE_RULE__*/")
			if reason != c.reason || chain != c.chain || entry != c.entry {
				t.Errorf("served reason %q chain %q entry %q, want %q %q %q", reason, chain, entry, c.reason, c.chain, c.entry)
			}
			// The loop itself.  The gate's requirement for this visitor is
			// the one nginx renders for its network ($unmask_asn_captcha /
			// $unmask_geo_captcha), asked here through its daemon-side twin:
			// a chain that does not end in a CAPTCHA mints a pass that gate
			// refuses, and the refusal comes back to this page.
			if h.axisNeedsCaptchaGradeFor(c.visitor, "/", pathMatchers{}, *h.cfg()) && !chainEndsInCaptcha(chain) {
				t.Errorf("the gate asks %s for a CAPTCHA-grade pass and the serve handed out %q: solved, refused, served again", c.visitor, chain)
			}
		})
	}
}

// The rate route behind a remote nginx.  A country or ASN rule with a rate
// limit of its own answers the overage nginx counted on the visitor's address
// with the rule's action, and a pass holder over that limit is the rule's,
// not the reuse cap's.  All three were decided on nginx's own network.
func TestRateRouteUsesTheVisitorBehindARemoteNginx(t *testing.T) {
	t.Setenv("UNMASK_TEST_GEO_OVERRIDE", "203.0.113.10:SG:132203,198.51.100.20:CN")
	const host = "example.test"
	h := newTestHandler(t)
	h.IPGeo = ipgeo.Open("", "")
	cur := h.snapshotSettings()
	cur.Server.BasePath = "/unmask"
	r60 := 60
	cur.Nginx.Asn = settings.AsnConfig{Rules: []settings.AsnRule{
		{ASN: 132203, Action: settings.RateChallengeDeny, RatePerMin: &r60, Enabled: true},
	}}
	cur.Nginx.Geo = settings.GeoConfig{Rules: []settings.GeoRule{
		{Country: "CN", Action: settings.RateChallengeCaptchaOnly, RatePerMin: &r60, Enabled: true},
	}}
	h.SetSettings(cur)

	overage := func(visitor string, page bool, bv string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(http.MethodGet, "https://"+host+"/unmask/_rl/articles/", nil)
		r.Host = host
		r.RemoteAddr = remoteNginx
		r.Header.Set("X-Real-IP", visitor)
		if page {
			r.Header.Set("Sec-Fetch-Dest", "document")
		} else {
			r.Header.Set("Sec-Fetch-Dest", "empty")
			r.Header.Set("Sec-Fetch-Mode", "cors")
		}
		if bv != "" {
			r.AddCookie(&http.Cookie{Name: "_bv", Value: bv})
		}
		rr := httptest.NewRecorder()
		h.ServeChallengeOrJSON(rr, r)
		return rr
	}
	jsonOf := func(rr *httptest.ResponseRecorder) map[string]any {
		t.Helper()
		var b map[string]any
		if err := json.Unmarshal(rr.Body.Bytes(), &b); err != nil {
			t.Fatalf("not JSON (status %d): %v\n%s", rr.Code, err, rr.Body.String())
		}
		return b
	}

	// The ASN rule's action is deny: a hard cap, not a challenge.
	if b := jsonOf(overage("203.0.113.10", false, "")); b["error"] != "rate_limited" {
		t.Errorf("over an ASN rule whose action is deny: %v, want the deny answer", b)
	}
	// The country rule's overage is served the rule's chain.
	if chain := injectedString(t, overage("198.51.100.20", true, "").Body.String(), "/*__CHMODE__*/"); chain != settings.RateChallengeCaptchaOnly {
		t.Errorf("over the country rule: chain %q, want the rule's captcha_only", chain)
	}
	// A pass holder over the country rule's limit gets the rule's answer.
	bv := cookies.IssueValue(cur.Secret.BVSecret, "198.51.100.20", host, "pow")
	if b := jsonOf(overage("198.51.100.20", false, bv)); b["reason"] != "rate_limit" {
		t.Errorf("a pass holder under the country rule: reason %v, want rate_limit, not the reuse cap's", b["reason"])
	}
}

// The deny page names the rule that refused the visitor: nginx refused on
// its own geo map, keyed on the address it names in X-Real-IP.
func TestAxisDenyNamesTheVisitorsRuleBehindARemoteNginx(t *testing.T) {
	t.Setenv("UNMASK_TEST_GEO_OVERRIDE", "198.51.100.20:CN")
	h := newTestHandler(t)
	h.IPGeo = ipgeo.Open("", "")
	cur := h.snapshotSettings()
	cur.Nginx.Geo = settings.GeoConfig{Rules: []settings.GeoRule{
		{Country: "CN", Action: settings.RateChallengeDeny, Enabled: true},
	}}
	h.SetSettings(cur)

	r := httptest.NewRequest(http.MethodGet, "/unmask/_deny/articles/", nil)
	r.Header.Set("Sec-Fetch-Dest", "empty") // non-navigation: the reason lands in the JSON body
	r.RemoteAddr = remoteNginx
	r.Header.Set("X-Real-IP", "198.51.100.20")
	w := httptest.NewRecorder()
	h.ServeAxisDeny(w, r)
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, w.Body.String())
	}
	if out["reason"] != "geo_deny" {
		t.Errorf("deny reason %v, want geo_deny -- the visitor's country rule", out["reason"])
	}
}
