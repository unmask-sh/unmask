package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/ipgeo"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// A country default that ends in a CAPTCHA, and a visitor the country
// database does not place.  nginx's geo block lists only the ranges of the
// countries a rule names, so that visitor takes the default and the gate asks
// for a CAPTCHA-grade pass.  The daemon resolved no country, asked nothing,
// and served the posture's proof of work: the gate refused the pass it minted
// and sent the visitor back to the same page, for good.  server.inc now hands
// over the gate's own answer (X-Unmask-Needs-Captcha), and the page ends in a
// CAPTCHA when it says so.
func TestServeMeetsTheGatesGradeForAnUnplacedAddress(t *testing.T) {
	t.Setenv("UNMASK_TEST_GEO_OVERRIDE", "198.51.100.20:JP,192.0.2.5:US")
	h := newTestHandler(t)
	h.IPGeo = ipgeo.Open("", "")
	cur := h.snapshotSettings()
	cur.Server.BasePath = "/unmask"
	cur.Global.KnownBrowserAction = settings.RateChallengePoWOnly
	cur.Global.UnknownUAAction = settings.RateChallengePoWOnly
	// Japan passes, every other country gets a CAPTCHA.
	cur.Nginx.Geo = settings.GeoConfig{
		DefaultAction: settings.RateChallengeCaptchaOnly,
		Rules:         []settings.GeoRule{{Country: "JP", Action: settings.GeoActionSkip, Enabled: true}},
	}
	h.SetSettings(cur)

	const ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36"
	serve := func(visitor, gate string) string {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/unmask/challenge/?u=%2F", nil)
		req.Header.Set("User-Agent", ua)
		req.RemoteAddr = "127.0.0.1:40000"
		req.Header.Set("X-Real-IP", visitor)
		if gate != "" {
			req.Header.Set("X-Unmask-Needs-Captcha", gate)
		}
		rr := httptest.NewRecorder()
		h.ServeChallenge(rr, req)
		return injectedString(t, rr.Body.String(), "/*__CHMODE__*/")
	}

	// The address the database does not place, with the gate asking.
	if got := serve("203.0.113.77", "1"); !chainEndsInCaptcha(got) {
		t.Errorf("an unplaced address the gate asks a CAPTCHA of was served %q -- a pass the gate refuses", got)
	}
	// A placed country no rule names: the daemon finds the default itself.
	if got := serve("192.0.2.5", ""); !chainEndsInCaptcha(got) {
		t.Errorf("a country under the default was served %q", got)
	}
	// The gate's answer raises a chain only: Japan keeps the posture's
	// proof of work when the gate asks for nothing more.
	if got := serve("198.51.100.20", "0"); got != settings.RateChallengePoWOnly {
		t.Errorf("a country set to pass, the gate asking nothing: served %q, want %q", got, settings.RateChallengePoWOnly)
	}
}

// The re-bind half of the same disagreement: carrying a proof-of-work solve
// onto a new address for a request the gate asks a CAPTCHA of mints a pass
// the gate refuses, and the challenge route re-binds it again.  When the gate
// says it asks for one, only a lineage born of a CAPTCHA roams.
func TestRebindHonoursTheGatesGrade(t *testing.T) {
	now := time.Now().Unix()
	rebind := func(grade, gate string) bool {
		t.Helper()
		h := expiryHandler(t, settings.ChallengeValues{})
		req := httptest.NewRequest(http.MethodGet, "https://example.com/unmask/challenge/", nil)
		req.Host = expiryHost
		req.Header.Set("X-Real-IP", expiryAddr)
		req.Header.Set("User-Agent", expiryUA)
		req.Header.Set("X-Client-JA4", expiryJA4)
		if gate != "" {
			req.Header.Set("X-Unmask-Needs-Captcha", gate)
		}
		req.AddCookie(&http.Cookie{Name: "_bvj", Value: expiryBVJ(now-day, grade, expiryUA)})
		return h.tryRebind(httptest.NewRecorder(), req, "default", "bt-test")
	}
	if !rebind("pow", "") {
		t.Fatal("precondition: a proof-of-work lineage should roam where nothing asks for a CAPTCHA")
	}
	if rebind("pow", "1") {
		t.Error("a proof-of-work lineage was re-bound for a request the gate asks a CAPTCHA of")
	}
	if !rebind("captcha", "1") {
		t.Error("a CAPTCHA lineage no longer roams where the gate asks for a CAPTCHA")
	}
}
