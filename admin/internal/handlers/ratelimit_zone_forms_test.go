package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/ratelimit"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// A rate zone's patterns are held against the request's URI as the client
// sent it and as the web server routes it.  Held against the first alone, a
// path with one character written as an escape ("/wp-login%2Ephp", served as
// /wp-login.php) was on no zone's paths: forward-auth did not count it, and
// the native rate route did not know its zone's cap for a deny.

func loginDenyZone() settings.Settings {
	return settings.Settings{
		Secret: settings.Secret{BVSecret: "test-secret"},
		RateLimit: settings.RateLimitConfig{
			Zones: []settings.RateZone{{
				Name:           "login",
				PathPatterns:   []string{`^/wp-login\.php`, `[?&]s=`},
				ChallengeMode:  settings.RateChallengeDeny,
				RequestsPerMin: 2,
			}},
		},
	}
}

func TestAuthCheck_ZoneCountsAPathWrittenWithAnEscape(t *testing.T) {
	const ua = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"
	blockedWithin := func(uri string, n int) bool {
		h := &Handler{RateLimiter: ratelimit.New()}
		h.SetSettings(loginDenyZone())
		for i := 0; i < n; i++ {
			r := httptest.NewRequest(http.MethodGet, "/unmask/api/check", nil)
			r.Header.Set("X-Original-URI", uri)
			r.Header.Set("X-Original-IP", "203.0.113.51")
			r.Header.Set("X-Original-Host", "shop.example.com")
			r.Header.Set("User-Agent", ua)
			w := httptest.NewRecorder()
			h.AuthCheck(w, r)
			if res := w.Result(); res.StatusCode == http.StatusForbidden && res.Header.Get("X-Unmask-Action") == "block" {
				return true
			}
		}
		return false
	}
	for _, uri := range []string{
		"/wp-login.php",
		"/wp-login%2Ephp",
		"/%77p-login.php?redirect_to=%2F",
		"/x/../wp-login.php",
		"//wp-login.php",
		"/?s=shoes",
		"/%73earch?page=2&s=shoes",
	} {
		if !blockedWithin(uri, 12) {
			t.Errorf("%s: twelve requests in a row were never held to the zone's cap of 2 a minute", uri)
		}
	}
	// A path the zone does not name is not held to its cap (the default
	// limit is far above twelve).
	if blockedWithin("/blog/", 12) {
		t.Error("/blog/ was held to the cap of a zone that does not name it")
	}
}

// The native rate route: nginx sends a request over a limit to
// /unmask/_rl<path>, by the path it routes (the module's redirect, and the
// classic rewrite), the query behind it and the request line's own URI in
// X-Original-URI.  A deny zone that names the request in either form is the
// hard cap.
func TestRateRouteKnowsADenyZoneInEitherForm(t *testing.T) {
	h := newTestHandler(t)
	s := loginDenyZone()
	h.updateSettingsInMemory(func(cur *settings.Settings) { cur.RateLimit = s.RateLimit })
	// What an API client is told: "rate_limited" is the deny, anything else
	// a challenge to clear (a rate challenge answers 429 as well).
	serve := func(target, sent string) string {
		r := httptest.NewRequest(http.MethodGet, "https://example.test/unmask/_rl"+target, nil)
		r.Host = "example.test"
		r.Header.Set("X-Real-IP", "203.0.113.7")
		r.Header.Set("Sec-Fetch-Dest", "empty")
		r.Header.Set("Sec-Fetch-Mode", "cors")
		if sent != "" {
			r.Header.Set("X-Original-URI", sent)
		}
		rr := httptest.NewRecorder()
		h.ServeChallengeOrJSON(rr, r)
		var b map[string]any
		if err := json.Unmarshal(rr.Body.Bytes(), &b); err != nil {
			t.Fatalf("GET /unmask/_rl%s: %d %s", target, rr.Code, rr.Body.String())
		}
		e, _ := b["error"].(string)
		return e
	}
	for _, c := range []struct{ what, target, sent string }{
		{"the path as the pattern writes it", "/wp-login.php", "/wp-login.php"},
		{"sent with an escape, routed without", "/wp-login.php", "/wp-login%2Ephp"},
		{"a pattern that names the query", "/search?page=2&s=shoes", "/search?page=2&s=shoes"},
		{"...under a path sent with an escape", "/search?s=shoes", "/%73earch?s=shoes"},
	} {
		if e := serve(c.target, c.sent); e != "rate_limited" {
			t.Errorf("%s: the rate route answered %q, want the deny zone's rate_limited", c.what, e)
		}
	}
	if e := serve("/blog/", "/blog/"); e == "rate_limited" || e == "" {
		t.Errorf("/blog/, which the zone does not name, was answered %q; want a challenge to clear", e)
	}
}

func TestRoutedURI(t *testing.T) {
	for in, want := range map[string]string{
		"/wp-login%2Ephp":           "/wp-login.php",
		"/%73earch?s=%2Fshoes":      "/search?s=%2Fshoes", // the query stays as sent
		"/wp-login.php":             "",                   // nothing to decode: the URI itself
		"/plain?x=%41":              "",
		"/bad%zzescape":             "",
		"/%E3%81%82?":               "/あ?",
		"/a%3Fb":                    "/a?b",
		"/files/%E3%81%82.pdf?dl=1": "/files/あ.pdf?dl=1",
		// The segments the web server resolves, written plainly or escaped.
		"/x/../wp-login.php":     "/wp-login.php",
		"/x/%2e%2e/wp-login.php": "/wp-login.php",
		"/x/..%2Fwp-login.php":   "/wp-login.php",
		"//wp-login.php?a=//":    "/wp-login.php?a=//",
		"/./wp-login.php":        "/wp-login.php",
		"/a/b/../":               "/a/",
		"/a/.":                   "/a/",
		"/a/..":                  "/",
		"/../../etc":             "/etc",
		"/api/":                  "", // a trailing slash is the path's own
		"/.well-known/x":         "", // a name that starts with a dot is a name
		"/a/.hidden/..b":         "",
		"/x/..a/wp-login.php":    "",
		"relative/../x":          "",
	} {
		if got := routedURI(in); got != want {
			t.Errorf("routedURI(%q) = %q, want %q", in, got, want)
		}
	}
}
