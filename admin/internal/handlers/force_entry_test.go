package handlers

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/ipgeo"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// A challenge names the entry behind its reason: the UA filter row, the ASN
// or country rule, the trap, the protected path, the stale browser.  The
// page carries it for its beacons beside the reason.
func TestForceEntryNamesWhatFired(t *testing.T) {
	t.Setenv("UNMASK_TEST_GEO_OVERRIDE", "203.0.113.10:SG:132203,192.0.2.5:US")
	h := newTestHandler(t)
	h.IPGeo = ipgeo.Open("", "")
	cur := h.snapshotSettings()
	cur.Server.BasePath = "/unmask"
	cur.Nginx.ChallengeTargets.Extra = []string{"X11; Linux x86_64"}
	cur.Nginx.ChallengeTargets.ExtraAction = []string{"captcha_only"}
	cur.Nginx.Asn = settings.AsnConfig{Rules: []settings.AsnRule{{ASN: 132203, Label: "the farm", Action: settings.RateChallengeCaptchaOnly, Enabled: true}}}
	cur.Nginx.Geo = settings.GeoConfig{Rules: []settings.GeoRule{{Country: "US", Action: settings.RateChallengeCaptchaOnly, Enabled: true}}}
	cur.Nginx.Honeypot.URLs = []settings.HoneypotURL{{Path: "/trap", Title: "the trap"}}
	cur.Nginx.ProtectedPaths.Paths = []settings.ProtectedPath{{Path: "^/account", Mode: "captcha"}}
	cur.Global.StaleBrowserChallenge = true
	h.SetSettings(cur)

	const farmUA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36"
	const plainUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36"
	const oldUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.0.0 Safari/537.36"
	serve := func(ua, ip, target string, hdr map[string]string) (reason, entry string) {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, target, nil)
		req.Header.Set("User-Agent", ua)
		req.RemoteAddr = ip + ":40000"
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		rr := httptest.NewRecorder()
		h.ServeChallenge(rr, req)
		body := rr.Body.String()
		fr := regexp.MustCompile(`/\*__CAPTCHA_FORCE__\*/"([a-z_]*)"`).FindStringSubmatch(body)
		fe := regexp.MustCompile(`/\*__FORCE_RULE__\*/"([^"]*)"`).FindStringSubmatch(body)
		if fr == nil || fe == nil {
			t.Fatalf("no reason / entry in the served page (status %d)", rr.Code)
		}
		return fr[1], fe[1]
	}
	const plain = "/unmask/challenge/?u=%2F"
	for _, c := range []struct {
		name, ua, ip, target string
		hdr                  map[string]string
		reason, entry        string
	}{
		{"ua filter row", farmUA, "198.51.100.1", plain, nil, "ua_target", "own:X11; Linux x86_64"},
		{"asn rule", plainUA, "203.0.113.10", plain, nil, "asn", "AS132203"},
		{"country rule", plainUA, "192.0.2.5", plain, nil, "geo", "US"},
		{"trap", plainUA, "198.51.100.1", "/unmask/challenge/?_orig=%2Ftrap", map[string]string{"X-Honeypot-Hit": "1"}, "honeypot", "the trap"},
		{"protected path", plainUA, "198.51.100.1", "/unmask/challenge/?_orig=%2Faccount%2Fsettings", map[string]string{"X-Protected-Mode": "captcha"}, "protected", "^/account"},
		{"stale browser", oldUA, "198.51.100.1", plain, nil, "stale", "chrome 100"},
		{"custom rule", plainUA, "198.51.100.1", plain, map[string]string{"X-Unmask-Rule": "cr1a2b", "X-Unmask-Rule-Action": "captcha_only"}, "custom_rule", "cr1a2b"},
		{"nothing", plainUA, "198.51.100.1", plain, nil, "none", ""},
	} {
		if reason, entry := serve(c.ua, c.ip, c.target, c.hdr); reason != c.reason || entry != c.entry {
			t.Errorf("%s: reason %q entry %q, want %q %q", c.name, reason, entry, c.reason, c.entry)
		}
	}

	// A beacon keeps the entry the daemon can vouch for: got again from the
	// beacon's own UA or address, or one of a bounded set; anything else goes.
	bt := issueBeaconToken(h.cfg().Secret.CaptchaSecretBase)
	beacon := func(ua, ip, reason, entry, marker string) string {
		t.Helper()
		body := `{"phase":"load","flags":0,"reload_count":0,"ua":"` + marker + `","force_reason":"` + reason + `","force_rule":"` + entry + `","bt":"` + bt + `"}`
		req := httptest.NewRequest(http.MethodPost, "/unmask/api/debug", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", ua)
		req.Header.Set("X-Real-IP", ip)
		req.RemoteAddr = ip + ":40000" // the network entries are looked up as the serve looks them up
		rr := httptest.NewRecorder()
		h.DebugBeacon(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("beacon %s: %d %s", marker, rr.Code, rr.Body.String())
		}
		var payload string
		for i := 0; i < 150 && !strings.Contains(payload, `"ua":"`+marker+`"`); i++ {
			time.Sleep(20 * time.Millisecond)
			_ = h.DB.QueryRow(`SELECT COALESCE(payload_json, '') FROM unmask_event WHERE phase = 'load' ORDER BY id DESC LIMIT 1`).Scan(&payload)
		}
		return payload
	}
	for i, c := range []struct {
		ua, ip, reason, entry string
		kept                  bool
	}{
		{farmUA, "198.51.100.1", "ua_target", "own:X11; Linux x86_64", true},
		{plainUA, "198.51.100.1", "ua_target", "own:X11; Linux x86_64", false}, // not this visitor's row
		{plainUA, "203.0.113.10", "asn", "AS132203", true},
		{plainUA, "198.51.100.1", "asn", "AS132203", false}, // not this address's rule
		{plainUA, "192.0.2.5", "geo", "US", true},
		{oldUA, "198.51.100.1", "stale", "chrome 100", true},
		{plainUA, "198.51.100.1", "honeypot", "the trap", true},
		{plainUA, "198.51.100.1", "honeypot", "a trap we do not have", false},
		{plainUA, "198.51.100.1", "protected", "^/account", true},
		{plainUA, "198.51.100.1", "protected", "^/elsewhere", false},
		{plainUA, "198.51.100.1", "header", "no_sch_ua", true},
		{plainUA, "198.51.100.1", "header", "bogus", false},
		{plainUA, "198.51.100.1", "ja4_bot", "no_such_verdict", false},
		{plainUA, "198.51.100.1", "community_bans", "ip_only", true},
		{plainUA, "198.51.100.1", "community_bans", "something", false},
	} {
		marker := "fe" + strings.Repeat("x", i+1)
		p := beacon(c.ua, c.ip, c.reason, c.entry, marker)
		if got := strings.Contains(p, `"force_rule":"`); got != c.kept {
			t.Errorf("beacon %s %q from %s: kept=%v, want %v (%s)", c.reason, c.entry, c.ip, got, c.kept, p)
		}
	}
}

// The names the page gives the entries.
func TestForceEntryNames(t *testing.T) {
	h := newTestHandler(t)
	cur := h.snapshotSettings()
	cur.Nginx.CustomRules = []settings.CustomRule{{ID: "cr1", Label: "the scraper", Enabled: true}}
	cur.Nginx.Asn = settings.AsnConfig{Rules: []settings.AsnRule{{ASN: 132203, Label: "the farm", Enabled: true}}}
	h.SetSettings(cur)
	for _, c := range []struct{ reason, entry, want string }{
		{"custom_rule", "cr1", "the scraper"},
		{"custom_rule", "cr9", "cr9"},
		{"ua_target", "preset:empty", "Empty UA / extremely short UA (5 chars or fewer)"},
		{"ua_target", "own:X11; Linux", "X11; Linux"},
		{"ua_target", "crawler:Googlebot", "Googlebot"},
		{"asn", "AS132203", "AS132203 · the farm"},
		{"asn", "AS64496", "AS64496"},
		{"geo", "US", "US"},
		{"stale", "chrome 100", "Chrome 100"},
		{"header", "no_sch_ua", "Sec-CH-UA なし"},
		{"ja4_bot", "bot_curl", "bot_curl"},
		{"none", "", ""},
	} {
		if got := h.forceEntryName("ja", c.reason, c.entry); got != c.want {
			t.Errorf("%s %q: %q, want %q", c.reason, c.entry, got, c.want)
		}
	}
}
