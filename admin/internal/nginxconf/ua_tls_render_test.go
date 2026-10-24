package nginxconf

import (
	"regexp"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestUATLSRenderOff: with the tier off none of its maps render, and the
// header tier, when on, writes $final_challenge itself.
func TestUATLSRenderOff(t *testing.T) {
	off := renderHTTPInc(t, func(s *settings.Settings) {
		s.Global.UATLSConsistencyDisabled = true
		s.Global.HeaderIntegrity = true
	})
	for _, absent := range []string{"$unmask_ua_tls_mismatch", "$unmask_ja4_chromium", "$fc_after_header", "X-UA-TLS-Mismatch"} {
		if strings.Contains(off, absent) {
			t.Errorf("tier off: %q must not render", absent)
		}
	}
	if !strings.Contains(off, `:$unmask_header_mismatch:$is_search_bot:$is_bypass_ip:$is_bypass_path:$bv_any_valid" $final_challenge {`) {
		t.Error("tier off: the header tier should write $final_challenge itself")
	}
}

// TestUATLSRenderHeld: on an install that reviews its upgrades the tier is
// held, like every default-on tightening, until the upgrade is acknowledged.
func TestUATLSRenderHeld(t *testing.T) {
	held := renderHTTPInc(t, func(s *settings.Settings) {
		s.Nginx.UpgradeReviewPolicy = settings.UpgradeReviewReview
		s.Nginx.EnforcementReviewedVersion = "v0.1.52"
	})
	if strings.Contains(held, "$unmask_ua_tls_mismatch") {
		t.Error("held: the tier rendered before the upgrade was acknowledged")
	}
	acked := renderHTTPInc(t, func(s *settings.Settings) {
		s.Nginx.UpgradeReviewPolicy = settings.UpgradeReviewReview
		s.Nginx.EnforcementReviewedVersion = settings.UATLSAddedIn
	})
	if !strings.Contains(acked, "$unmask_ua_tls_mismatch") {
		t.Error("acknowledged: the tier did not render")
	}
	var found bool
	for _, p := range HeldEnforcementPresets(func() settings.Settings {
		s := settings.Settings{}
		s.Nginx.UpgradeReviewPolicy = settings.UpgradeReviewReview
		s.Nginx.EnforcementReviewedVersion = "v0.1.52"
		return s
	}()) {
		if p.ID == "ua_tls_consistency" {
			found = true
		}
	}
	if !found {
		t.Error("the held list does not name the tier")
	}
}

// TestUATLSRenderOn: the default render carries the tier, chained after the
// header tier when that is on: the header tier writes $fc_after_header, the
// tier reads it and writes $final_challenge, keyed after every exemption;
// server.inc forwards the contradiction's name to the daemon.
func TestUATLSRenderOn(t *testing.T) {
	httpInc, serverInc, _ := renderIncs(t, func(s *settings.Settings) { s.Global.HeaderIntegrity = true })
	for _, want := range []string{
		`map $effective_ja4 $unmask_ja4_t13 {`,
		`map $effective_ja4 $unmask_ja4_chromium {`,
		`map $effective_ja4 $unmask_ja4_chromium_ciphers {`,
		`"~^t13d[0-9]+h[12]_8daaf6152771_" 1;`,
		`"~^t13d[0-9]+h[12]_8daaf6152771_(cb7bf5808d99|`,
		`map $http_user_agent $unmask_ua_tls_family {`,
		`map "$unmask_ua_tls_family:$http_user_agent" $unmask_ua_pre_tls13 {`,
		`map "$unmask_ja4_chromium:$unmask_ua_tls_family:$unmask_ja4_t13:$unmask_ua_pre_tls13:$unmask_ua_tls_reverse" $unmask_ua_tls_mismatch {`,
		`"~^1:[fs]:" family;`,
		`"~^[01]:[cfs]:1:1:" version;`,
		`:$unmask_header_mismatch:$is_search_bot:$is_bypass_ip:$is_bypass_path:$bv_any_valid" $fc_after_header {`,
		`map "$fc_after_header:$unmask_ua_tls_mismatch:$is_search_bot:$is_bypass_ip:$is_bypass_path:$bv_any_valid" $final_challenge {`,
		`default               $fc_after_header;`,
		`"~^0:[a-z]+:0:0:0:0$" 1;`,
	} {
		if !strings.Contains(httpInc, want) {
			t.Errorf("tier on: http.inc missing %q", want)
		}
	}
	if !strings.Contains(serverInc, `proxy_set_header   X-UA-TLS-Mismatch $unmask_ua_tls_mismatch;`) {
		t.Error("tier on: server.inc does not forward the contradiction")
	}
	// Alone -- header and stale off -- it reads the base decision and the base
	// map writes the intermediate.
	alone := renderHTTPInc(t, func(s *settings.Settings) { s.Global.HeaderIntegrity = false })
	if !strings.Contains(alone, `map "$final_challenge_base:$unmask_ua_tls_mismatch:`) {
		t.Error("tier alone: should read $final_challenge_base")
	}
	if !strings.Contains(alone, `:$ja4_action:$serve_bot_challenge" $final_challenge_base {`) {
		t.Error("tier alone: the base map should write $final_challenge_base")
	}
	// After the stale tier, with the header tier off: reads $fc_after_stale,
	// which the stale tier writes because a later tier runs.
	stale := renderHTTPInc(t, func(s *settings.Settings) {
		s.Global.HeaderIntegrity = false
		s.Global.StaleBrowserChallenge = true
	})
	if !strings.Contains(stale, `map "$fc_after_stale:$unmask_ua_tls_mismatch:`) ||
		!strings.Contains(stale, `:$unmask_stale_browser:$is_search_bot:$is_bypass_ip:$is_bypass_path:$bv_any_valid" $fc_after_stale {`) {
		t.Error("tier after stale: the stale tier should write $fc_after_stale and the tier read it")
	}
}

// TestUATLSMapSemantics pins what the rendered patterns MEAN against the
// browsers they are about.  nginx runs them under PCRE and this test under
// Go's regexp; the patterns use the common subset.
func TestUATLSMapSemantics(t *testing.T) {
	on := renderHTTPInc(t, nil)
	pat := func(mapHeader string) []string {
		i := strings.Index(on, mapHeader)
		if i < 0 {
			t.Fatalf("map %q not rendered", mapHeader)
		}
		body := on[i:]
		body = body[:strings.Index(body, "\n}")]
		var out []string
		for _, m := range regexp.MustCompile(`(?m)^\s*"~([^"]+)"\s+(\S+);`).FindAllStringSubmatch(body, -1) {
			out = append(out, m[1]+"\x00"+m[2])
		}
		return out
	}
	first := func(entries []string, in string) string {
		for _, e := range entries {
			re, val, _ := strings.Cut(e, "\x00")
			if regexp.MustCompile(re).MatchString(in) {
				return val
			}
		}
		return ""
	}
	t13 := pat(`map $effective_ja4 $unmask_ja4_t13 {`)
	chromium := pat(`map $effective_ja4 $unmask_ja4_chromium {`)
	family := pat(`map $http_user_agent $unmask_ua_tls_family {`)
	pre := pat(`map "$unmask_ua_tls_family:$http_user_agent" $unmask_ua_pre_tls13 {`)
	verdict := pat(`map "$unmask_ja4_chromium:$unmask_ua_tls_family:$unmask_ja4_t13:$unmask_ua_pre_tls13:$unmask_ua_tls_reverse" $unmask_ua_tls_mismatch {`)
	bit := func(v string) string {
		if v == "" {
			return "0"
		}
		return v
	}
	decide := func(ja4, ua string) string {
		fam := first(family, ua)
		key := bit(first(chromium, ja4)) + ":" + fam + ":" + bit(first(t13, ja4)) + ":" + bit(first(pre, fam+":"+ua)) + ":0"
		return first(verdict, key)
	}
	const chromeJA4 = "t13d1517h2_8daaf6152771_dcad5a053991"   // Chromium, TLS 1.3
	const chromeH1JA4 = "t13d1516h1_8daaf6152771_02713d6af862" // Chromium over h1
	const ffJA4 = "t13d1715h2_5b57614c22b0_3d5424432f57"       // Firefox, TLS 1.3
	const appleJA4 = "t13d2014h2_a09f3c656075_14788d8d241b"    // Safari, TLS 1.3
	const oldJA4 = "t12d1409h2_c866b44c5a26_6e3c2d30f1e8"      // a TLS 1.2 session
	for _, c := range []struct {
		name, ja4, ua, want string
	}{
		// The reported case: a Chromium fingerprint under a Safari 10 name, and
		// under a Chrome 47 name.
		{"safari10 on chromium", chromeJA4, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/603.3.8 (KHTML, like Gecko) Version/10.1.2 Safari/603.3.8", "family"},
		{"chrome47 on tls1.3", chromeJA4, "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.111 Safari/537.36", "version"},
		{"firefox on chromium", chromeJA4, "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:141.0) Gecko/20100101 Firefox/141.0", "family"},
		{"firefox on chromium h1", chromeH1JA4, "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0", "family"},
		{"safari name over chrome's whole fingerprint", "t13d1516h2_8daaf6152771_02713d6af862", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15", "family"},
		// Firefox 158 sends Chrome's fifteen ciphers under Firefox's own
		// extensions: the ciphers alone contradict nothing (before this,
		// 2026-10, every Firefox 158 user was sent to the CAPTCHA).
		{"firefox 158 on its own stack", "t13d1517h2_8daaf6152771_3cbfd9057e0d", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:158.0) Gecko/20100101 Firefox/158.0", ""},
		// Chrome's ciphers under an extension hash the list does not know:
		// not judged -- a Chrome release ahead of the list fails open.
		{"firefox name over unlisted extensions", "t13d1516h2_8daaf6152771_0c27189014cf", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:158.0) Gecko/20100101 Firefox/158.0", ""},
		{"old firefox on tls1.3", ffJA4, "Mozilla/5.0 (Windows NT 6.1; rv:52.0) Gecko/20100101 Firefox/52.0", "version"},
		{"ios11 safari on tls1.3", appleJA4, "Mozilla/5.0 (iPhone; CPU iPhone OS 11_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/11.0 Mobile/15E148 Safari/604.1", "version"},
		// Consistent clients, left alone.
		{"chrome", chromeJA4, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36", ""},
		{"edge", chromeJA4, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 Edg/141.0.0.0", ""},
		{"opera", chromeJA4, "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36 OPR/125.0.0.0", ""},
		{"headless chrome", chromeJA4, "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/141.0.0.0 Safari/537.36", ""},
		{"android webview", chromeJA4, "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/141.0.0.0 Mobile Safari/537.36", ""},
		{"firefox", ffJA4, "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:141.0) Gecko/20100101 Firefox/141.0", ""},
		{"firefox esr 60", ffJA4, "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0", ""},
		{"safari 17", appleJA4, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15", ""},
		{"safari 12.1", appleJA4, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.1 Safari/605.1.15", ""},
		{"chrome ios on apple tls", appleJA4, "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/141.0.0.0 Mobile/15E148 Safari/604.1", ""},
		{"firefox ios on apple tls", appleJA4, "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/141.0 Mobile/15E148 Safari/605.1.15", ""},
		{"chrome 65 on tls1.3", chromeJA4, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36", ""},
		// A TLS 1.2 session says nothing about the version, and an old name on
		// it is not a contradiction.
		{"chrome47 on tls1.2", oldJA4, "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.111 Safari/537.36", ""},
		// No fingerprint (behind a TLS-terminating LB): silent.
		{"no ja4", "", "Mozilla/5.0 (Windows NT 6.1; rv:52.0) Gecko/20100101 Firefox/52.0", ""},
		// curl and the like name no family: nothing to contradict.
		{"curl", chromeJA4, "curl/8.5.0", ""},
	} {
		if got := decide(c.ja4, c.ua); got != c.want {
			t.Errorf("%s: mismatch = %q, want %q", c.name, got, c.want)
		}
	}
}

// TestUATLSReverseSemantics: the opt-in reverse check names a Chromium
// browser over a fingerprint that is not Chromium's, on a TCP TLS 1.3
// session only, and never Chrome on iOS; off, the key's fifth field is 0.
func TestUATLSReverseSemantics(t *testing.T) {
	render := func(on bool) string {
		return renderHTTPInc(t, func(s *settings.Settings) { s.Global.UATLSReverseCheck = on })
	}
	pat := func(inc, mapHeader string) []string {
		i := strings.Index(inc, mapHeader)
		if i < 0 {
			t.Fatalf("map %q not rendered", mapHeader)
		}
		body := inc[i:]
		body = body[:strings.Index(body, "\n}")]
		var out []string
		for _, m := range regexp.MustCompile(`(?m)^\s*"~([^"]+)"\s+(\S+);`).FindAllStringSubmatch(body, -1) {
			out = append(out, m[1]+"\x00"+m[2])
		}
		return out
	}
	first := func(entries []string, in string) string {
		for _, e := range entries {
			re, val, _ := strings.Cut(e, "\x00")
			if regexp.MustCompile(re).MatchString(in) {
				return val
			}
		}
		return "0"
	}
	const chromeJA4 = "t13d1517h2_8daaf6152771_dcad5a053991"
	const goJA4 = "t13d1312h2_e8f1e7e78f70_bd3ad4a5b2e4"
	const quicJA4 = "q13d0312h3_55b375c5d22e_cd85d2d88918"
	const chromeUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"
	const criosUA = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/141.0.0.0 Mobile/15E148 Safari/604.1"
	const firefoxUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:141.0) Gecko/20100101 Firefox/141.0"
	for _, on := range []bool{true, false} {
		inc := render(on)
		// The reverse check reads the ciphers alone: a Chrome whose extensions
		// the family list does not know yet must not become a spoof.
		chromium := pat(inc, `map $effective_ja4 $unmask_ja4_chromium_ciphers {`)
		name := pat(inc, `map $http_user_agent $unmask_chromium_named {`)
		reverse := pat(inc, `map "$effective_ja4:$unmask_ja4_chromium_ciphers:$unmask_chromium_named" $unmask_ua_tls_reverse {`)
		decide := func(ja4, ua string) string {
			return first(reverse, ja4+":"+first(chromium, ja4)+":"+first(name, ua))
		}
		want := func(ja4, ua, exp, why string) {
			if got := decide(ja4, ua); got != exp {
				t.Errorf("reverse on=%v: %s: got %q, want %q", on, why, got, exp)
			}
		}
		if !on {
			want(goJA4, chromeUA, "0", "the check is off")
			continue
		}
		want(goJA4, chromeUA, "1", "a Chrome name over a Go fingerprint")
		want(chromeJA4, chromeUA, "0", "Chrome on Chrome's fingerprint")
		want("t13d1516h2_8daaf6152771_0c27189014cf", chromeUA, "0", "Chrome's ciphers under extensions the family list does not know")
		want(goJA4, criosUA, "0", "Chrome on iOS is WebKit")
		want(goJA4, firefoxUA, "0", "a Firefox name is the family check's business")
		want(quicJA4, chromeUA, "0", "a QUIC session is not judged")
	}
	if !strings.Contains(render(true), `"~^0:c:1:0:1$" reverse;`) {
		t.Error("the tier's map does not name the reverse contradiction")
	}
}

// TestChromiumJA4CList: every entry is a JA4_c (twelve hex digits), none
// repeats, and the family map carries them all -- the hash alone would judge
// Firefox 158, whose ciphers are Chrome's.
func TestChromiumJA4CList(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range ChromiumJA4C {
		if !regexp.MustCompile(`^[0-9a-f]{12}$`).MatchString(c) {
			t.Errorf("ChromiumJA4C entry %q is not a JA4_c", c)
		}
		if seen[c] {
			t.Errorf("ChromiumJA4C repeats %q", c)
		}
		seen[c] = true
	}
	inc := renderHTTPInc(t, nil)
	want := `"~^t13d[0-9]+h[12]_8daaf6152771_(` + strings.Join(ChromiumJA4C, "|") + `)$" 1;`
	if !strings.Contains(inc, want) {
		t.Errorf("the family map does not carry the list: want %s", want)
	}
}
