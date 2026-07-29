package nginxconf

import (
	"regexp"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestHeaderIntegrityRenderOff: with the axis off, none of its maps are
// emitted and $final_challenge is produced directly by the base map (zero
// rendered-config diff on upgrade).
func TestHeaderIntegrityRenderOff(t *testing.T) {
	off := renderHTTPInc(t, nil)
	for _, absent := range []string{"$unmask_header_mismatch", "$unmask_ua_chromium", "$fc_after_stale"} {
		if strings.Contains(off, absent) {
			t.Errorf("axis off: %q must not render", absent)
		}
	}
}

// TestHeaderIntegrityRenderOn: enabling the axis wires the chromium / modern /
// mismatch maps and folds a would-pass mismatch into $final_challenge, keyed
// after every exemption.
func TestHeaderIntegrityRenderOn(t *testing.T) {
	on := renderHTTPInc(t, func(s *settings.Settings) {
		s.Global.HeaderIntegrity = true
	})
	for _, want := range []string{
		`map $http_user_agent $unmask_ua_chromium {`,
		`map $server_protocol $unmask_http_modern {`,
		`map "$unmask_ua_chromium:$scheme:$unmask_http_modern:$http_sec_ch_ua" $unmask_header_mismatch {`,
		`"~^1:https:1:$" 1;`, // chromium + https + h2/h3 + empty Sec-CH-UA
		// The escalation consumes the base decision (no stale tier here) and
		// only bumps a would-pass, non-exempt mismatch.
		`:$unmask_header_mismatch:$is_search_bot:$is_bypass_ip:$is_bypass_path:$bv_any_valid" $final_challenge {`,
		`"~^0:1:0:0:0:0$" 1;`,
	} {
		if !strings.Contains(on, want) {
			t.Errorf("axis on: missing %q", want)
		}
	}
	// Without the stale tier the header escalation reads the base directly.
	if !strings.Contains(on, `map "$final_challenge_base:$unmask_header_mismatch`) {
		t.Error("header tier should read $final_challenge_base when stale is off")
	}
	// The chromium map must carry the Sec-CH-UA version floor (Chromium 89), not
	// a bare Chrome/[0-9]: below 89 the header is legitimately absent, and since
	// that is permanent, firing there re-challenged genuine old browsers forever.
	// Keep in step with classify.SecCHUAMinChromeMajor + headerDecide.
	if strings.Contains(on, `"~(?i)Chrome/[0-9]" 1;`) {
		t.Error("chromium map still matches every Chrome major (pre-89 false positive)")
	}
	if !strings.Contains(on, `Chrome/(?:89|9[0-9]|[1-9][0-9][0-9]+)`) {
		t.Error("chromium map missing the Chromium-89 Sec-CH-UA floor")
	}
}

// TestChromiumMapVersionFloorSemantics pins the rendered regex's MEANING (not
// just its text) against the Go axis: every major the nginx map matches must be
// exactly the set headerDecide has an opinion on (>= 89).  The two run in
// different engines (PCRE vs Go regexp) on the two deploy modes, so a drift here
// means native and forward-auth disagree about the same visitor.
func TestChromiumMapVersionFloorSemantics(t *testing.T) {
	on := renderHTTPInc(t, func(s *settings.Settings) {
		s.Global.HeaderIntegrity = true
	})
	// Lift the pattern out of the rendered map so the test reads what shipped.
	m := regexp.MustCompile(`"~\(\?i\)(Chrome/\(\?:[^"]+)" 1;`).FindStringSubmatch(on)
	if m == nil {
		t.Fatal("could not find the chromium map pattern in the rendered http.inc")
	}
	// Go's regexp has no (?: ... ) difference here; (?i) is applied via the flag.
	re := regexp.MustCompile(`(?i)` + m[1])
	for _, c := range []struct {
		ua   string
		want bool
	}{
		// An aging Android WebView: pre-89 Chromium, so no Sec-CH-UA to miss.
		{"Mozilla/5.0 (Linux; Android 5.1.1; wv) AppleWebKit/537.36 Chrome/55.0.2883.91 Mobile Safari/537.36", false},
		{"Mozilla/5.0 Chrome/88.0.4324.150 Safari/537.36", false},
		{"Mozilla/5.0 Chrome/8.0.552.224 Safari/534.10", false},
		{"Mozilla/5.0 Chrome/9.1.0.0 Safari/537.36", false},
		{"Mozilla/5.0 Chrome/89.0.4389.90 Safari/537.36", true},
		{"Mozilla/5.0 Chrome/99.0.4844.51 Safari/537.36", true},
		{"Mozilla/5.0 Chrome/125.0.6422.60 Safari/537.36", true},
		{"Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0", false},
	} {
		if got := re.MatchString(c.ua); got != c.want {
			t.Errorf("nginx map match=%v, want %v for %q", got, c.want, c.ua)
		}
	}
}

// TestHeaderIntegrityRenderLBFronted: with a trusted LB configured, the axis
// keys off the LB-forwarded scheme ($unmask_forwarded_proto) and a modern-context
// map, never the raw $scheme / $server_protocol -- which behind a TLS-terminating
// LB describe the backend hop (http/1.1) and would leave the h2/h3 precondition
// permanently unsatisfiable, so the axis would never fire.
func TestHeaderIntegrityRenderLBFronted(t *testing.T) {
	on := renderHTTPInc(t, func(s *settings.Settings) {
		s.Global.HeaderIntegrity = true
		s.Nginx.TrustedLBPresets = []string{"gcp"}
	})
	for _, want := range []string{
		`map $http_x_forwarded_proto $unmask_via_lb {`,
		`map "$unmask_http_modern$unmask_via_lb" $unmask_modern_ctx {`,
		`map "$unmask_ua_chromium:$unmask_forwarded_proto:$unmask_modern_ctx:$http_sec_ch_ua" $unmask_header_mismatch {`,
		`"~^1:https:1:$" 1;`,
	} {
		if !strings.Contains(on, want) {
			t.Errorf("LB-fronted: missing %q", want)
		}
	}
	// The direct-mode key (raw $scheme + $server_protocol) must NOT appear --
	// it is exactly what breaks behind the LB.
	if strings.Contains(on, `map "$unmask_ua_chromium:$scheme:$unmask_http_modern:$http_sec_ch_ua"`) {
		t.Error("LB-fronted must not emit the raw $scheme mismatch map")
	}
}

// TestHeaderIntegrityChainsWithStale: with BOTH tiers on, stale emits into the
// intermediate $fc_after_stale and the header tier consumes it, so exactly one
// producer of $final_challenge exists and the chain is base -> stale -> header.
func TestHeaderIntegrityChainsWithStale(t *testing.T) {
	on := renderHTTPInc(t, func(s *settings.Settings) {
		s.Global.HeaderIntegrity = true
		s.Global.StaleBrowserChallenge = true
		s.Global.CurrentChromeMajor = 150
		s.Global.StaleBrowserLag = 11
	})
	if !strings.Contains(on, `$fc_after_stale {`) {
		t.Error("stale tier must emit into $fc_after_stale when the header tier follows")
	}
	if !strings.Contains(on, `map "$fc_after_stale:$unmask_header_mismatch`) {
		t.Error("header tier must consume $fc_after_stale")
	}
	// Exactly one map produces $final_challenge (the header tier, last in chain).
	if n := strings.Count(on, `$final_challenge {`); n != 1 {
		t.Errorf("want exactly 1 producer of $final_challenge, got %d", n)
	}
}
