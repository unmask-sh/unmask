package nginxconf

import (
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
