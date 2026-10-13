package nginxconf

import (
	"regexp"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestGatedLogRender: the access log's fc= and bp= come from $unmask_gated,
// so a location without protect.inc -- which serves its content whatever the
// judgement says -- is not counted as challenged.  The flag has to be set by
// every gate: protect.inc, ahead of each rewrite in it (a `rewrite ... last`
// ends the phase, so a flag set after one would never be set for the requests
// it sends to the challenge), and server.inc's ban and deny rewrites, which
// answer before any location.  Both rate modes, since compose drops the
// classic rewrite.
func TestGatedLogRender(t *testing.T) {
	for _, mode := range []string{"never", "always"} {
		httpInc, serverInc, protectInc := renderIncs(t, func(s *settings.Settings) {
			s.Nginx.RateComposeMode = mode
			s.Nginx.Geo.Rules = []settings.GeoRule{{Country: "CN", Action: settings.RateChallengeDeny, Enabled: true}}
		})
		for _, want := range []string{
			"map $remote_addr $unmask_gated {\n    default \"\";\n}",
			"map $unmask_gated $unmask_fc_log {\n    default 0;\n    \"1:\"    $final_challenge;\n}",
			"map $unmask_gated $unmask_bp_log {\n    default 1;\n    \"1:\"    $unmask_bypassed;\n}",
			" fc=$unmask_fc_log ",
			" bp=$unmask_bp_log ",
		} {
			if !strings.Contains(httpInc, want) {
				t.Errorf("%s: http.inc lacks %q", mode, want)
			}
		}
		if strings.Contains(httpInc, "fc=$final_challenge") || strings.Contains(httpInc, "bp=$unmask_bypassed") {
			t.Errorf("%s: the log still carries the judgement itself", mode)
		}

		set := strings.Index(protectInc, `set $unmask_gated "1:${unmask_failopen}";`)
		if set < 0 {
			t.Fatalf("%s: protect.inc does not set $unmask_gated", mode)
		}
		if i := strings.Index(protectInc, "\nrewrite "); i >= 0 && i < set {
			t.Errorf("%s: a rewrite in protect.inc comes before $unmask_gated is set", mode)
		}
		if i := strings.Index(protectInc, "    rewrite "); i >= 0 && i < set {
			t.Errorf("%s: a rewrite in protect.inc comes before $unmask_gated is set", mode)
		}

		for _, to := range []string{`/unmask/_ban\$request_uri`, `/unmask/challenge/`, `/unmask/_deny\$request_uri`} {
			re := regexp.MustCompile(`set \$unmask_gated "1:";\n    rewrite \^ ` + to + ` last;`)
			if !re.MatchString(serverInc) {
				t.Errorf("%s: server.inc's rewrite to %s does not set $unmask_gated first", mode, to)
			}
		}
	}
}

// TestGatedLogRenderVetoPass: with a veto-pass feature on, a verified signed
// agent or token holder is let through by protect.inc, so fc= logs the
// decision protect.inc enforces ($final_challenge_eff), not the judgement
// before the veto.
func TestGatedLogRenderVetoPass(t *testing.T) {
	httpInc, _, _ := renderIncs(t, func(s *settings.Settings) {
		s.Nginx.AdvancedEnabled = true // master gate: WebBotAuthActive() needs both
		s.Nginx.WebBotAuth.Enabled = true
	})
	if !strings.Contains(httpInc, "\"1:\"    $final_challenge_eff;") {
		t.Error("with Web Bot Auth on, fc= does not log the decision protect.inc enforces")
	}
}
