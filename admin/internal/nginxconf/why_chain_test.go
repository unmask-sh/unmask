package nginxconf

import (
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// mapRow is one row of an nginx map block as rendered: the pattern (or
// "default") and the value, without the comment.
type mapRow struct{ pattern, value string }

// renderedMap returns the source expression and the rows of the map in conf
// whose opening line ends in " <variable> {".
func renderedMap(t *testing.T, conf, variable string) (source string, rows []mapRow) {
	t.Helper()
	lines := strings.Split(conf, "\n")
	for i, ln := range lines {
		if !strings.HasPrefix(ln, "map ") || !strings.HasSuffix(ln, " "+variable+" {") {
			continue
		}
		source = strings.TrimSuffix(strings.TrimPrefix(ln, "map "), " "+variable+" {")
		for _, row := range lines[i+1:] {
			row = strings.TrimSpace(row)
			if row == "}" {
				return source, rows
			}
			if row == "" || strings.HasPrefix(row, "#") || row == "volatile;" {
				continue
			}
			semi := strings.Index(row, ";")
			if semi < 0 {
				t.Fatalf("map %s: a row without a ';': %q", variable, row)
			}
			f := strings.Fields(row[:semi])
			if len(f) != 2 {
				t.Fatalf("map %s: a row that is not a pattern and a value: %q", variable, row)
			}
			rows = append(rows, mapRow{f[0], f[1]})
		}
		t.Fatalf("map %s is not closed", variable)
	}
	t.Fatalf("no map defines %s", variable)
	return "", nil
}

// TestWhyChainMirrorsTheChain: $unmask_why_chain names the reason for every
// row of the $final_challenge chain that lets a request through, and the
// admin lists who got through under each reason.  The two maps are written
// out separately, so a row added to the chain has to be added to the other:
// one that answers 0 and has no twin would let requests through that the
// list files under "none" -- or, with a reason copied from a neighbour,
// under the wrong one.  The key, the patterns and their order are held equal
// here, and each value to the kind its twin calls for.
func TestWhyChainMirrorsTheChain(t *testing.T) {
	for name, mutate := range map[string]func(*settings.Settings){
		"plain": func(s *settings.Settings) {
			s.Global.StaleBrowserChallenge = false
			s.Global.HeaderIntegrity = false
		},
		"with the later tiers": func(s *settings.Settings) {
			s.Global.StaleBrowserChallenge = true
			s.Global.HeaderIntegrity = true
		},
	} {
		inc := renderHTTPInc(t, mutate)
		chainVar := "$final_challenge"
		if strings.Contains(inc, " $final_challenge_base {") {
			chainVar = "$final_challenge_base"
		}
		chainSrc, chain := renderedMap(t, inc, chainVar)
		whySrc, why := renderedMap(t, inc, "$unmask_why_chain")
		if chainSrc != whySrc {
			t.Errorf("%s: the two maps read different keys:\n  chain %s\n  why   %s", name, chainSrc, whySrc)
		}
		if len(chain) != len(why) {
			t.Fatalf("%s: the chain has %d rows, $unmask_why_chain has %d", name, len(chain), len(why))
		}
		if len(chain) < 15 {
			t.Fatalf("%s: only %d rows read out of the chain; the render is not the one this test was written for", name, len(chain))
		}
		for i := range chain {
			c, w := chain[i], why[i]
			if c.pattern != w.pattern {
				t.Errorf("%s: row %d: the chain matches %s, $unmask_why_chain matches %s", name, i+1, c.pattern, w.pattern)
				continue
			}
			switch {
			case c.pattern == "default":
				if c.value != "0" || w.value != "none" {
					t.Errorf("%s: default: the chain says %s and the reason is %s; a request no row matches passes (0) and has to read \"none\"", name, c.value, w.value)
				}
			case c.value == "1":
				if w.value != `""` {
					t.Errorf("%s: %s is a challenge in the chain and has the reason %s", name, c.pattern, w.value)
				}
			case c.value == "0":
				switch w.value {
				case "cookie", "ip", "path", "name":
				default:
					t.Errorf("%s: %s lets the request through and names no reason the admin knows (%s)", name, c.pattern, w.value)
				}
			case c.value == "$unmatched_should_challenge":
				if w.value != "$unmask_why_global" {
					t.Errorf("%s: %s is the Global axis's call and its reason is %s, not $unmask_why_global", name, c.pattern, w.value)
				}
			default:
				t.Errorf("%s: %s answers %s in the chain: a value this test has no rule for", name, c.pattern, c.value)
			}
		}
		src, global := renderedMap(t, inc, "$unmask_why_global")
		if src != "$unmatched_should_challenge" || len(global) != 2 ||
			global[0] != (mapRow{"default", `""`}) || global[1] != (mapRow{"0", "global"}) {
			t.Errorf("%s: $unmask_why_global is not \"global\" exactly where the Global axis says pass: source %s, rows %v", name, src, global)
		}
	}
}

// TestWhyLogNamesWhatAnswered: the access log's why= is composed where the
// line is written -- unmask's own answers read "", and the rows after them
// name the gates' ways through.  The variables a row reads exist only in the
// renders that set them (monitor mode, the signed-agent detours).
func TestWhyLogNamesWhatAnswered(t *testing.T) {
	type c struct {
		mutate func(*settings.Settings)
		passed string
		judged string
	}
	for name, tc := range map[string]c{
		"plain": {func(*settings.Settings) {}, "$unmask_why_chain", "none"},
		"monitor mode": {func(s *settings.Settings) {
			s.Challenge.Default.ObserveOnly = settings.BoolPtr(true)
		}, "$unmask_why_chain", "$unmask_why_judged"},
		"web bot auth": {func(s *settings.Settings) {
			s.Nginx.AdvancedEnabled = true
			s.Nginx.WebBotAuth.Enabled = true
		}, "$unmask_why_passed", "none"},
	} {
		inc := renderHTTPInc(t, tc.mutate)
		src, rows := renderedMap(t, inc, "$unmask_why_log")
		if src != `"$unmask_bounced$unmask_own_uri:$unmask_gated:$unmask_fc_log"` {
			t.Errorf("%s: $unmask_why_log reads %s", name, src)
		}
		want := []mapRow{
			{"default", "none"},
			{`"~^[hu]"`, `""`},
			{`"~^::"`, "$unmask_why_nogate"},
			{`"~^:1:1:"`, "down"},
			{`":1::0"`, tc.passed},
			{`":1::1"`, tc.judged},
		}
		if len(rows) != len(want) {
			t.Fatalf("%s: $unmask_why_log has %d rows, want %d: %v", name, len(rows), len(want), rows)
		}
		for i := range want {
			if rows[i] != want[i] {
				t.Errorf("%s: row %d is %v, want %v", name, i+1, rows[i], want[i])
			}
		}
		// Without a gate the one thing the line can still say is whether
		// the client carries a valid pass.
		if src, nogate := renderedMap(t, inc, "$unmask_why_nogate"); src != "$bv_any_valid" || len(nogate) != 2 ||
			nogate[0] != (mapRow{"default", "nogate"}) || nogate[1] != (mapRow{"1", "cookie"}) {
			t.Errorf("%s: $unmask_why_nogate is not \"cookie\" for a valid pass and \"nogate\" otherwise: source %s, rows %v", name, src, nogate)
		}
		for _, v := range []string{tc.passed, tc.judged} {
			if strings.HasPrefix(v, "$") && !strings.Contains(inc, " "+v+" {") {
				t.Errorf("%s: $unmask_why_log reads %s, which this render does not define", name, v)
			}
		}
		if !strings.Contains(inc, " why=$unmask_why_log lp=$unmask_lp_log ua=$http_user_agent'") {
			t.Errorf("%s: the log format does not end in why=, lp= and the User-Agent", name)
		}
	}
	// server.inc marks the redirect to HTTPS as its own answer.
	server := renderServerInc(t, func(s *settings.Settings) {})
	if strings.Contains(server, "return 301 https://$host$request_uri;") &&
		!strings.Contains(server, "set $unmask_bounced \"h\";\n    return 301 https://$host$request_uri;") {
		t.Error("server.inc answers with the redirect to HTTPS without setting $unmask_bounced first")
	}
}
