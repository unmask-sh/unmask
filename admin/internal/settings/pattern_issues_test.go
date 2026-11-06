package settings

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// PatternIssues reads the rule lists for the rows that break something, list
// by list.  A row the renderer and nginx handle -- a literal with a quote in
// it, a regex with a backslash -- is left alone, the page's refusal of those
// notwithstanding.
func TestPatternIssues(t *testing.T) {
	var s Settings
	n := &s.Nginx
	n.SearchBots.Extra = []string{
		"contains:Good\"Bot", // a literal: escaped on the way out, fine
		`Good\d+Bot`,         // a regex with a backslash: fine
		"Bad(Bot",            // does not compile
		"",                   // an empty row is not a pattern
	}
	n.ChallengeTargets.Extra = []string{"(a+)+$"} // exponential in nginx's engine
	n.JA4Verdicts.Extra = []JA4VerdictExtraRule{
		{Pattern: "t13d1516h2_", Verdict: "chrome"},
		{Pattern: "t13d[", Verdict: "broken"},
		{Pattern: "t12d", Verdict: `say "hi"`},
	}
	n.Honeypot.URLs = []HoneypotURL{{Path: "^/trap$"}, {Path: "^/trap(("}}
	n.ProtectedPaths.Paths = []ProtectedPath{{Path: "^/login"}, {Path: "/a\nb"}}
	n.BypassPaths.Paths = []BypassPath{{Path: "exact:/healthz"}, {Path: "^/x[0-"}}
	n.Geo.ExemptPaths = []BypassPath{{Path: "^/feed(?P<bad"}}
	n.Asn.ExemptPaths = []BypassPath{{Path: "^/feed/"}}
	n.HTTPSRedirectExempt.Rules = []HTTPSRedirectExemptRule{{Pattern: "^/.well-known/"}, {Pattern: "*oops"}}
	n.AdminAllowedHosts = []string{"exact:admin.example", "admin[.example"}
	s.RateLimit.Zones = []RateZone{
		{Name: "login", PathPatterns: []string{"^/login$", "^/login(", ""}},
	}

	got := s.PatternIssues()
	want := []struct{ key, value, problem string }{
		{"nginx.search_bots.extra", "Bad(Bot", "is refused"},
		{"nginx.challenge_targets.extra", "(a+)+$", "nested repetition"},
		{"nginx.ja4_verdicts.extra", "t13d[", "is refused"},
		{"nginx.ja4_verdicts.extra", "t12d", `names the verdict "say \"hi\""`},
		{"nginx.honeypot.urls", "^/trap((", "is refused"},
		{"nginx.protected_paths.paths", "/a\nb", "line break"},
		{"nginx.bypass_paths.paths", "^/x[0-", "is refused"},
		{"nginx.geo.exempt_paths", "^/feed(?P<bad", "is refused"},
		{"nginx.https_redirect_exempt.rules", "*oops", "is refused"},
		{"nginx.admin_allowed_hosts", "admin[.example", "matches no host"},
		{"rate_limit.zones[login].path_patterns", "^/login(", "is refused"},
	}
	if len(got) != len(want) {
		t.Fatalf("%d issue(s), want %d:\n%s", len(got), len(want), issueLines(got))
	}
	for i, w := range want {
		if got[i].Key != w.key || got[i].Value != w.value || !strings.Contains(got[i].Problem, w.problem) {
			t.Errorf("issue %d = %s\nwant key %q, value %q, problem with %q", i, got[i], w.key, w.value, w.problem)
		}
	}
	// The sentence names the list and the pattern, for a log line.
	if msg := got[0].String(); !strings.HasPrefix(msg, `nginx.search_bots.extra: the pattern "Bad(Bot" is refused`) {
		t.Errorf("message: %s", msg)
	}
}

func issueLines(is []PatternIssue) string {
	var b strings.Builder
	for _, i := range is {
		b.WriteString("  " + i.String() + "\n")
	}
	return b.String()
}

// The shipped defaults, and a file the settings page wrote, have nothing to
// report: the check must not cry over what the product itself puts there.
func TestPatternIssuesQuietOnDefaults(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "config.yml")
	body := "secret:\n  bv_secret: 0123456789abcdef0123456789abcdef\n  admin_secret: fedcba9876543210fedcba9876543210\n"
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := Load(cfg)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := s.PatternIssues(); len(got) != 0 {
		t.Fatalf("a default configuration reports:\n%s", issueLines(got))
	}
}

// Load says it once per row when it reads the file, and loads the file all
// the same with the row as written: the row is the operator's to correct.
func TestLoadWarnsPatternIssues(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "config.yml")
	body := "secret:\n  bv_secret: 0123456789abcdef0123456789abcdef\n  admin_secret: fedcba9876543210fedcba9876543210\n" +
		"nginx:\n  honeypot:\n    urls:\n      - path: \"^/trap((\"\n      - path: \"^/fine$\"\n"
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	old := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(old)
	s, err := Load(cfg)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	out := buf.String()
	for _, want := range []string{`nginx.honeypot.urls: the pattern "^/trap((" is refused`, "nginx -t"} {
		if !strings.Contains(out, want) {
			t.Errorf("the load log must carry %q, got:\n%s", want, out)
		}
	}
	if strings.Contains(out, "^/fine$") {
		t.Errorf("a row that compiles is not mentioned:\n%s", out)
	}
	if len(s.Nginx.Honeypot.URLs) != 2 || s.Nginx.Honeypot.URLs[0].Path != "^/trap((" {
		t.Errorf("the row is kept as written, not dropped or rewritten: %+v", s.Nginx.Honeypot.URLs)
	}
}
