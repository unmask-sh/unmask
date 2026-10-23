package nginxconf

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// readNginxQuoted reads a double-quoted token the way nginx's config reader
// does (ngx_conf_read_token): the token ends at the first quote that is not
// escaped, `\"` `\'` `\\` become the character, `\t` `\r` `\n` the control
// character, and any other pair is kept as written.  What it returns is
// what PCRE is handed.
func readNginxQuoted(s string) (string, bool) {
	if !strings.HasPrefix(s, `"`) {
		return "", false
	}
	var b strings.Builder
	for i := 1; i < len(s); i++ {
		c := s[i]
		if c == '\\' && i+1 < len(s) {
			switch s[i+1] {
			case '"', '\'', '\\':
				b.WriteByte(s[i+1])
				i++
				continue
			case 't':
				b.WriteByte('\t')
				i++
				continue
			case 'r':
				b.WriteByte('\r')
				i++
				continue
			case 'n':
				b.WriteByte('\n')
				i++
				continue
			}
			b.WriteByte(c)
			continue
		}
		if c == '"' {
			return b.String(), true
		}
		b.WriteByte(c)
	}
	return "", false
}

// regexKeysOf returns, for the map block that starts with head, the regex
// each quoted key hands PCRE (the `~`, `~*` or `~^` operator removed).
func regexKeysOf(t *testing.T, conf, head string) []string {
	t.Helper()
	i := strings.Index(conf, head)
	if i < 0 {
		t.Fatalf("no %q in the rendered config", head)
	}
	block := conf[i+len(head):]
	if j := strings.Index(block, "\n}"); j >= 0 {
		block = block[:j]
	}
	var out []string
	for _, line := range strings.Split(block, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, `"~`) {
			continue
		}
		key, ok := readNginxQuoted(line)
		if !ok {
			t.Errorf("%s: the key is never closed: %s", head, line)
			continue
		}
		key = strings.TrimPrefix(key, "~")
		key = strings.TrimPrefix(key, "*")
		key = strings.TrimPrefix(key, "^")
		out = append(out, key)
	}
	return out
}

// A pattern with a quote, a backslash or an escaped dot -- a regex, which
// the path, honeypot and redirect-exemption forms accept with all three,
// or a literal, which is escaped as a regex first -- is written inside the
// double-quoted map key with nginx's escaping (nginxQuote, through the rx
// template func), so the key is closed where the template closes it and
// nginx's reader hands PCRE the expression the operator meant.  A regex
// used to be written as typed: `x"y; include /etc/evil.conf; #` ended the
// key at its quote and the rest of the pattern was read as directives, in
// a file nginx loads as root.
func TestPatternsRenderQuotedInEveryList(t *testing.T) {
	const injection = `x"y; include /etc/evil.conf; #`
	const escaped = `/search\?q=\\d+`
	text := `q"uote\back.slash`
	literal := settings.MakePatternWithMode(text, settings.ModeContains)
	patterns := []string{injection, escaped, literal}
	// What PCRE must see for each: a regex as typed, a literal escaped.
	want := []string{injection, escaped, regexp.QuoteMeta(text)}

	var s settings.Settings
	s.Nginx.HTTPSRedirect = true
	for _, p := range patterns {
		s.Nginx.ChallengeTargets.Extra = append(s.Nginx.ChallengeTargets.Extra, p)
		s.Nginx.ProtectedPaths.Paths = append(s.Nginx.ProtectedPaths.Paths, settings.ProtectedPath{Path: p, Mode: "pow"})
		s.Nginx.BypassPaths.Paths = append(s.Nginx.BypassPaths.Paths, settings.BypassPath{Path: p})
		s.Nginx.Honeypot.URLs = append(s.Nginx.Honeypot.URLs, settings.HoneypotURL{Path: p, Action: "deny"})
		s.Nginx.Geo.ExemptPaths = append(s.Nginx.Geo.ExemptPaths, settings.BypassPath{Path: p})
		s.Nginx.HTTPSRedirectExempt.Rules = append(s.Nginx.HTTPSRedirectExempt.Rules, settings.HTTPSRedirectExemptRule{Type: "path", Pattern: p})
	}
	dir := t.TempDir()
	if err := Render(s, dir, "test"); err != nil {
		t.Fatal(err)
	}
	httpInc, err := os.ReadFile(dir + "/http.inc")
	if err != nil {
		t.Fatal(err)
	}
	serverInc, err := os.ReadFile(dir + "/server.inc")
	if err != nil {
		t.Fatal(err)
	}
	conf := string(httpInc)

	for _, head := range []string{
		"map $http_user_agent $is_challenge_target {",
		"map $uri $unmask_pp_global {",
		"map $uri $unmask_bp_global {",
		"map $request_uri $unmask_hp_global {",
		"map $uri $unmask_gx_global {",
	} {
		got := regexKeysOf(t, conf, head)
		for _, w := range want {
			found := false
			for _, g := range got {
				if g == w {
					found = true
				}
			}
			if !found {
				t.Errorf("%s: PCRE is not handed %q; the keys read: %q", head, w, got)
			}
		}
	}

	// server.inc: the redirect exemptions are `if` conditions, quoted alike.
	var got []string
	for _, line := range strings.Split(string(serverInc), "\n") {
		line = strings.TrimSpace(line)
		const lead = `if ($request_uri ~ `
		if !strings.HasPrefix(line, lead) {
			continue
		}
		key, ok := readNginxQuoted(strings.TrimPrefix(line, lead))
		if !ok {
			t.Errorf("server.inc: the condition is never closed: %s", line)
			continue
		}
		got = append(got, key)
	}
	for _, w := range want {
		found := false
		for _, g := range got {
			if g == w {
				found = true
			}
		}
		if !found {
			t.Errorf("server.inc: PCRE is not handed %q; the conditions read: %q", w, got)
		}
	}

	// The injection never reaches a line of its own: wherever its text is,
	// the line is a quoted key or condition.
	for _, conf := range []string{conf, string(serverInc)} {
		for _, line := range strings.Split(conf, "\n") {
			if !strings.Contains(line, "evil.conf") {
				continue
			}
			l := strings.TrimSpace(line)
			if !strings.HasPrefix(l, `"~`) && !strings.HasPrefix(l, `if (`) {
				t.Errorf("the pattern became a directive line: %s", line)
			}
		}
	}
}
