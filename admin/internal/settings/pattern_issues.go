package settings

import (
	"fmt"
	"log"
	"regexp"
	"strings"
)

// The patterns an operator writes -- the UA lists, the JA4 verdicts, the
// honeypot URLs, the protected / bypass / exempt paths, the redirect
// exemptions, the admin's host names, the rate zones' paths -- are checked
// where they are typed: the settings page refuses one that does not compile
// or that nginx's engine could take exponential time on (CheckRegex).  A
// config.yml written by hand or by a configuration manager never passes that
// page.  Such a row is rendered as written: one that does not compile fails
// `nginx -t` at the next reload, one only Go refuses is enforced by nginx
// while the daemon's own matching skips it, and nothing said so until nginx
// did.
//
// PatternIssues reads the file for the rows that break something: a pattern
// that fails CheckRegex, a line break in one, and a JA4 verdict's label that
// would end the quotes it is written between (the one value of these lists
// the renderer does not escape).  It is not the page's whole list of refusals
// -- the page also turns away a quote or a backslash in a UA pattern, which
// the renderer escapes and nginx reads correctly.  Load logs what is found
// and `unmask doctor` warns with it; nothing is rewritten or dropped.

// PatternIssue: one pattern in config.yml that the settings page would refuse.
type PatternIssue struct {
	// Key is the list the pattern sits in, as config.yml names it:
	// nginx.honeypot.urls, rate_limit.zones[login].path_patterns.
	Key   string
	Value string
	// Problem says what is wrong with it, for the end of a sentence.
	Problem string
}

// String reads as the body of a log line or of a doctor warning.
func (i PatternIssue) String() string {
	return fmt.Sprintf("%s: the pattern %q %s", i.Key, i.Value, i.Problem)
}

// PatternIssues lists the rows of the rule lists that would break the
// rendered configuration or the daemon's matching, list by list.  An empty
// row is not a pattern (the settings page skips it too).
func (s Settings) PatternIssues() []PatternIssue {
	var out []PatternIssue
	add := func(key, value, problem string) {
		out = append(out, PatternIssue{Key: key, Value: value, Problem: problem})
	}
	compiles := func(key, value, expr string) {
		if err := CheckRegex(expr); err != nil {
			add(key, value, "is refused: "+err.Error())
		}
	}

	// A User-Agent rule: a literal (contains: / exact:) means itself and is
	// escaped on the way out; a regex has to compile.
	uaRule := func(key string, rows []string) {
		for _, p := range rows {
			if p = strings.TrimSpace(p); p == "" {
				continue
			}
			if strings.ContainsAny(p, "\x00\r\n") {
				add(key, p, "holds a line break or a NUL")
				continue
			}
			if !IsLiteralPattern(p) {
				compiles(key, p, PatternRegex(p))
			}
		}
	}
	// A path rule (and a JA4 verdict's pattern): one line, and it compiles.
	lineRule := func(key, p string) {
		if p = strings.TrimSpace(p); p == "" {
			return
		}
		if strings.ContainsAny(p, "\x00\r\n") {
			add(key, p, "holds a line break or a NUL")
			return
		}
		compiles(key, p, PatternRegex(p))
	}

	n := s.Nginx
	uaRule("nginx.search_bots.extra", n.SearchBots.Extra)
	uaRule("nginx.challenge_targets.extra", n.ChallengeTargets.Extra)
	for _, e := range n.JA4Verdicts.Extra {
		lineRule("nginx.ja4_verdicts.extra", e.Pattern)
		// The verdict's label is written between quotes as it is.
		if strings.ContainsAny(e.Verdict, "\"\\\x00\r\n") {
			add("nginx.ja4_verdicts.extra", e.Pattern, fmt.Sprintf("names the verdict %q, which holds a quote, a backslash or a line break and would end the quoted value it is written into", e.Verdict))
		}
	}
	for _, u := range n.Honeypot.URLs {
		lineRule("nginx.honeypot.urls", u.Path)
	}
	for _, p := range n.ProtectedPaths.Paths {
		lineRule("nginx.protected_paths.paths", p.Path)
	}
	for _, p := range n.BypassPaths.Paths {
		lineRule("nginx.bypass_paths.paths", p.Path)
	}
	for _, p := range n.Geo.ExemptPaths {
		lineRule("nginx.geo.exempt_paths", p.Path)
	}
	for _, p := range n.Asn.ExemptPaths {
		lineRule("nginx.asn.exempt_paths", p.Path)
	}
	for _, r := range n.HTTPSRedirectExempt.Rules {
		lineRule("nginx.https_redirect_exempt.rules", r.Pattern)
	}
	// A host name of the admin's: a regex-mode entry is matched anchored and
	// case-insensitively, and one that does not compile matches nothing.
	for _, h := range n.AdminAllowedHosts {
		if h = strings.TrimSpace(h); h == "" {
			continue
		}
		if strings.ContainsAny(h, "\x00\r\n") {
			add("nginx.admin_allowed_hosts", h, "holds a line break or a NUL")
			continue
		}
		if PatternModeOf(h) == ModeRegex {
			if _, err := regexp.Compile("(?i)^(?:" + h + ")$"); err != nil {
				add("nginx.admin_allowed_hosts", h, "does not compile, so it matches no host: "+err.Error())
			}
		}
	}
	// A rate zone's path is a regex with no marker: compiled as written.
	for _, z := range s.RateLimit.Zones {
		key := "rate_limit.zones[" + z.Name + "].path_patterns"
		for _, p := range z.PathPatterns {
			if p = strings.TrimSpace(p); p == "" {
				continue
			}
			if strings.ContainsAny(p, "\x00\r\n") {
				add(key, p, "holds a line break or a NUL")
				continue
			}
			compiles(key, p, p)
		}
	}
	return out
}

// warnPatternIssues logs what PatternIssues lists, once per load of a config
// file.
func warnPatternIssues(resolved string, s Settings) {
	for _, is := range s.PatternIssues() {
		log.Printf("unmask: config %s: %s. The settings page would not have taken this row; here it is used as written, so run nginx -t before the next reload, or correct the row.", resolved, is)
	}
}
