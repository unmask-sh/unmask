package main

import (
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// A pattern stored with its marker twice matches nothing it was written for,
// and reads correctly at a glance; a title column of another length than its
// list puts titles on other rows.  doctor names both, with where they are and
// what puts them right (a large install, 2026-10-06: doubled UA rows that
// rescued and challenged nothing, and five titles for four rows).
func TestCheckPatternLists(t *testing.T) {
	run := func(s settings.Settings) (ok, warn []string) {
		checkPatternLists(s,
			func(title, msg string) { ok = append(ok, title+": "+msg) },
			func(title, msg string) { warn = append(warn, title+": "+msg) })
		return
	}

	var clean settings.Settings
	clean.Nginx.SearchBots.Extra = []string{"contains:Piano ESP", "exact:SomeBot"}
	clean.Nginx.SearchBots.ExtraTitle = []string{"a", "b"}
	clean.Nginx.ChallengeTargets.Extra = []string{"contains:Bytespider", "^Mozilla/4"}
	clean.Nginx.ChallengeTargets.ExtraAction = []string{"captcha_only"} // stops short: the rest inherit
	clean.Nginx.BypassIPs = []string{"192.0.2.1"}                       // no titles at all
	if ok, warn := run(clean); len(warn) != 0 || len(ok) != 1 {
		t.Errorf("a clean configuration: ok %q, warnings %q", ok, warn)
	}

	bad := clean
	bad.Nginx.SearchBots.Extra = []string{"contains:contains:Piano ESP", "exact:exact:SomeBot", "contains:AgentScanner", "subdomain:example.com"}
	bad.Nginx.SearchBots.ExtraTitle = []string{"a", "b", "c", "d", "e"}
	bad.Nginx.ChallengeTargets.ExtraAction = []string{"", "", "deny"}
	bad.Nginx.BypassPaths.Paths = []settings.BypassPath{{Path: "exact:exact:/feed"}}
	_, warn := run(bad)
	joined := strings.Join(warn, "\n")
	for _, want := range []string{
		`3 pattern(s) carry their marker twice`,
		`nginx.search_bots.extra "contains:contains:Piano ESP"`,
		`nginx.search_bots.extra "exact:exact:SomeBot"`,
		`nginx.bypass_paths.paths "exact:exact:/feed"`,
		"Save the settings tab that lists them once",
		"nginx.search_bots.extra has 4 row(s) and 5 extra_title",
		"nginx.challenge_targets.extra has 2 row(s) and 3 extra_action",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("the warnings lack %q:\n%s", want, joined)
		}
	}
	if strings.Contains(joined, "AgentScanner") || strings.Contains(joined, "subdomain:example.com") {
		t.Errorf("a pattern with one marker is reported:\n%s", joined)
	}
	if strings.Contains(joined, "bypass_ips") {
		t.Errorf("a list with no titles at all is reported:\n%s", joined)
	}

	// Titles that stop short are as wrong as titles that run long: the
	// next one appended belongs to a row further down.
	short := clean
	short.Nginx.ChallengeTargets.ExtraTitle = []string{"only the first"}
	if _, warn := run(short); len(warn) != 1 || !strings.Contains(warn[0], "nginx.challenge_targets.extra has 2 row(s) and 1 extra_title") {
		t.Errorf("titles short of the rows: %q", warn)
	}
}
