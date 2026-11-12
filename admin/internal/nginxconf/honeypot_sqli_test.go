package nginxconf

import (
	"regexp"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// sqlInjectionGroup: the opt-in group under test, looked up by ID so the test
// follows the list however it is reordered.
func sqlInjectionGroup(t *testing.T) HoneypotGroup {
	t.Helper()
	for _, g := range HoneypotPresetGroups {
		if g.ID == "sql-injection" {
			return g
		}
	}
	t.Fatal("no sql-injection honeypot group")
	return HoneypotGroup{}
}

// sqlInjectionHit: the index of the first pattern of g that matches uri,
// compiled the way the Go wires compile them ("(?i)" + pattern; nginx renders
// the same text into a ~* map), or -1.
func sqlInjectionHit(g HoneypotGroup, uri string) int {
	for i, p := range g.Patterns {
		if regexp.MustCompile("(?i)" + p).MatchString(uri) {
			return i
		}
	}
	return -1
}

// TestSQLInjectionPatternsMatchEncodedProbes: nginx matches the group against
// $request_uri, which it does not decode -- a probe's spaces arrive as %20 or
// +, its quotes and brackets often as %27 / %28.  The patterns used to spell
// literal whitespace, so the UNION SELECT, ' OR '1'='1, WAITFOR DELAY and DROP
// TABLE probes below went through (checked on 2026-10-06 against a stock nginx
// with the rendered map).
func TestSQLInjectionPatternsMatchEncodedProbes(t *testing.T) {
	g := sqlInjectionGroup(t)
	for _, uri := range []string{
		"/item?id=1%20UNION%20SELECT%201,2,3--",
		"/item?id=1+UNION+SELECT+1,2,3--",
		"/item?id=1%20UNION%20ALL%20SELECT%20NULL,NULL--",
		"/item?id=1%20UNION/**/SELECT%201",
		"/item?id=-1%20union(select%201)",
		"/item?id=1'%20OR%20'1'='1",
		"/item?id=1%27%20OR%20%271%27%3D%271",
		"/item?id=1'+or+1=1--",
		"/item?id=1%20AND%20SLEEP(5)",
		"/item?id=1%20AND%20SLEEP%285%29",
		"/item?id=1;WAITFOR%20DELAY%20'0:0:5'--",
		"/item?id=1%20AND%201=CONCAT(0x7171,0x7170)",
		"/item?id=1%20AND%20CONCAT%280x71%2C1%29",
		"/item?q=information_schema.tables",
		"/item?q=information_schema%2Eschemata",
		"/item?id=1;%20DROP%20TABLE%20users",
		"/item?id=1%3B%20drop%20database%20shop",
		"/item?id=1%20AND%20BENCHMARK(5000000,MD5(1))",
		"/item?id=1%20INTO%20OUTFILE%20'/tmp/x'",
		"/item?id=LOAD_FILE%28'/etc/passwd'%29",
		"/item?id=1;exec%20xp_cmdshell%20'dir'",
	} {
		if sqlInjectionHit(g, uri) < 0 {
			t.Errorf("no pattern matches the probe %s", uri)
		}
	}
}

// TestSQLInjectionPatternsReadCommentsAsWhitespace: a probe pads its keywords
// with inline comments where a space would be filtered -- empty ones, MySQL's
// versioned ones, as they are or percent-encoded -- and the patterns read each
// as whitespace.  The comment's body is bounded and cannot hold the character
// its closing mark begins with (see sqlSp), which these all satisfy.
func TestSQLInjectionPatternsReadCommentsAsWhitespace(t *testing.T) {
	g := sqlInjectionGroup(t)
	for _, uri := range []string{
		"/item?id=1/**/UNION/**/SELECT/**/1",
		"/item?id=1/**/UNION/*!50000*/SELECT/**/1",
		"/item?id=1%2f%2a%2a%2fUNION%2f%2a%2a%2fSELECT%201",
		"/item?id=1%2F%2A%2A%2FUNION%2F%2A%2A%2FSELECT%201",
		"/item?id=1%20union/*%20x%20*/select%201",
		"/item?id=1'/**/OR/**/'1'='1",
		"/item?id=1%20AND%20SLEEP/**/(/**/5/**/)",
		"/item?id=1;WAITFOR/**/DELAY%20'0:0:5'--",
		"/item?id=1%20INTO/**/OUTFILE%20'/tmp/x'",
		"/item?id=1;/**/DROP/**/TABLE%20users",
	} {
		if sqlInjectionHit(g, uri) < 0 {
			t.Errorf("no pattern matches the probe %s", uri)
		}
	}
}

// TestSQLInjectionCommentHasOneExtent: sqlSp is repeated by nearly every
// pattern of the group, so what it calls a comment must be readable in one
// way only.  Written as "/*", any text, "*/", a run of "/*/" could be cut into
// comments in a number of ways that doubles with every repeat, and nginx's
// engine tried them all on a request made of such a run.  The body is now a
// bounded run of characters that cannot begin the closing mark; this pins
// the two pieces that make it so.
func TestSQLInjectionCommentHasOneExtent(t *testing.T) {
	for _, piece := range []string{`/\*[^*]{0,64}\*/`, `%2f%2a[^%]{0,64}%2a%2f`} {
		if !strings.Contains(sqlSp, piece) {
			t.Errorf("sqlSp lacks the bounded comment %s: %s", piece, sqlSp)
		}
	}
	if strings.Contains(sqlSp, ".*") || strings.Contains(sqlSp, ".+") {
		t.Errorf("sqlSp repeats any character again: %s", sqlSp)
	}
	// One extent: on a run of comment openers the first comment ends at the
	// first closing mark and nowhere later.
	re := regexp.MustCompile("^(?:" + sqlSp + ")")
	for subject, want := range map[string]string{
		"/*/*/*/*/":                           "/*/*/",
		"/**//**/":                            "/**/",
		"%2f%2a%2a%2f%2f%2a%2a%2f":            "%2f%2a%2a%2f",
		"/*" + strings.Repeat("a", 65) + "*/": "", // past the bound: not a comment
	} {
		if got := re.FindString(subject); got != want {
			t.Errorf("sqlSp at the start of %q read %q, want %q", subject, got, want)
		}
	}
}

// TestSQLInjectionPatternsLeaveOrdinaryURLs: what a site serves every day --
// searches with SQL words in plain language, slugs, sort parameters -- matches
// nothing.  A search for the SQL itself ("?q=union+select") does match: such a
// site turns the group off in disabled_presets.
func TestSQLInjectionPatternsLeaveOrdinaryURLs(t *testing.T) {
	g := sqlInjectionGroup(t)
	for _, uri := range []string{
		"/search?q=order+by+date",
		"/search?q=european+union",
		"/search?q=select+a+plan",
		"/news/union-selects-new-leader",
		"/products?sort=price&order=desc&select=all",
		"/search?q=sleep+tips",
		"/search?q=sleep(8+hours)",
		"/search?q=don%27t+drop+the+ball",
		"/search?q=o%27reilly+or+manning",
		"/docs/information-schema-overview",
		"/blog/2026/10/concat-strings-in-go",
		"/api/delay?waitfor=5",
	} {
		if i := sqlInjectionHit(g, uri); i >= 0 {
			t.Errorf("pattern %d (%s) matches the ordinary URL %s", i, g.Patterns[i], uri)
		}
	}
}

// TestSQLInjectionGroupOnByDefault: since v0.1.50 an encoded probe trips the
// group through ResolveHoneypotAction with nothing configured -- but not once
// the operator has switched it off, and not on an install that reviews new
// enforcement until it has reviewed v0.1.50.
func TestSQLInjectionGroupOnByDefault(t *testing.T) {
	uri := "/item?id=1%20UNION%20SELECT%201,2,3--"
	var n settings.Nginx
	n.SeenVersion = "v0.1" // baseline, as in TestResolveHoneypotAction
	n.Honeypot.PresetAction = map[string]string{"sql-injection": "captcha_only"}
	if act, matched := ResolveHoneypotAction(uri, "", n); !matched || act != "captcha_only" {
		t.Fatalf("default: got (%q, %v), want (captcha_only, true)", act, matched)
	}

	off := n
	off.Honeypot.DisabledPresets = []string{"sql-injection"}
	if _, matched := ResolveHoneypotAction(uri, "", off); matched {
		t.Fatal("the group matched although disabled_presets names it")
	}

	held := n
	held.UpgradeReviewPolicy = settings.UpgradeReviewReview
	held.EnforcementReviewedVersion = "v0.1.49"
	if _, matched := ResolveHoneypotAction(uri, "", held); matched {
		t.Fatal("the group matched on a review install that has not reviewed v0.1.50")
	}
	held.EnforcementReviewedVersion = "v0.1.50"
	if _, matched := ResolveHoneypotAction(uri, "", held); !matched {
		t.Fatal("the group is still held after v0.1.50 was reviewed")
	}

	// It shipped opt-in in v0.1.0: an install that turned it on then gave its
	// go-ahead, and keeps it through the upgrade without a review.
	consented := n
	consented.UpgradeReviewPolicy = settings.UpgradeReviewReview
	consented.EnforcementReviewedVersion = "v0.1.49"
	consented.Honeypot.EnabledPresets = []string{"sql-injection"}
	if _, matched := ResolveHoneypotAction(uri, "", consented); !matched {
		t.Fatal("the group is held on an install that had turned it on while it was opt-in")
	}
	g := sqlInjectionGroup(t)
	if g.AddedIn != "v0.1.0" || g.UpdatedIn != "v0.1.50" || g.DefaultOnIn != "v0.1.50" {
		t.Errorf("versions: added %q, updated %q, on by default %q; want v0.1.0, v0.1.50, v0.1.50", g.AddedIn, g.UpdatedIn, g.DefaultOnIn)
	}
	// The review banner names the release whose change is held.
	var heldSet settings.Settings
	heldSet.Nginx = held
	heldSet.Nginx.EnforcementReviewedVersion = "v0.1.49"
	var found bool
	for _, hp := range HeldEnforcementPresets(heldSet) {
		if hp.Category == "honeypot" && hp.ID == "sql-injection" {
			found = true
			if hp.AddedIn != "v0.1.50" {
				t.Errorf("held as of %q, want v0.1.50", hp.AddedIn)
			}
		}
	}
	if !found {
		t.Error("the review banner does not list the held group")
	}
}
