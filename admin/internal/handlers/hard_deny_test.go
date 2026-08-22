package handlers

import (
	"os"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/nginxconf"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// "deny" has to deny.  It did not: every axis except the ban was consulted only
// when $bv_any_valid was 0, so the word meant "deny unless this client has
// cleared a challenge at some point in the last week".  Against anything that
// can clear one, that is not a block -- observed on a production install, a
// crawler the operator had already taken out of the rescue list solved the
// proof-of-work across a large pool of addresses and served itself a day's
// worth of traffic through a UA row set to deny.  Difficulty cannot reach it
// either: a pass cookie lasts a week, so the cost is one solve per address per
// week whatever the difficulty.  Ordering is the only fix.
func TestDenyIsNotEscapedByAPassCookie(t *testing.T) {
	n := settings.Nginx{}
	n.ChallengeTargets.Extra = []string{"contains:Bytespider"}
	n.ChallengeTargets.ExtraAction = []string{settings.RateChallengeDeny}

	const ua = "Mozilla/5.0 (Linux; Android 5.0) AppleWebKit/537.36 (KHTML, like Gecko) " +
		"Mobile Safari/537.36 (compatible; Bytespider; spider-feedback@bytedance.com)"
	if !hardDenyUA(ua, n) {
		t.Fatal("a UA row pinned to deny does not resolve to a hard deny")
	}
	// The same UA under any other chain is NOT a hard deny -- it is a challenge,
	// and a challenge is exactly what a pass cookie is allowed to satisfy.
	for _, act := range []string{
		settings.RateChallengePoWOnly,
		settings.RateChallengeCaptchaOnly,
		settings.RateChallengePoWThenCaptcha,
		"",
	} {
		n2 := settings.Nginx{}
		n2.ChallengeTargets.Extra = []string{"contains:Bytespider"}
		n2.ChallengeTargets.ExtraAction = []string{act}
		if hardDenyUA(ua, n2) {
			t.Errorf("action %q resolves to a hard deny; only deny may skip the cookie", act)
		}
	}
	// A disabled row denies nothing.
	n3 := settings.Nginx{}
	n3.ChallengeTargets.Extra = []string{"contains:Bytespider"}
	n3.ChallengeTargets.ExtraAction = []string{settings.RateChallengeDeny}
	n3.ChallengeTargets.ExtraDisabled = []bool{true}
	if hardDenyUA(ua, n3) {
		t.Error("a disabled row still denies")
	}
	// An ordinary visitor is untouched.
	if hardDenyUA("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "+
		"(KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36", n) {
		t.Error("a real browser resolves to a hard deny")
	}
}

// The list-wide default carries too: setting the black list itself to deny
// denies every row that pinned no chain of its own.
func TestListDefaultDenyAppliesToUnpinnedRows(t *testing.T) {
	n := settings.Nginx{}
	n.ChallengeTargets.DefaultAction = settings.RateChallengeDeny
	n.ChallengeTargets.Extra = []string{"contains:Scrapy", "contains:MJ12bot"}
	n.ChallengeTargets.ExtraAction = []string{"", settings.RateChallengeCaptchaOnly}

	if !hardDenyUA("Scrapy/2.11 (+https://scrapy.org)", n) {
		t.Error("an unpinned row does not inherit the list default of deny")
	}
	// ...and a row that pinned a softer chain keeps it.  The default is a
	// default, not a floor.
	if hardDenyUA("Mozilla/5.0 (compatible; MJ12bot/v1.4.8)", n) {
		t.Error("a row pinned to captcha_only was overridden by the list default")
	}
}

// The render and the daemon answer the same question on two wires, from two
// code paths, and a disagreement is invisible until an operator reports that a
// deny works in one mode and not the other.  Every pattern the render emits
// into $unmask_ua_deny must be one the daemon agrees is a hard deny.
func TestHardDenyRenderMatchesTheDaemon(t *testing.T) {
	s := settings.Settings{}
	s.Nginx.ChallengeTargets.DefaultAction = settings.RateChallengeDeny
	s.Nginx.ChallengeTargets.Extra = []string{"contains:Bytespider", "contains:PetalBot"}
	s.Nginx.ChallengeTargets.ExtraAction = []string{"", settings.RateChallengePoWOnly}

	pats := nginxconf.HardDenyUAPatternsForTest(s)
	if len(pats) == 0 {
		t.Fatal("the render emits no deny patterns for a list defaulted to deny")
	}
	// Compared per UA rather than per pattern: a preset pattern is a raw regex,
	// so there is no honest way to turn one back into a UA that matches it, and
	// a test that guesses would be asserting its own guess.  What has to hold is
	// the property itself -- for any given visitor, nginx and the daemon reach
	// the same verdict.
	denyByPattern := func(ua string) bool {
		for _, p := range pats {
			if matchedRegex(p, ua) {
				return true
			}
		}
		return false
	}
	for _, ua := range []string{
		"Mozilla/5.0 (Linux; Android 5.0) AppleWebKit/537.36 (KHTML, like Gecko) " +
			"Mobile Safari/537.36 (compatible; Bytespider; spider-feedback@bytedance.com)",
		"Mozilla/5.0 (compatible; PetalBot;+https://webmaster.petalsearch.com/site/petalbot)",
		"curl/8.7.1",
		"python-requests/2.32.3",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) " +
			"Chrome/150.0.0.0 Safari/537.36",
		"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
		"",
	} {
		if got, want := denyByPattern(ua), hardDenyUA(ua, s.Nginx); got != want {
			t.Errorf("ua %q: nginx would deny=%v, daemon says deny=%v -- the two wires disagree",
				ua, got, want)
		}
	}
	// And the row pinned to a softer chain is not emitted at all: nginx would
	// otherwise deny ahead of the cookie something the daemon only challenges.
	if denyByPattern("Mozilla/5.0 (compatible; PetalBot;+https://webmaster.petalsearch.com/site/petalbot)") {
		t.Error("a row pinned to pow_only was emitted as a hard deny")
	}
}

// The dispatch has to sit with the ban, above everything that reads _bv --
// which is the entire point.  Asserted on the rendered template because the
// ordering is the fix: the same rule further down the file is the bug.
func TestHardDenyDispatchesAheadOfTheCookie(t *testing.T) {
	b, err := os.ReadFile("../nginxconf/templates/server.inc.tmpl")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	deny := strings.Index(src, "$unmask_deny_now")
	if deny < 0 {
		t.Fatal("server.inc never dispatches a hard deny")
	}
	ban := strings.Index(src, "$unmask_ban_action_effective")
	if ban < 0 || deny < ban {
		t.Error("the hard deny is dispatched before the ban; the ban is the stricter of the two")
	}
	if !strings.Contains(src[deny:], "/unmask/_deny") {
		t.Error("the hard deny dispatch does not route to the deny page")
	}

	h, err := os.ReadFile("../nginxconf/templates/http.conf.tmpl")
	if err != nil {
		t.Fatal(err)
	}
	hs := string(h)
	// The rescues gate the signal, so an exemption the operator set on purpose
	// still wins over a deny.  Reached through a map VALUE rather than a key --
	// see the render test for why that distinction is worth 8x.
	unresc := strings.Index(hs, "$unmask_deny_unrescued {")
	if unresc < 0 {
		t.Fatal("the deny signal is not gated on the rescues")
	}
	for _, want := range []string{"$is_search_bot", "$is_bypass_ip", "$is_bypass_path"} {
		if !strings.Contains(hs[unresc-200:unresc], want) {
			t.Errorf("%s does not gate the deny; an exemption would be overridden", want)
		}
	}
	// ...and the dispatch is a rewrite, so it has to be masked off on the mount
	// it rewrites to or it loops -- the same guard the ban carries.
	now := strings.Index(hs, "$unmask_deny_now {")
	if now < 0 {
		t.Fatal("$unmask_deny_now is not rendered")
	}
	if !strings.Contains(hs[now:now+220], `"~^/unmask/"`) {
		t.Error("the deny signal is not masked off on /unmask/*; the rewrite loops")
	}
}

// Native and forward-auth must agree on WHERE the deny sits, not just that it
// exists.  server.inc dispatches $unmask_deny_now before the Web Bot Auth and
// Privacy Pass gates; the forward-auth switch originally had the same case
// BELOW both, so a signed agent whose UA was denied got blocked in one mode and
// passed in the other.  Nothing functional catches that -- each mode is
// self-consistent -- so the orders are compared directly.
func TestHardDenyHasTheSamePlaceOnBothWires(t *testing.T) {
	sv, err := os.ReadFile("../nginxconf/templates/server.inc.tmpl")
	if err != nil {
		t.Fatal(err)
	}
	native := string(sv)
	nDeny := strings.Index(native, "$unmask_deny_now = ")
	nWBA := strings.Index(native, "$unmask_signed_gate = ")
	nPAT := strings.Index(native, "$unmask_pat_gate = ")
	if nDeny < 0 || nWBA < 0 || nPAT < 0 {
		t.Fatal("server.inc no longer dispatches all three gates")
	}
	if !(nDeny < nWBA && nDeny < nPAT) {
		t.Fatal("native no longer denies before the WBA / PAT gates; update this test and the switch together")
	}

	fa, err := os.ReadFile("auth_check.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(fa)
	fDeny := strings.Index(src, "case hardDenyUA(ua, cfg.Nginx) &&")
	fWBA := strings.Index(src, "case wbaResult.OK &&")
	fPAT := strings.Index(src, "case patResult.OK:")
	// Anchored on the indented case statement, not the bare words: the case
	// carries a guard now (the CAPTCHA-grade requirement) so the trailing
	// colon is gone, and the prose above it says "case bvOK below" -- which a
	// looser match finds first, inside a comment, and reports the cases in the
	// wrong order.
	fBV := strings.Index(src, "\n\t\tcase bvOK")
	if fDeny < 0 || fWBA < 0 || fPAT < 0 || fBV < 0 {
		t.Fatal("the forward-auth decision switch lost one of its cases")
	}
	if fDeny > fWBA || fDeny > fPAT {
		t.Error("forward-auth verifies a signed agent / token BEFORE the deny, but native denies first: " +
			"the same request is blocked in native mode and passed in forward-auth")
	}
	if fDeny > fBV {
		t.Error("forward-auth lets a pass cookie outrank the deny; that is the bug this axis exists to fix")
	}
	// The rescues must be re-checked in the case itself.  Every case that grants
	// them sits BELOW the cookie, so a deny placed above the cookie skips them
	// unless it asks again.
	caseSrc := src[fDeny:fWBA]
	for _, want := range []string{"isSearchBotUA(", "matchers.ipBypass.Match(", "matchers.bypass"} {
		if !strings.Contains(caseSrc, want) {
			t.Errorf("the forward-auth deny does not re-check %s; an exemption the operator "+
				"set on purpose would be overridden", want)
		}
	}
}

// The two wires must record the SAME buckets, not just reach the same verdict.
// forward-auth had no crawler_pass arm at all: a rescued crawler was passed
// correctly and then counted as nothing, so on a node answering /api/check the
// composition card's benign share sat at zero all day while the residue tracked
// the crawler table request for request (227 of 1,094 in an hour).  Every
// functional test passed -- the DECISION was right, only the bookkeeping was
// missing, and native's own tests cannot see a gap on the other wire.
func TestBothWiresRecordTheSameBuckets(t *testing.T) {
	fa, err := os.ReadFile("auth_check.go")
	if err != nil {
		t.Fatal(err)
	}
	nat, err := os.ReadFile("../nginxlog/nginxlog.go")
	if err != nil {
		t.Fatal(err)
	}
	// Every kind onLine can write, forward-auth must be able to write too.
	// Checked through the exported bump method rather than the kind string,
	// because that is the only route the other wire has -- and both halves are
	// asserted, so renaming the method without wiring it still fails.
	for kind, method := range map[string]string{
		"crawler_pass": "BumpCrawlerPass",
		"bypass_pass":  "BumpBypass",
	} {
		if !strings.Contains(string(nat), `bumpKind(site, "`+kind+`")`) {
			t.Errorf("%s does not write %s; the two wires cannot agree through it", method, kind)
		}
		if !strings.Contains(string(nat), `r.bumpKind(p.site, "`+kind+`")`) {
			t.Errorf("onLine no longer writes %s natively; update this test with it", kind)
		}
		if !strings.Contains(string(fa), "h.NginxLog."+method+"(") {
			t.Errorf("forward-auth never calls %s, so it never records %s: the same traffic lands "+
				"in different buckets depending on the deploy mode", method, kind)
		}
	}
	// ...and in the same order, as one decision rather than independent ifs.
	sw := strings.Index(string(fa), "switch {\n\t\tcase bvKind != \"\" || fc:")
	if sw < 0 {
		t.Fatal("the forward-auth classification is not a single switch; independent ifs are how the native side counted a cookie holder twice")
	}
	seg := string(fa)[sw:]
	if end := strings.Index(seg, "\n\t\t}"); end > 0 {
		seg = seg[:end]
	}
	crawler := strings.Index(seg, "BumpCrawlerPass")
	bypass := strings.Index(seg, "BumpBypass")
	if crawler < 0 || bypass < 0 || crawler > bypass {
		t.Error("forward-auth does not classify crawler before bypass; native does, so a listed " +
			"crawler on a bypassed path would be counted differently on each wire")
	}
}
