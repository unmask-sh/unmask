package handlers

import (
	"slices"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/classify"
	"github.com/unmask-sh/unmask/admin/internal/nginxconf"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// A crawler set on its own gets the same answer from every reader of the
// setting: the render's deny list, the daemon's forward-auth lookups, the
// serve-time chain and IsBot.
func TestCrawlerSetOnItsOwnAgreesEverywhere(t *testing.T) {
	const bytespider = "Mozilla/5.0 (Linux; Android 5.0) AppleWebKit/537.36 (KHTML, like Gecko) " +
		"Mobile Safari/537.36 (compatible; Bytespider; spider-feedback@bytedance.com)"
	const opengraph = "python-opengraph/1.0"

	var s settings.Settings
	sb := &s.Nginx.SearchBots
	sb.UpstreamPatternMode = map[string]string{
		`Bytespider`:       classify.GroupModeBlack, // its group (ai-training) passes
		`python-opengraph`: classify.GroupModeWhite, // its group (http-library) is stopped
	}
	sb.UpstreamGroupAction = map[string]string{"ai-training": settings.RateChallengeDeny}

	// Stopped on its own, with its group's chain.
	if listed, cat, act := lookupUAListed(bytespider, s.Nginx); listed != "ai-training" || cat != "challenge" || act != settings.RateChallengeDeny {
		t.Errorf("Bytespider: lookupUAListed = %q %q %q, want ai-training challenge deny", listed, cat, act)
	}
	if !slices.Contains(nginxconf.HardDenyUAPatternsForTest(s), `Bytespider`) {
		t.Error("Bytespider: the render must deny it ahead of the cookie")
	}
	if !hardDenyUA(bytespider, s.Nginx) {
		t.Error("Bytespider: the daemon must deny it too -- the two wires disagree")
	}
	if got := classify.ResolveActionForUA(bytespider, sb.UpstreamGroupMode, sb.UpstreamPatternMode, sb.UpstreamGroupAction); got != settings.RateChallengeDeny {
		t.Errorf("Bytespider: serve-time chain = %q, want deny", got)
	}

	// Its group's other crawlers still pass, and are denied nothing.
	const ccbot = "CCBot/2.0 (https://commoncrawl.org/faq/)"
	if listed, cat, _ := lookupUAListed(ccbot, s.Nginx); cat == "challenge" {
		t.Errorf("CCBot follows its passing group, but lookupUAListed lists it (%q)", listed)
	}
	if hardDenyUA(ccbot, s.Nginx) {
		t.Error("CCBot follows its passing group: the group's deny chain must not reach it")
	}

	// IsBot no longer reports it as a rescued search_ai hit.
	classify.SetUpstreamUnrescued(nginxconf.UpstreamUnrescued(s.Nginx))
	t.Cleanup(func() { classify.SetUpstreamUnrescued(nil) })
	if classify.IsBot(bytespider, "") == classify.SearchAI {
		t.Error("Bytespider set to stop must not classify as a rescued search_ai hit")
	}
	if classify.IsBot(ccbot, "") != classify.SearchAI {
		t.Error("CCBot follows its passing group and is still a search_ai hit")
	}

	// Passed on its own inside a stopped group: the upstream branch no longer
	// lists it as a challenge target.
	if listed, cat, _ := lookupUAListed(opengraph, s.Nginx); cat == "challenge" {
		t.Errorf("python-opengraph set to pass must not be a challenge target (listed by %q)", listed)
	}
}
