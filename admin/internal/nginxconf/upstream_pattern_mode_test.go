package nginxconf

import (
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// mapBody returns the entries of the first map in conf whose header line
// starts with header, or "" when there is none.
func mapBody(conf, header string) string {
	i := strings.Index(conf, header)
	if i < 0 {
		return ""
	}
	rest := conf[i:]
	if j := strings.Index(rest, "\n}"); j >= 0 {
		return rest[:j]
	}
	return rest
}

func inMap(conf, header, pat string) bool {
	return strings.Contains(mapBody(conf, header), `"~*`+pat+`" 1;`)
}

const (
	whiteMap   = "map $http_user_agent $unmask_search_bot_ua {"
	blackMap   = "map $http_user_agent $is_challenge_target {"
	denyMap    = "map $http_user_agent $unmask_ua_deny {"
	captchaMap = "map $http_user_agent $unmask_ua_needs_captcha {"
)

// A crawler set on its own takes its own mode whatever its group says: one
// stopped inside a passing group leaves the whitelist for the challenge
// targets, one passed inside a stopped group does the reverse, and the rest of
// both groups follow their group.
func TestRenderCrawlerSetOnItsOwn(t *testing.T) {
	conf := renderHTTPInc(t, func(s *settings.Settings) {
		// No notification-preview pattern passes, so the plain whitelist map
		// is the one rendered.
		s.Nginx.SearchBots.UpstreamGroupMode = map[string]string{"notification-preview": "none"}
		s.Nginx.SearchBots.UpstreamPatternMode = map[string]string{
			`MJ12bot`: "black", // seo passes by default
			`^curl`:   "white", // http-library is stopped by default
			`dotbot`:  "none",
		}
	})
	if inMap(conf, whiteMap, `MJ12bot`) || !inMap(conf, blackMap, `MJ12bot`) {
		t.Error("MJ12bot set to stop: it must leave the whitelist for the challenge targets")
	}
	if !inMap(conf, whiteMap, `^curl`) || inMap(conf, blackMap, `^curl`) {
		t.Error("^curl set to pass: it must move from the challenge targets to the whitelist")
	}
	if inMap(conf, whiteMap, `dotbot`) || inMap(conf, blackMap, `dotbot`) {
		t.Error("dotbot set to normal checks: it must be in neither map")
	}
	if !inMap(conf, whiteMap, `rogerbot`) {
		t.Error("rogerbot follows its passing group: it must stay in the whitelist")
	}
	if !inMap(conf, blackMap, `python-requests`) {
		t.Error("python-requests follows its stopped group: it must stay a challenge target")
	}
}

// A crawler stopped on its own takes its group's chain, the same one the
// group's crawlers get when the whole group is stopped -- for the deny
// dispatch and for the CAPTCHA-grade map alike.
func TestRenderCrawlerStoppedOnItsOwnTakesItsGroupsChain(t *testing.T) {
	conf := renderHTTPInc(t, func(s *settings.Settings) {
		s.Nginx.SearchBots.UpstreamPatternMode = map[string]string{`Bytespider`: "black", `MJ12bot`: "black"}
		s.Nginx.SearchBots.UpstreamGroupAction = map[string]string{"ai-training": "deny", "seo": "captcha_only"}
	})
	if !inMap(conf, denyMap, `Bytespider`) {
		t.Error("Bytespider stopped on its own in a group whose chain is deny: it must be in the deny map")
	}
	if inMap(conf, denyMap, `MJ12bot`) {
		t.Error("MJ12bot's group chain is captcha_only: it must not be denied")
	}
	if !inMap(conf, captchaMap, `MJ12bot`) {
		t.Error("MJ12bot's group chain ends in a CAPTCHA: it must be in the CAPTCHA-grade map")
	}
	// The group's chain reaches only the crawlers stopped: the rest of the
	// group still passes and is denied nothing.
	if inMap(conf, denyMap, `GPTBot`) || inMap(conf, denyMap, `CCBot`) {
		t.Error("the group's deny chain must not reach crawlers that are not stopped")
	}
}
