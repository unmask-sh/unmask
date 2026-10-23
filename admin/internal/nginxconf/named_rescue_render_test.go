package nginxconf

import (
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// A crawler known by its name alone: the rescue clears the global posture and
// nothing else -- a trap, a listing, a rule, a protected path, a deny and every
// rate limit apply to it -- it holds only for a fetch (GET / HEAD), it is
// counted against its own per-address budget, and the access log says the
// request was passed on the claim.
func TestNamedRescueRender(t *testing.T) {
	httpInc, serverInc, protectInc := renderIncs(t, nil)
	for _, want := range []string{
		// the two-stage rescue, gated on the method
		`:$request_method" $is_search_bot {`,
		`(?:GET|HEAD)$`,
		// the base decision: targeted axes apply to a named crawler ...
		`"~^0:1:0:0:1:"                    1;`,
		`"~^0:1:0:0:0:1:"                  1;`,
		`"~^0:1:0:0:0:0:captcha:"          1;`,
		`"~^0:1:0:0:0:0::0:[^:]*:1$"       1;`,
		// ... and only the global posture is cleared
		`"~^0:1:"                          0;`,
		// the rate limits count it like anyone
		`map "$bv_any_valid:$is_bypass_ip:$is_bypass_path" $rate_limit_key {`,
		`map "$is_bypass_ip:$is_bypass_path" $rate_limit_key_deny {`,
		// its own budget, per address
		`map "$is_search_bot:$bv_any_valid:$is_bypass_ip:$is_bypass_path:$unmask_preview_verified" $unmask_named_rate_key {`,
		`limit_req_zone $unmask_named_rate_key zone=unmask_named_rate:10m rate=30r/m;`,
		// the log carries the claim ...
		` sb=$is_search_bot sfs=$unmask_sfs_log sfd=$unmask_sfd_log rh=$unmask_ref_host ua=$http_user_agent'`,
		// ... and a request the rate route answered is served, not passed
		`map $uri $unmask_rl_served {`,
		`map "$unmask_gated:$unmask_rl_served" $unmask_fc_log {`,
		`"~^1::1$" 1;`,
	} {
		if !strings.Contains(httpInc, want) {
			t.Errorf("http.inc lacks %q", want)
		}
	}
	// No rate key consults the name any more.
	for _, line := range strings.Split(httpInc, "\n") {
		if strings.HasPrefix(line, "map ") && strings.Contains(line, "_key {") && strings.Contains(line, "$is_search_bot") &&
			!strings.Contains(line, "$unmask_named_rate_key") {
			t.Errorf("a rate key still exempts the name-only rescue: %s", line)
		}
	}
	if !strings.Contains(protectInc, "limit_req zone=unmask_named_rate burst=30 nodelay;") {
		t.Error("protect.inc does not apply the name-only budget")
	}
	if !strings.Contains(serverInc, "proxy_set_header   X-Unmask-Named-Rescue $is_search_bot;") {
		t.Error("server.inc does not tell the daemon the request was a name-only claim")
	}

	// The budget follows the setting, and 0 turns it off.
	zero := 0
	httpInc, _, protectInc = renderIncs(t, func(s *settings.Settings) { s.Nginx.SearchBots.NameOnlyRatePerMin = &zero })
	if strings.Contains(httpInc, "unmask_named_rate") || strings.Contains(protectInc, "unmask_named_rate") {
		t.Error("a budget of 0 must render no zone")
	}
	big := 120
	httpInc, _, protectInc = renderIncs(t, func(s *settings.Settings) { s.Nginx.SearchBots.NameOnlyRatePerMin = &big })
	if !strings.Contains(httpInc, "zone=unmask_named_rate:10m rate=120r/m;") || !strings.Contains(protectInc, "limit_req zone=unmask_named_rate burst=120 nodelay;") {
		t.Error("the budget zone does not follow the setting")
	}
}
