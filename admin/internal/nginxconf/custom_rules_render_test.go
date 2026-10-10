package nginxconf

import (
	"os"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The operator's custom rules as http.inc draws them: a 0/1 map (or geo
// block) per condition line, one map ANDing the lines, a first-match chain
// into $unmask_cr_id / $unmask_cr_action, the action joining the challenge,
// the CAPTCHA grade and the deny block, a rate limit as a limit_req zone
// with the rule's own over-limit answer in a map, and the id on the access
// log.  With no rules the variables still exist, empty.
func TestCustomRulesRender(t *testing.T) {
	render := func(s settings.Settings) (string, string) {
		dir := t.TempDir()
		if err := Render(s, dir, "test"); err != nil {
			t.Fatal(err)
		}
		h, err := os.ReadFile(dir + "/http.inc")
		if err != nil {
			t.Fatal(err)
		}
		p, err := os.ReadFile(dir + "/protect.inc")
		if err != nil {
			t.Fatal(err)
		}
		return string(h), string(p)
	}

	out, prot := render(settings.Settings{})
	for _, want := range []string{
		"map \"\" $unmask_cr_id {\n    default \"\";\n}",
		"map $unmask_cr_id $unmask_cr_action {\n    default \"\";\n}",
		"map $unmask_cr_id $unmask_cr_rate_action {\n    default \"\";\n}",
		"map $unmask_cr_action $unmask_cr_challenge {",
		"map $unmask_cr_action $unmask_cr_deny {",
		`map "$unmask_ua_needs_captcha$unmask_cr_captcha" $unmask_ua_captcha_eff {`,
		`map "$geo_challenge_eff:$asn_challenge_eff:$unmask_cr_challenge" $is_net_challenge {`,
		"scheme=$unmask_forwarded_proto cr=$unmask_cr_id ua=$http_user_agent",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("no rules: http.inc lacks %q", want)
		}
	}
	if strings.Contains(out, "$unmask_cr_1") || strings.Contains(prot, "crrate_") {
		t.Error("no rules must draw no rule maps or zones")
	}

	cond := func(kind string, vals ...string) settings.CustomCondition {
		return settings.CustomCondition{Kind: kind, Values: vals}
	}
	var s settings.Settings
	s.Nginx.CustomRules = []settings.CustomRule{
		// rule 1: four lines, CAPTCHA on a match
		{ID: "cr1", Label: "scraper", Enabled: true, Action: settings.GeoActionCaptchaOnly, Conditions: []settings.CustomCondition{
			cond("ja4", "t13d1516h2_8daaf6152771_b0da82dd1658", "t13d*"), cond("ua", `python-requests|scrapy`), cond("path", `^/search\?`), cond("host", "shop.example.jp")}},
		// rule 2: addresses, monitor on a match plus a rate limit that denies over the limit
		{ID: "cr2", Label: "burst", Enabled: true, Action: settings.CustomRuleMonitor, RatePerMin: 30, RateAction: settings.GeoActionDeny, Conditions: []settings.CustomCondition{
			cond("ip", "203.0.113.0/24", "198.51.100.7"), cond("country", "CN"), cond("asn", "4134")}},
		// rule 3: deny; two lines of the same kind both hold
		{ID: "cr3", Label: "deny", Enabled: true, Action: settings.GeoActionDeny, Conditions: []settings.CustomCondition{cond("ua", "bot"), cond("ua", "v2")}},
		{ID: "cr4", Label: "off", Enabled: false, Action: settings.GeoActionDeny, Conditions: []settings.CustomCondition{cond("ip", "192.0.2.9")}},
		// a quote in a pattern is escaped
		{ID: "cr5", Label: "count", Enabled: true, Action: settings.CustomRuleMonitor, Conditions: []settings.CustomCondition{cond("ua", `"quoted"`)}},
	}
	out, prot = render(s)
	for _, want := range []string{
		"map $effective_ja4 $unmask_cr_1_c1 {\n    default 0;\n    \"t13d1516h2_8daaf6152771_b0da82dd1658\" 1;\n    \"~^t13d\" 1;\n}",
		"map $http_user_agent $unmask_cr_1_c2 {\n    default 0;\n    \"~*python-requests|scrapy\" 1;\n}",
		"map $request_uri $unmask_cr_1_c3 {\n    default 0;\n    \"~^/search\\?\" 1;\n}",
		"map $host $unmask_cr_1_c4 {\n    default 0;\n    \"shop.example.jp\" 1;\n}",
		"map \"$unmask_cr_1_c1:$unmask_cr_1_c2:$unmask_cr_1_c3:$unmask_cr_1_c4\" $unmask_cr_1 {\n    default 0;\n    \"1:1:1:1\" 1;\n}",
		"map $unmask_cr_1 $unmask_cr_1_pick {\n    default $unmask_cr_2_pick;\n    \"1\"     \"cr1\";\n}",
		"geo $remote_addr $unmask_cr_2_c1 {\n    default 0;\n    203.0.113.0/24 1;\n    198.51.100.7 1;\n}",
		"map $unmask_country $unmask_cr_2_c2 {\n    default 0;\n    \"CN\" 1;\n}",
		"map $unmask_asn $unmask_cr_2_c3 {\n    default 0;\n    \"AS4134\" 1;\n}",
		"map \"$is_search_bot:$is_bypass_ip:$unmask_cr_2\" $crrate_2_key {",
		"limit_req_zone $crrate_2_key zone=crrate_2:10m rate=30r/m;",
		"map \"$unmask_cr_3_c1:$unmask_cr_3_c2\" $unmask_cr_3 {",
		"map $unmask_cr_3 $unmask_cr_3_pick {\n    default $unmask_cr_4_pick;",
		"map $unmask_cr_4 $unmask_cr_4_pick {\n    default \"\";\n    \"1\"     \"cr5\";\n}",
		"map \"\" $unmask_cr_id {\n    default $unmask_cr_1_pick;\n}",
		"map $unmask_cr_id $unmask_cr_action {\n    default \"\";\n    \"cr1\" \"captcha_only\";\n    \"cr3\" \"deny\";\n}",
		"map $unmask_cr_id $unmask_cr_rate_action {\n    default \"\";\n    \"cr2\" \"deny\";\n}",
		"\"~*\\\"quoted\\\"\" 1;",
		`"~^0:0:0:0:0:1$" 1;  # custom rule set to deny`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("http.inc lacks %q", want)
		}
	}
	if strings.Contains(out, "cr4") {
		t.Error("a disabled rule rendered")
	}
	if !strings.Contains(prot, "limit_req zone=crrate_2 burst=30 nodelay;") {
		t.Error("protect.inc lacks the rate limit's limit_req")
	}
}

// The server.inc hands the deciding rule, its action and its over-limit
// answer to the daemon.
func TestCustomRulesServerHeaders(t *testing.T) {
	dir := t.TempDir()
	if err := Render(settings.Settings{}, dir, "test"); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(dir + "/server.inc")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"proxy_set_header   X-Unmask-Rule        $unmask_cr_id;", "proxy_set_header   X-Unmask-Rule-Action $unmask_cr_action;", "proxy_set_header   X-Unmask-Rule-Rate-Action $unmask_cr_rate_action;"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("server.inc lacks %q", want)
		}
	}
}
