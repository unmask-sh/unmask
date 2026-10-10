package nginxconf

import (
	"os"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The operator's custom rules as http.inc draws them: a 0/1 map per
// condition present, one map ANDing them, a first-match chain into
// $unmask_cr_id / $unmask_cr_action, the action joining the challenge, the
// CAPTCHA grade and the deny block, a throttle as a limit_req zone, and the
// id on the access log.  With no rules the variables still exist, empty.
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

	// No rules: the chain's variables exist and stay empty, so every map
	// that reads them parses.
	out, prot := render(settings.Settings{})
	for _, want := range []string{
		"map \"\" $unmask_cr_id {\n    default \"\";\n}",
		"map $unmask_cr_id $unmask_cr_action {\n    default \"\";\n}",
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

	// Three rules: a conjunction with a challenge, a throttle, a deny.
	var s settings.Settings
	s.Nginx.CustomRules = []settings.CustomRule{
		{ID: "cr1", Label: "scraper", Enabled: true, JA4s: []string{"t13d1516h2_8daaf6152771_b0da82dd1658", "t13d*"}, UA: `python-requests|scrapy`, Path: `^/search\?`, Hosts: []string{"shop.example.jp"}, Action: settings.GeoActionCaptchaOnly},
		{ID: "cr2", Label: "burst", Enabled: true, IPs: []string{"203.0.113.0/24", "198.51.100.7"}, Action: settings.CustomRuleMonitor, RatePerMin: 30},
		{ID: "cr3", Label: "deny", Enabled: true, IPs: []string{"192.0.2.0/24"}, Action: settings.GeoActionDeny},
		{ID: "cr4", Label: "off", Enabled: false, IPs: []string{"192.0.2.9"}, Action: settings.GeoActionDeny},
		{ID: "cr5", Label: "count", Enabled: true, UA: `"quoted"`, Action: settings.CustomRuleMonitor},
	}
	out, prot = render(s)
	for _, want := range []string{
		// rule 1: its conditions, the AND, the pick
		"map $effective_ja4 $unmask_cr_1_ja4 {\n    default 0;\n    \"t13d1516h2_8daaf6152771_b0da82dd1658\" 1;\n    \"~^t13d\" 1;\n}",
		"map $http_user_agent $unmask_cr_1_ua {\n    default 0;\n    \"~*python-requests|scrapy\" 1;\n}",
		"map $request_uri $unmask_cr_1_path {\n    default 0;\n    \"~^/search\\?\" 1;\n}",
		"map $host $unmask_cr_1_host {\n    default 0;\n    \"shop.example.jp\" 1;\n}",
		"map \"$unmask_cr_1_ja4:$unmask_cr_1_ua:$unmask_cr_1_path:$unmask_cr_1_host\" $unmask_cr_1 {\n    default 0;\n    \"1:1:1:1\" 1;\n}",
		"map $unmask_cr_1 $unmask_cr_1_pick {\n    default $unmask_cr_2_pick;\n    \"1\"     \"cr1\";\n}",
		// rule 2: addresses, a throttle (no action entry)
		"geo $remote_addr $unmask_cr_2_ip {\n    default 0;\n    203.0.113.0/24 1;\n    198.51.100.7 1;\n}",
		"map \"$is_search_bot:$is_bypass_ip:$unmask_cr_2\" $crrate_2_key {",
		"limit_req_zone $crrate_2_key zone=crrate_2:10m rate=30r/m;",
		// rule 3: deny, the last of the chain
		"map $unmask_cr_3 $unmask_cr_3_pick {\n    default $unmask_cr_4_pick;",
		"map $unmask_cr_4 $unmask_cr_4_pick {\n    default \"\";\n    \"1\"     \"cr5\";\n}",
		"map \"\" $unmask_cr_id {\n    default $unmask_cr_1_pick;\n}",
		"map $unmask_cr_id $unmask_cr_action {\n    default \"\";\n    \"cr1\" \"captcha_only\";\n    \"cr3\" \"deny\";\n}",
		// a quote in a pattern is escaped
		"\"~*\\\"quoted\\\"\" 1;",
		// the deny block is drawn, with the rule's term
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
		t.Error("protect.inc lacks the throttle's limit_req")
	}
}

// The server.inc hands the deciding rule and its action to the daemon.
func TestCustomRulesServerHeaders(t *testing.T) {
	dir := t.TempDir()
	if err := Render(settings.Settings{}, dir, "test"); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(dir + "/server.inc")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"proxy_set_header   X-Unmask-Rule        $unmask_cr_id;", "proxy_set_header   X-Unmask-Rule-Action $unmask_cr_action;"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("server.inc lacks %q", want)
		}
	}
}
