package settings

import (
	"strings"
	"testing"
)

func TestNormalizeCustomRule(t *testing.T) {
	r := CustomRule{ID: "CR1", Label: " x ", Action: "captcha_only", RatePerMin: 2_000_000, Conditions: []CustomCondition{
		{Kind: " IP ", Values: []string{" 203.0.113.5 ", "", "10.0.0.0/8"}, Memo: " seen "},
		{Kind: "ja4", Values: []string{"T13D*"}},
		{Kind: "country", Values: []string{"jp"}},
		{Kind: "asn", Values: []string{"AS4134", "16509"}},
		{Kind: "ua", Values: []string{"(?i)curl, wget"}}, // a regex is one value, comma and all
		{Kind: "path", Values: []string{`^/a\?b=1`}},
		{Kind: "host", Values: []string{"Example.COM"}},
		{Kind: "ip", Values: []string{"", "  "}}, // an empty line is dropped
	}}
	if err := NormalizeCustomRule(&r); err != nil {
		t.Fatal(err)
	}
	c := r.Conditions
	if r.ID != "cr1" || r.Label != "x" || r.RatePerMin != 1_000_000 || len(c) != 7 ||
		c[0].Kind != "ip" || len(c[0].Values) != 2 || c[0].Memo != "seen" ||
		c[1].Values[0] != "t13d*" || c[2].Values[0] != "JP" || c[3].Values[0] != "4134" || c[3].Values[1] != "16509" ||
		c[4].Values[0] != "(?i)curl, wget" || c[6].Values[0] != "example.com" {
		t.Errorf("normalised: %+v", r)
	}
	// The rate limit sits beside the action, with its own answer; without a
	// rate the answer is dropped, an unknown answer refused.
	rl := CustomRule{Action: "captcha_only", Conditions: []CustomCondition{{Kind: "ip", Values: []string{"203.0.113.5"}}}, RatePerMin: 60, RateAction: " deny "}
	if err := NormalizeCustomRule(&rl); err != nil || rl.RatePerMin != 60 || rl.RateAction != "deny" || rl.Action != "captcha_only" {
		t.Errorf("action with a rate limit: %v %+v", err, rl)
	}
	nr := CustomRule{Action: "deny", Conditions: []CustomCondition{{Kind: "ip", Values: []string{"203.0.113.5"}}}, RateAction: "deny"}
	if err := NormalizeCustomRule(&nr); err != nil || nr.RateAction != "" {
		t.Errorf("rate answer without a rate: %v %+v", err, nr)
	}
	ok := func(c CustomCondition) CustomRule {
		return CustomRule{Action: "deny", Conditions: []CustomCondition{c}}
	}
	if err := NormalizeCustomRule(&CustomRule{Action: "deny", Conditions: []CustomCondition{{Kind: "ip", Values: []string{"203.0.113.5"}}}, RatePerMin: 10, RateAction: "ban"}); err == nil {
		t.Error("an unknown over-limit answer was accepted")
	}
	// The name is optional and bounded.
	if err := NormalizeCustomRule(&CustomRule{Action: "deny", Conditions: []CustomCondition{{Kind: "ip", Values: []string{"203.0.113.5"}}}, Label: strings.Repeat("x", 81)}); err == nil {
		t.Error("an 81-character name was accepted")
	}
	for name, bad := range map[string]CustomRule{
		"no condition":   {Action: "deny"},
		"only empty":     {Action: "deny", Conditions: []CustomCondition{{Kind: "ip", Values: []string{""}}}},
		"bad action":     {Action: "ban", Conditions: []CustomCondition{{Kind: "ip", Values: []string{"203.0.113.5"}}}},
		"rate as action": {Action: "rate_limit", Conditions: []CustomCondition{{Kind: "ip", Values: []string{"203.0.113.5"}}}},
		"bad kind":       ok(CustomCondition{Kind: "ssl", Values: []string{"x"}}),
		"bad cidr":       ok(CustomCondition{Kind: "ip", Values: []string{"203.0.113.5/40"}}),
		"bad ja4":        ok(CustomCondition{Kind: "ja4", Values: []string{"t13d 1516"}}),
		"bad country":    ok(CustomCondition{Kind: "country", Values: []string{"JPN"}}),
		"bad asn":        ok(CustomCondition{Kind: "asn", Values: []string{"AS0"}}),
		"bad regex":      ok(CustomCondition{Kind: "ua", Values: []string{"("}}),
		"bad host":       ok(CustomCondition{Kind: "host", Values: []string{"a b"}}),
		"long memo":      ok(CustomCondition{Kind: "ip", Values: []string{"203.0.113.5"}, Memo: strings.Repeat("x", 301)}),
	} {
		b := bad
		if err := NormalizeCustomRule(&b); err == nil {
			t.Errorf("%s: accepted %+v", name, b)
		} else if strings.TrimSpace(err.Error()) == "" {
			t.Errorf("%s: an empty error", name)
		}
	}
	// A condition's error names its line and kind.
	bad := CustomRule{Action: "deny", Conditions: []CustomCondition{{Kind: "ip", Values: []string{"203.0.113.5"}}, {Kind: "ja4", Values: []string{"nope!"}}}}
	if err := NormalizeCustomRule(&bad); err == nil || !strings.HasPrefix(err.Error(), "condition 2 (ja4): ") {
		t.Errorf("the error does not name the line: %v", err)
	}
	var n Nginx
	n.CustomRules = []CustomRule{{ID: "a", Enabled: true, Conditions: []CustomCondition{{Kind: "ip", Values: []string{"203.0.113.5"}}}, Action: "deny"}, {ID: "b", Enabled: false, Conditions: []CustomCondition{{Kind: "ip", Values: []string{"203.0.113.6"}}}, Action: "deny"}, {ID: "c", Enabled: true, Action: "deny"}}
	if got := n.EnabledCustomRules(); len(got) != 1 || got[0].ID != "a" {
		t.Errorf("enabled: %+v", got)
	}
}

// The draft query opens the tab with the rule filled in, one c=<kind>:<values>
// per line; every value is one run of the characters the ask page's
// linkifier accepts, so the path survives as a link in an answer.
func TestCustomRuleDraftQuery(t *testing.T) {
	q := CustomRuleDraftQuery(CustomRule{Label: "scraper ~ v2", Action: "captcha_only", RatePerMin: 30, RateAction: "deny", Conditions: []CustomCondition{
		{Kind: "ip", Values: []string{"203.0.113.0/24", "198.51.100.7"}}, {Kind: "ja4", Values: []string{"t13d*"}}, {Kind: "ua", Values: []string{"python-requests|scrapy (x)"}}, {Kind: "path", Values: []string{`^/search\?q=`}}}})
	if !strings.HasPrefix(q, "?new=1&") {
		t.Errorf("new=1 must lead: %q", q)
	}
	for _, want := range []string{"label=scraper%20%7E%20v2", "c=ip%3A203.0.113.0%2F24%2C198.51.100.7", "c=ja4%3At13d%2A", "c=ua%3Apython-requests%7Cscrapy%20%28x%29", "c=path%3A%5E%2Fsearch%5C%3Fq%3D", "action=captcha_only", "rate=30", "rate_action=deny"} {
		if !strings.Contains(q, want) {
			t.Errorf("query %q lacks %q", q, want)
		}
	}
	for _, c := range q[1:] {
		if !strings.ContainsRune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.%=&-", c) {
			t.Errorf("query carries %q, which the linkifier stops at: %s", c, q)
		}
	}
	if q := CustomRuleDraftQuery(CustomRule{}); q != "?new=1" {
		t.Errorf("empty rule: %q", q)
	}
}
