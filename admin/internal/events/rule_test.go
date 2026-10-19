package events

import "testing"

// The rule a row names: the custom rule behind a custom_rule challenge, or
// the entry a deny axis matched.
func TestExtractRule(t *testing.T) {
	for _, c := range []struct{ payload, want string }{
		{`{"force_reason":"custom_rule","force_rule":"cr1a2b","bt":"x"}`, "cr1a2b"},
		{`{"force_reason":"asn_deny","deny":1,"deny_rule":"AS64496"}`, "AS64496"},
		{`{"force_reason":"custom_rule","force_rule":"cr1a2b","deny_rule":"CN"}`, "cr1a2b"},
		{`{"force_reason":"none"}`, ""},
		{``, ""},
	} {
		if got := extractRule(c.payload); got != c.want {
			t.Errorf("%s: rule %q, want %q", c.payload, got, c.want)
		}
	}
}
