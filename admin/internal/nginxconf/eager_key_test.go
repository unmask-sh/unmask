package nginxconf

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// nginx builds a map key EAGERLY -- every variable in it, on every request that
// reads the map -- and resolves only the matched entry's value.  So a variable
// in a key is paid by everyone; the same variable reached through a value is
// paid only on the branch that needs it.  Nothing in a functional test can see
// the difference, and the two shapes look equally reasonable in review.
//
// The maps below are read by `if`s at SERVER scope, so they run for every
// request to the vhost -- including requests served by locations that never
// include protect.inc and would otherwise build none of the decision chain.
// Measured on such a location: $final_challenge in the Web Bot Auth gate key
// cost 56k -> 3.9k req/s just for turning the feature on, and $is_search_bot
// (which pulls $effective_ja4 behind the notification-preview composite) in the
// hard-deny key cost 46k -> 3.4k.  Both are ~13x for a decision that is almost
// always "no".
func TestServerScopeGatesDoNotBuildTheChainEagerly(t *testing.T) {
	b, err := os.ReadFile("templates/http.conf.tmpl")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)

	// The map key is everything between `map ` and the variable it defines.
	keyOf := func(defines string) string {
		re := regexp.MustCompile(`(?m)^map\s+(.*?)\s+\` + defines + `\s*\{`)
		m := re.FindStringSubmatch(src)
		if m == nil {
			t.Fatalf("map defining %s not found", defines)
			return ""
		}
		return m[1]
	}
	for _, tc := range []struct {
		defines string
		banned  []string
	}{
		{"$unmask_signed_gate", []string{"$final_challenge"}},
		{"$unmask_pat_gate", []string{"$final_challenge"}},
		{"$unmask_deny_raw", []string{"$is_search_bot", "$effective_ja4", "$final_challenge"}},
	} {
		key := keyOf(tc.defines)
		for _, bad := range tc.banned {
			if strings.Contains(key, bad) {
				t.Errorf("%s is keyed on %s (key: %s).\n"+
					"  That builds it for every request to the vhost, not just the ones that need it.\n"+
					"  Reach it through the map VALUE instead -- same truth table, ~13x the throughput\n"+
					"  on a location that does not include protect.inc.", tc.defines, bad, key)
			}
		}
	}
}
