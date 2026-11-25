package nginxconf

import (
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/classify"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// uaMapBody is the body of the map on $http_user_agent that sets v.
func uaMapBody(t *testing.T, httpInc, v string) string {
	t.Helper()
	head := "map $http_user_agent " + v + " {\n"
	i := strings.Index(httpInc, head)
	if i < 0 {
		t.Fatalf("http.inc has no map of %s", v)
	}
	body := httpInc[i+len(head):]
	if j := strings.Index(body, "\n}"); j >= 0 {
		body = body[:j]
	}
	return body
}

// TestCrawlerNamesMatchedAsWrittenKeepTheirCaseInTheMaps: a crawler-list
// pattern that is matched as written (classify.MatchExpr) reaches nginx's
// User-Agent maps in a group that restores case inside the map's "~*" -- the
// rescue map by default, and the stop maps once the operator stops the
// crawler -- while every other pattern is rendered as it was.  The daemon's
// matchers read the list through the same function, so a name is the same
// name to both.
func TestCrawlerNamesMatchedAsWrittenKeepTheirCaseInTheMaps(t *testing.T) {
	httpInc, _, _ := renderIncs(t, nil)
	rescue := uaMapBody(t, httpInc, "$unmask_search_bot_ua")
	for _, want := range []string{
		`"~*(?-i:Sonic)" 1;`,
		`"~*(?-i:Fetch\\/)" 1;`,
		`"~*(?-i:ICBot\\/)" 1;`,
		// a pattern that is not on the list: as before
		`"~*PetalBot" 1;`,
	} {
		if !strings.Contains(rescue, want) {
			t.Errorf("the rescue map lacks %s", want)
		}
	}
	for _, not := range []string{`"~*Sonic"`, `"~*Fetch\\/"`, `"~*ICBot\\/"`} {
		if strings.Contains(httpInc, not) {
			t.Errorf("http.inc still matches %s without regard to case", not)
		}
	}
	if n := strings.Count(httpInc, "(?-i:"); n != len(classify.AsWrittenPatterns()) {
		t.Errorf("%d case-restoring groups in http.inc, want one a pattern matched as written (%d)", n, len(classify.AsWrittenPatterns()))
	}

	// Stopped one by one, the crawler moves to the stop map and keeps its
	// case there: the stop is for the crawler, not for every User-Agent that
	// holds its letters.
	stopped, _, _ := renderIncs(t, func(s *settings.Settings) {
		s.Nginx.SearchBots.UpstreamPatternMode = map[string]string{"Sonic": classify.GroupModeBlack}
	})
	if got := uaMapBody(t, stopped, "$is_challenge_target"); !strings.Contains(got, `"~*(?-i:Sonic)" 1;`) {
		t.Error("the stop map does not hold the stopped crawler's pattern with its case")
	}
	if got := uaMapBody(t, stopped, "$unmask_search_bot_ua"); strings.Contains(got, "Sonic") {
		t.Error("the rescue map still holds a crawler the operator stopped")
	}
	if strings.Contains(stopped, `"~*Sonic"`) {
		t.Error("the stopped crawler's pattern is matched without regard to case somewhere")
	}
}

// TestAsWrittenPatternsAreOfTheNameOnlyLists: the patterns matched as
// written are resolved through classify.MatchExpr by the category and tag
// matchers and by the maps above.  Two of the daemon's matchers compile
// their patterns themselves -- the range-verified crawlers' (uaRangeRE, and
// the forward-auth path's copy of it) and the notification-preview one of
// the forward-auth path -- so a pattern on the list must not be one of
// theirs, or the daemon and nginx would read it differently.
func TestAsWrittenPatternsAreOfTheNameOnlyLists(t *testing.T) {
	notif := map[string]bool{}
	for _, e := range classify.UpstreamRescueList()[classify.NotificationPreviewTag] {
		notif[e.Pattern] = true
	}
	for _, p := range classify.AsWrittenPatterns() {
		if _, ok := UARangePresets[p]; ok {
			t.Errorf("%q is matched as written and is a range-verified pattern, whose matcher does not read the rule", p)
		}
		if notif[p] {
			t.Errorf("%q is matched as written and is a notification-preview pattern, whose matcher does not read the rule", p)
		}
	}
}
