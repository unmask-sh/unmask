package handlers

import (
	"net/url"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/i18n"
)

// The hunt's filters become a custom-rule draft, one condition per filter in
// the form the rule needs: the address and the network as they are, a whole
// fingerprint as it is and a shorter one (the hunt matched it as a
// substring) as a prefix, the user-agent substring quoted into a regex.  No
// filter that can be a condition, no draft.  The name is "hunt: ..." and
// stays inside the rule's limit.
func TestHuntCustomRuleDraft(t *testing.T) {
	if got := huntCustomRuleDraft("", "", "", 0, i18n.LangJA); got != "" {
		t.Errorf("no filters gave a draft: %q", got)
	}
	parse := func(href string) url.Values {
		t.Helper()
		if !strings.HasPrefix(href, "?new=1&") {
			t.Fatalf("draft does not lead with new=1: %q", href)
		}
		q, err := url.ParseQuery(strings.TrimPrefix(href, "?"))
		if err != nil {
			t.Fatal(err)
		}
		return q
	}
	q := parse(huntCustomRuleDraft("203.0.113.5", "t13d1516h2", "python-requests (+http", 4134, i18n.LangJA))
	want := []string{"ip:203.0.113.5", "ja4:t13d1516h2*", `ua:python-requests \(\+http`, "asn:4134"}
	if got := q["c"]; strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("conditions = %q, want %q", got, want)
	}
	if got := q.Get("label"); got != "hunt: 203.0.113.5 + t13d1516h2 + python-requests (+http + AS4134" {
		t.Errorf("label = %q", got)
	}
	if got := q.Get("action"); got != "captcha_only" {
		t.Errorf("action = %q, want captcha_only", got)
	}

	// A whole fingerprint is the condition as it is, in lower case.
	q = parse(huntCustomRuleDraft("", "T13D1516H2_8daaf6152771_b0da82dd1658", "", 0, i18n.LangEN))
	if got := q["c"]; len(got) != 1 || got[0] != "ja4:t13d1516h2_8daaf6152771_b0da82dd1658" {
		t.Errorf("whole fingerprint: conditions = %q", got)
	}

	// A name that would run past the rule's limit keeps the first filter
	// and says there is more, rather than being cut or refused on save.
	long := strings.Repeat("Mozilla/5.0 ", 8)
	q = parse(huntCustomRuleDraft("203.0.113.5", "", long, 0, i18n.LangJA))
	if got := q.Get("label"); got != "hunt: 203.0.113.5 + …" {
		t.Errorf("long label = %q", got)
	}
}
