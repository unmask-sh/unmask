package handlers

import (
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestApplyChallengeFormPageGzip: the box on the challenge tab is ticked
// where nothing is said.  Unticked, the record says false; a form that does
// not carry the box leaves the record as it was; and on the Default record
// the ticked box, which says what unset means, is not written out.
func TestApplyChallengeFormPageGzip(t *testing.T) {
	apply := func(start *bool, vals url.Values) settings.ChallengeConfig {
		t.Helper()
		r := httptest.NewRequest("POST", "/unmask/admin/settings/save?section=challenge", strings.NewReader(vals.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		cur := settings.ChallengeConfig{}
		cur.Default.ChallengePageGzip = start
		if err := applyChallengeFormV2(&cur, r); err != nil {
			t.Fatalf("applyChallengeFormV2: %v", err)
		}
		return cur
	}

	// Unticked: the operator's "leave it to nginx".
	cur := apply(nil, url.Values{"challenge_page_gzip_present": {"1"}})
	if p := cur.Default.ChallengePageGzip; p == nil || *p || cur.Default.IsChallengePageGzip() {
		t.Fatalf("the unticked box did not turn the daemon's compression off: %v", p)
	}
	// Ticked, on a record that had it off: on again, and nothing written.
	cur = apply(settings.BoolPtr(false), url.Values{"challenge_page_gzip_present": {"1"}, "challenge_page_gzip": {"1"}})
	if cur.Default.ChallengePageGzip != nil || !cur.Default.IsChallengePageGzip() {
		t.Fatalf("the ticked box did not go back to unset: %v", cur.Default.ChallengePageGzip)
	}
	// Ticked and never set: a save that touches nothing writes nothing.
	cur = apply(nil, url.Values{"challenge_page_gzip_present": {"1"}, "challenge_page_gzip": {"1"}})
	if cur.Default.ChallengePageGzip != nil {
		t.Fatal("a save with the box as it came wrote challenge_page_gzip: true")
	}
	// A form that does not carry the box: the stored answer stays.
	cur = apply(settings.BoolPtr(false), url.Values{})
	if p := cur.Default.ChallengePageGzip; p == nil || *p {
		t.Fatal("a form without the box changed the stored answer")
	}
}
