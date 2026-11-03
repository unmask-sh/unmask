package notifier

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// The mark is one table for the list and the hooks.
func TestSeverity(t *testing.T) {
	cases := []struct {
		event  string
		fields map[string]any
		want   string
	}{
		{EventBanCreated, nil, SeverityInfo},
		{EventAdvisorDigest, nil, SeverityInfo},
		{EventChallengeBurst, nil, SeverityWarn},
		{EventPreviewChallenged, nil, SeverityWarn},
		{EventOverBlock, map[string]any{"tripped": true}, SeverityCrit},
		{EventOverBlock, map[string]any{"tripped": false}, SeverityInfo},
		{EventNativeFailsafe, map[string]any{"active": true}, SeverityCrit},
		{EventNativeFailsafe, map[string]any{"active": false}, SeverityInfo},
		{EventLoopPanic, map[string]any{"consecutive": 1}, SeverityWarn},
		{EventLoopPanic, map[string]any{"consecutive": 3}, SeverityCrit},
		{"something_else", nil, SeverityInfo},
	}
	for _, c := range cases {
		if got := Severity(c.event, c.fields); got != c.want {
			t.Errorf("Severity(%s, %v) = %s, want %s", c.event, c.fields, got, c.want)
		}
	}
}

// hookFor: with no critical hook URL takes everything; with one, the critical
// alerts go there and the rest to URL, which may be empty; the floor at warn
// moves the warnings over; the breaker's clearing follows its trip; the pause
// stops both; and each hook is posted in its own format -- the critical one
// in the first hook's when it names none.
func TestHookForRoutesBySeverity(t *testing.T) {
	trip := map[string]any{"tripped": true}
	cleared := map[string]any{"tripped": false}
	one := Config{URL: "info", Format: FormatSlack}
	two := Config{URL: "info", CriticalURL: "crit", Format: FormatSlack}
	twoWarn := Config{URL: "info", CriticalURL: "crit", Format: FormatSlack, CriticalMinSeverity: SeverityWarn}
	twoFormats := Config{URL: "info", CriticalURL: "crit", Format: FormatSlack, CriticalFormat: FormatDiscord}
	critOnly := Config{CriticalURL: "crit", Format: FormatGeneric}
	paused := Config{URL: "info", CriticalURL: "crit", Format: FormatSlack, WebhookDisabled: true}
	cases := []struct {
		name       string
		cfg        Config
		event      string
		fields     map[string]any
		want       string
		wantFormat string
	}{
		{"one hook, a ban", one, EventBanCreated, nil, "info", FormatSlack},
		{"one hook, the trip", one, EventOverBlock, trip, "info", FormatSlack},
		{"two hooks, a ban", two, EventBanCreated, nil, "info", FormatSlack},
		{"two hooks, the digest", two, EventAdvisorDigest, nil, "info", FormatSlack},
		{"two hooks, a burst stays with the floor at crit", two, EventChallengeBurst, nil, "info", FormatSlack},
		{"two hooks, previews stopped stay", two, EventPreviewChallenged, nil, "info", FormatSlack},
		{"two hooks, the trip", two, EventOverBlock, trip, "crit", FormatSlack},
		{"two hooks, the clearing follows the trip", two, EventOverBlock, cleared, "crit", FormatSlack},
		{"floor at warn, a burst", twoWarn, EventChallengeBurst, nil, "crit", FormatSlack},
		{"floor at warn, previews stopped", twoWarn, EventPreviewChallenged, nil, "crit", FormatSlack},
		{"floor at warn, a ban stays", twoWarn, EventBanCreated, nil, "info", FormatSlack},
		{"two formats, the trip in the critical hook's", twoFormats, EventOverBlock, trip, "crit", FormatDiscord},
		{"two formats, the clearing in the critical hook's", twoFormats, EventOverBlock, cleared, "crit", FormatDiscord},
		{"two formats, a ban in the first hook's", twoFormats, EventBanCreated, nil, "info", FormatSlack},
		{"critical hook alone, a ban goes nowhere", critOnly, EventBanCreated, nil, "", ""},
		{"critical hook alone, the trip", critOnly, EventOverBlock, trip, "crit", FormatGeneric},
		{"paused", paused, EventOverBlock, trip, "", ""},
	}
	for _, c := range cases {
		got, format := c.cfg.hookFor(c.event, c.fields)
		if got != c.want || format != c.wantFormat {
			t.Errorf("%s: hookFor = %q in %q, want %q in %q", c.name, got, format, c.want, c.wantFormat)
		}
	}
}

// Two live hooks: the breaker's trip lands on the critical one with its
// severity in the generic payload, a ban on the other, and neither hook sees
// the other's alert.
func TestCriticalHookGetsTheCriticalAlerts(t *testing.T) {
	type post struct{ event, severity string }
	hook := func() (*httptest.Server, chan post) {
		got := make(chan post, 4)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			var m map[string]any
			_ = json.Unmarshal(b, &m)
			ev, _ := m["event"].(string)
			sev, _ := m["severity"].(string)
			got <- post{ev, sev}
		}))
		return srv, got
	}
	first, firstGot := hook()
	defer first.Close()
	critical, criticalGot := hook()
	defer critical.Close()
	n := New(Config{URL: first.URL, CriticalURL: critical.URL, Format: FormatGeneric, BanEvents: true})
	n.OverBlock(tripReport)
	n.BanCreated("203.0.113.7", "t13d", "honeypot", "hit /wp-login.php", "")
	want := func(ch chan post, what string, p post) {
		t.Helper()
		select {
		case got := <-ch:
			if got != p {
				t.Errorf("%s: got %+v, want %+v", what, got, p)
			}
		case <-time.After(2 * time.Second):
			t.Errorf("%s did not arrive", what)
		}
	}
	want(criticalGot, "the trip on the critical hook", post{EventOverBlock, SeverityCrit})
	want(firstGot, "the ban on the first hook", post{EventBanCreated, SeverityInfo})
	for _, ch := range []chan post{firstGot, criticalGot} {
		select {
		case p := <-ch:
			t.Errorf("a hook got a second alert: %+v", p)
		case <-time.After(150 * time.Millisecond):
		}
	}
}

// Two live hooks on different services: the critical one is a Discord and
// gets the trip as a Discord body (content, no event), the first keeps the
// generic payload for the ban.
func TestCriticalHookPostsInItsOwnFormat(t *testing.T) {
	type post struct {
		event   string
		content bool
	}
	hook := func() (*httptest.Server, chan post) {
		got := make(chan post, 4)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			var m map[string]any
			_ = json.Unmarshal(b, &m)
			ev, _ := m["event"].(string)
			_, content := m["content"].(string)
			got <- post{ev, content}
		}))
		return srv, got
	}
	first, firstGot := hook()
	defer first.Close()
	critical, criticalGot := hook()
	defer critical.Close()
	n := New(Config{URL: first.URL, CriticalURL: critical.URL, Format: FormatGeneric, CriticalFormat: FormatDiscord, BanEvents: true})
	n.OverBlock(tripReport)
	n.BanCreated("203.0.113.7", "t13d", "honeypot", "hit /wp-login.php", "")
	want := func(ch chan post, what string, p post) {
		t.Helper()
		select {
		case got := <-ch:
			if got != p {
				t.Errorf("%s: got %+v, want %+v", what, got, p)
			}
		case <-time.After(2 * time.Second):
			t.Errorf("%s did not arrive", what)
		}
	}
	want(criticalGot, "the trip on the critical hook, as a Discord body", post{"", true})
	want(firstGot, "the ban on the first hook, generic", post{EventBanCreated, false})
}
