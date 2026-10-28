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
		{"native_failsafe", map[string]any{"active": true}, SeverityInfo},
	}
	for _, c := range cases {
		if got := Severity(c.event, c.fields); got != c.want {
			t.Errorf("Severity(%s, %v) = %s, want %s", c.event, c.fields, got, c.want)
		}
	}
}

// hookFor: with no critical hook URL takes everything; with one, the critical
// alerts go there and the rest to URL, which may be empty; the floor at warn
// moves the warnings over; the breaker's clearing follows its trip; and the
// pause stops both.
func TestHookForRoutesBySeverity(t *testing.T) {
	trip := map[string]any{"tripped": true}
	cleared := map[string]any{"tripped": false}
	one := Config{URL: "info"}
	two := Config{URL: "info", CriticalURL: "crit"}
	twoWarn := Config{URL: "info", CriticalURL: "crit", CriticalMinSeverity: SeverityWarn}
	critOnly := Config{CriticalURL: "crit"}
	paused := Config{URL: "info", CriticalURL: "crit", WebhookDisabled: true}
	cases := []struct {
		name   string
		cfg    Config
		event  string
		fields map[string]any
		want   string
	}{
		{"one hook, a ban", one, EventBanCreated, nil, "info"},
		{"one hook, the trip", one, EventOverBlock, trip, "info"},
		{"two hooks, a ban", two, EventBanCreated, nil, "info"},
		{"two hooks, the digest", two, EventAdvisorDigest, nil, "info"},
		{"two hooks, a burst stays with the floor at crit", two, EventChallengeBurst, nil, "info"},
		{"two hooks, previews stopped stay", two, EventPreviewChallenged, nil, "info"},
		{"two hooks, the trip", two, EventOverBlock, trip, "crit"},
		{"two hooks, the clearing follows the trip", two, EventOverBlock, cleared, "crit"},
		{"floor at warn, a burst", twoWarn, EventChallengeBurst, nil, "crit"},
		{"floor at warn, previews stopped", twoWarn, EventPreviewChallenged, nil, "crit"},
		{"floor at warn, a ban stays", twoWarn, EventBanCreated, nil, "info"},
		{"critical hook alone, a ban goes nowhere", critOnly, EventBanCreated, nil, ""},
		{"critical hook alone, the trip", critOnly, EventOverBlock, trip, "crit"},
		{"paused", paused, EventOverBlock, trip, ""},
	}
	for _, c := range cases {
		if got := c.cfg.hookFor(c.event, c.fields); got != c.want {
			t.Errorf("%s: hookFor = %q, want %q", c.name, got, c.want)
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
