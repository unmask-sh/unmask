package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
	_ "time/tzdata" // the zones below, wherever the test runs

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The answer's times are the operator's: the TZ picker's zone when one is
// set, else the browser's, sent with the question; a name that is not a zone
// is UTC.
func TestAskLocation(t *testing.T) {
	post := func(form url.Values, cookie string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/admin/ask/send", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if cookie != "" {
			r.AddCookie(&http.Cookie{Name: tzCookieName, Value: cookie})
		}
		return r
	}
	for _, c := range []struct {
		name, cookie, tz, want string
	}{
		{"picker", "Europe/London", "Asia/Tokyo", "Europe/London"},
		{"browser", "", "Asia/Tokyo", "Asia/Tokyo"},
		{"picker on browser", "browser", "America/New_York", "America/New_York"},
		{"not a zone", "", "../../etc/passwd", "UTC"},
		{"none", "", "", "UTC"},
	} {
		if got := askLocation(post(url.Values{"q": {"x"}, "tz": {c.tz}}, c.cookie)).String(); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
}

// The note set after the question carries the operator's clock and today's
// browser versions.
func TestAskContext(t *testing.T) {
	loc, err := time.LoadLocation("Asia/Tokyo")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 13, 17, 5, 0, 0, time.UTC)
	note := askContext(now, loc, settings.GlobalConfig{})
	for _, want := range []string{"Now: 2026-10-14 02:05 +09:00", "time zone Asia/Tokyo", "Chrome ", "Firefox "} {
		if !strings.Contains(note, want) {
			t.Errorf("note missing %q: %s", want, note)
		}
	}
}
