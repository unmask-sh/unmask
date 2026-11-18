package main

import (
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// A per-pass figure below its window's minutes is one WARN saying what the
// pair runs as; a pair that stands, the seeds, and a cap that is off are
// silent.
func TestCheckReusePassWindow(t *testing.T) {
	for _, ru := range []settings.ReuseLimitConfig{
		{},
		{PassRequests: 300, PassMinutes: 5},
		{PassRequests: 60},
		{PassRequests: 30, Disabled: true},
	} {
		s := settings.Settings{}
		s.RateLimit.Reuse = ru
		got, _, addWarn, _ := newCaptures()
		checkReusePassWindow(s, addWarn)
		if len(got.warn) != 0 {
			t.Errorf("%+v: %+v, want silence", ru, got)
		}
	}

	s := settings.Settings{}
	s.RateLimit.Reuse = settings.ReuseLimitConfig{PassRequests: 30}
	got, _, addWarn, _ := newCaptures()
	checkReusePassWindow(s, addWarn)
	if len(got.warn) != 1 {
		t.Fatalf("30 every 60 minutes: %+v, want one warning", got)
	}
	for _, w := range []string{"reuse cap per-pass window", "30 requests every 60 minutes", "30 at once and one back a minute", "pass_requests to at least pass_minutes"} {
		if !strings.Contains(got.warn[0], w) {
			t.Errorf("the warning must carry %q, got: %s", w, got.warn[0])
		}
	}
	if len(got.ok)+len(got.err) != 0 {
		t.Errorf("only a warning comes out of this check: %+v", got)
	}
}
