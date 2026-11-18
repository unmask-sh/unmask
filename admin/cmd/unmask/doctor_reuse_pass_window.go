package main

import (
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// checkReusePassWindow: the reuse cap's per-pass budget is so many requests
// every so many minutes, and nginx refills a zone by one request a minute at
// the least.  A figure below its window's minutes written into config.yml is
// rendered with that smallest rate, so the budget comes back faster than the
// file says -- nothing breaks and nothing shows.  The settings page refuses
// such a pair; this is for the file edited by hand or by a configuration
// manager.  A pair that stands, or a cap that is off, is silent.
func checkReusePassWindow(s settings.Settings, addWarn func(t, m string)) {
	if is := s.RateLimit.Reuse.PassWindowIssue(); is != "" {
		addWarn("reuse cap per-pass window", is+". Set pass_requests to at least pass_minutes, or shorten the window.")
	}
}
