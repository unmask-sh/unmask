package settings

import (
	"fmt"
	"log"
)

// PassWindowIssue: what a per-pass figure below its window's minutes runs as,
// for a config file edited by hand or by a configuration manager -- the
// settings page refuses the pair (PassWindowErr).  "" when the pair stands,
// or the cap is off and renders nothing.
//
// Nothing breaks: nginx is given the figure as the burst and its smallest
// rate, one request a minute, so a pass's budget comes back faster than the
// file says and an operator who wrote "30 every 60 minutes" would go on
// believing it took.
func (c ReuseLimitConfig) PassWindowIssue() string {
	if c.Disabled || c.PassWindowErr() == nil {
		return ""
	}
	n, m := c.ResolvedPassRequests(), c.ResolvedPassMinutes()
	return fmt.Sprintf("rate_limit.reuse gives one pass %d requests every %d minutes, less than the one request a minute "+
		"nginx refills at the least: it runs as %d at once and one back a minute (%d every %d minutes)", n, m, n, n, n)
}

// warnReusePassWindow logs PassWindowIssue, once per load of a config file.
func warnReusePassWindow(resolved string, s Settings) {
	if is := s.RateLimit.Reuse.PassWindowIssue(); is != "" {
		log.Printf("unmask: config %s: %s. Set pass_requests to at least pass_minutes, or shorten the window, to silence this.", resolved, is)
	}
}
