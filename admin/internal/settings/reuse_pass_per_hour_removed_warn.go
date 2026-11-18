package settings

import (
	"log"

	"gopkg.in/yaml.v3"
)

// warnRemovedReusePassPerHour: `rate_limit.reuse.pass_per_hour` was one
// pass's budget from 0.1.53, with the hour built in.  0.1.58 lets the window
// be set, so the budget is two keys: pass_requests, refilled every
// pass_minutes (60 unless set).
//
// The old key is ignored, so an install that wrote a figure of its own is
// back at the seed -- tighter than it asked for where the figure was raised
// for a site whose pages call an API many times a minute, looser where it was
// lowered.  The generic unknown-key line would read as harmless; name the key,
// the figure it held, and the line that puts it back.
func warnRemovedReusePassPerHour(resolved string, raw []byte) {
	var probe struct {
		RateLimit struct {
			Reuse struct {
				PassPerHour *int `yaml:"pass_per_hour"`
			} `yaml:"reuse"`
		} `yaml:"rate_limit"`
	}
	if yaml.Unmarshal(raw, &probe) != nil || probe.RateLimit.Reuse.PassPerHour == nil {
		return
	}
	n := *probe.RateLimit.Reuse.PassPerHour
	log.Printf("unmask: config %s still carries rate_limit.reuse.pass_per_hour: %d -- REMOVED in 0.1.58 and ignored: "+
		"one pass's budget is rate_limit.reuse.pass_requests now, refilled every pass_minutes (60 unless set), and it "+
		"runs at the default %d every %d minutes until the figure is written there (pass_requests: %d keeps what this "+
		"install had). Delete the old key to silence this.",
		resolved, n, ReusePassSeedRequests, ReusePassSeedMinutes, n)
}
