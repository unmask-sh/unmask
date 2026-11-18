package settings

import "testing"

// nginx takes a rate per minute: the per-day budget is rounded up, so the cap
// never undercounts what the operator allowed; blank fields take the seeds.
func TestReuseLimitResolve(t *testing.T) {
	for _, c := range []struct {
		perDay, wantRate int
	}{
		{0, 7}, // the seed, 10,000 a day
		{10000, 7},
		{1440, 1},
		{1441, 2},
		{2880, 2},
	} {
		if got := (ReuseLimitConfig{PerDay: c.perDay}).RatePerMin(); got != c.wantRate {
			t.Errorf("PerDay %d -> %d r/m, want %d", c.perDay, got, c.wantRate)
		}
	}
	// The per-pass tier the same way: the figure over its window's minutes,
	// rounded up to whole requests a minute.  A blank window is an hour, so
	// a config that never set one renders what it always did.
	for _, c := range []struct {
		requests, minutes, wantRate int
	}{
		{0, 0, 9}, // the seeds, 500 every 60 minutes
		{500, 0, 9},
		{500, 60, 9},
		{60, 0, 1},
		{61, 0, 2},
		{120, 0, 2},
		{0, 5, 100}, // the seed figure over five minutes
		{300, 5, 60},
		{30, 5, 6},
		{31, 5, 7},
		{100, 1, 100},
		{1, 1, 1},
		{1440, 1440, 1},
		{1441, 1440, 2},
	} {
		if got := (ReuseLimitConfig{PassRequests: c.requests, PassMinutes: c.minutes}).PassRatePerMin(); got != c.wantRate {
			t.Errorf("%d every %d minutes -> %d r/m, want %d", c.requests, c.minutes, got, c.wantRate)
		}
	}
	var zero ReuseLimitConfig
	if zero.ResolvedBurst() != ReuseSeedBurst || zero.ResolvedPerDay() != ReuseSeedPerDay {
		t.Errorf("blank fields should take the seeds, got %d / %d", zero.ResolvedPerDay(), zero.ResolvedBurst())
	}
	if zero.ResolvedPassRequests() != ReusePassSeedRequests || (ReuseLimitConfig{PassRequests: 300}).ResolvedPassRequests() != 300 {
		t.Errorf("per pass: blank should take the seed and a figure should stand, got %d", zero.ResolvedPassRequests())
	}
	if zero.ResolvedPassMinutes() != ReusePassSeedMinutes || (ReuseLimitConfig{PassMinutes: 5}).ResolvedPassMinutes() != 5 {
		t.Errorf("per pass: a blank window should be the seed and a set one should stand, got %d", zero.ResolvedPassMinutes())
	}
	// The figure is at least its window's minutes, blank fields at their
	// seeds: below that nginx's one request a minute would refill it faster
	// than the setting says.
	for _, c := range []struct {
		requests, minutes int
		ok                bool
	}{
		{0, 0, true},    // 500 every 60
		{60, 0, true},   // 60 every 60: one a minute
		{59, 0, false},  // 59 every 60
		{30, 5, true},   // the short window a burst is caught with
		{4, 5, false},   // less than one a minute
		{0, 500, true},  // 500 every 500
		{0, 501, false}, // the seed figure under a longer window
		{1440, 1440, true},
		{1, 1, true},
	} {
		err := (ReuseLimitConfig{PassRequests: c.requests, PassMinutes: c.minutes}).PassWindowErr()
		if (err == nil) != c.ok {
			t.Errorf("%d every %d minutes: err = %v, want ok = %v", c.requests, c.minutes, err, c.ok)
		}
	}
	if zero.ResolvedAction() != RateChallengeCaptchaOnly {
		t.Errorf("default action = %q, want captcha_only", zero.ResolvedAction())
	}
	if (ReuseLimitConfig{Action: "pow_only"}).ResolvedAction() != RateChallengeCaptchaOnly {
		t.Error("an action a pass holder could meet with a PoW must resolve to captcha_only")
	}
	if !zero.IsZero() || (ReuseLimitConfig{Burst: 1}).IsZero() || (ReuseLimitConfig{PassRequests: 1}).IsZero() ||
		(ReuseLimitConfig{PassMinutes: 1}).IsZero() {
		t.Error("IsZero must hold only for an untouched cap")
	}
}
