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
	var zero ReuseLimitConfig
	if zero.ResolvedBurst() != ReuseSeedBurst || zero.ResolvedPerDay() != ReuseSeedPerDay {
		t.Errorf("blank fields should take the seeds, got %d / %d", zero.ResolvedPerDay(), zero.ResolvedBurst())
	}
	if zero.ResolvedAction() != RateChallengeCaptchaOnly {
		t.Errorf("default action = %q, want captcha_only", zero.ResolvedAction())
	}
	if (ReuseLimitConfig{Action: "pow_only"}).ResolvedAction() != RateChallengeCaptchaOnly {
		t.Error("an action a pass holder could meet with a PoW must resolve to captcha_only")
	}
	if !zero.IsZero() || (ReuseLimitConfig{Burst: 1}).IsZero() {
		t.Error("IsZero must hold only for an untouched cap")
	}
}
