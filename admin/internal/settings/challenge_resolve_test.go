package settings

import "testing"

// Challenge.Resolve: scalar per-site overrides merge field-by-field on top of
// the default; sites without an override entry get the default unchanged; a
// zero-value field in an override slot inherits the default (= empty Theme /
// PowDifficulty == 0 / ShowCreditSet == false).  The returned value never
// carries the Overrides map -- callers must not re-resolve.
func TestChallengeResolve(t *testing.T) {
	base := Challenge{
		CookieSeconds:             86400 * 3,
		PowCookieValidSeconds:     86400 * 3,
		CaptchaCookieValidSeconds: 86400 * 7,
		DebugRateLimitPer5Min:     20,
		Theme:                     "default",
		PowDifficulty:             18,
		ShowCredit:                false,
		CaptchaProvider: Captcha{
			Provider:              "builtin",
			BuiltinScoreThreshold: 0.5,
		},
		Overrides: map[string]ChallengeOverride{
			"shop.example.com": {
				Theme:         "cat",
				PowDifficulty: 20,
				// ShowCreditSet false -> inherit ShowCredit
			},
			"blog.example.com": {
				// Theme empty -> inherit
				ShowCredit:    true,
				ShowCreditSet: true,
			},
			"empty.example.com": {}, // every field zero -> inherit all
			"creditoff.example.com": {
				ShowCredit:    false,
				ShowCreditSet: true,
			},
		},
	}

	cases := []struct {
		name              string
		site              string
		wantTheme         string
		wantPow           int
		wantShowCredit    bool
	}{
		{name: "no site -> default", site: "", wantTheme: "default", wantPow: 18, wantShowCredit: false},
		{name: "undeclared site -> default", site: "api.example.com", wantTheme: "default", wantPow: 18, wantShowCredit: false},
		{name: "shop override -> theme + pow merge, credit inherit", site: "shop.example.com", wantTheme: "cat", wantPow: 20, wantShowCredit: false},
		{name: "blog override -> theme inherit, credit explicit on", site: "blog.example.com", wantTheme: "default", wantPow: 18, wantShowCredit: true},
		{name: "empty override entry -> default", site: "empty.example.com", wantTheme: "default", wantPow: 18, wantShowCredit: false},
		{name: "explicit credit off with ShowCreditSet -> off", site: "creditoff.example.com", wantTheme: "default", wantPow: 18, wantShowCredit: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := base.Resolve(tc.site)
			if got.Theme != tc.wantTheme {
				t.Errorf("Theme = %q, want %q", got.Theme, tc.wantTheme)
			}
			if got.PowDifficulty != tc.wantPow {
				t.Errorf("PowDifficulty = %d, want %d", got.PowDifficulty, tc.wantPow)
			}
			if got.ShowCredit != tc.wantShowCredit {
				t.Errorf("ShowCredit = %t, want %t", got.ShowCredit, tc.wantShowCredit)
			}
			if got.Overrides != nil {
				t.Errorf("Overrides leaked into resolved value")
			}
			// Install-wide fields must always survive resolution untouched.
			if got.CookieSeconds != base.CookieSeconds {
				t.Errorf("CookieSeconds inherited unexpectedly: got %d want %d", got.CookieSeconds, base.CookieSeconds)
			}
			if got.CaptchaProvider.Provider != base.CaptchaProvider.Provider {
				t.Errorf("CaptchaProvider should be inherited unchanged")
			}
		})
	}
}

// ShowCreditSet pointer-like distinction: the bool override must honour the
// Set flag so a site that explicitly wants ShowCredit=false can override a
// default of true (and vice versa).
func TestChallengeResolveShowCreditSetFlag(t *testing.T) {
	base := Challenge{ShowCredit: true}
	base.Overrides = map[string]ChallengeOverride{
		"setfalse.example.com": {ShowCredit: false, ShowCreditSet: true},
		"unset.example.com":    {ShowCredit: false}, // Set=false -> inherit
	}
	if got := base.Resolve("setfalse.example.com").ShowCredit; got != false {
		t.Errorf("setfalse: got %t want false", got)
	}
	if got := base.Resolve("unset.example.com").ShowCredit; got != true {
		t.Errorf("unset: got %t want true (inherited)", got)
	}
}
