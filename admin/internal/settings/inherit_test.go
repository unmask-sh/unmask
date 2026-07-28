package settings

import "testing"

// TestSparsifyStoresOnlyDifferences: the per-site form submits every field, so
// without this a save would write a complete copy of Default and the record
// would stop tracking it -- the exact freeze per-field inheritance exists to
// end.  Only what genuinely differs may reach the file.
func TestSparsifyStoresOnlyDifferences(t *testing.T) {
	def := ChallengeValues{
		PowCookieValidSeconds:     86400 * 7,
		CaptchaCookieValidSeconds: 86400 * 14,
		DebugRateLimitPer5Min:     20,
		PowDifficulty:             18,
		PublicTestPages:           BoolPtr(true),
		CaptchaProvider:           Captcha{Provider: "builtin", BuiltinScoreThreshold: 0.5},
	}
	// What a form round-trip produces: every field filled in with the resolved
	// value, one of them changed.
	submitted := def
	submitted.PowDifficulty = 22

	got := SparsifyChallenge(submitted, def)
	if got.PowDifficulty != 22 {
		t.Errorf("the changed field was stripped: %d", got.PowDifficulty)
	}
	for name, v := range map[string]int{
		"pow_cookie_valid_seconds":     got.PowCookieValidSeconds,
		"captcha_cookie_valid_seconds": got.CaptchaCookieValidSeconds,
		"debug_rate_limit_per_5min":    got.DebugRateLimitPer5Min,
	} {
		if v != 0 {
			t.Errorf("%s was stored despite matching Default (=%d)", name, v)
		}
	}
	if got.PublicTestPages != nil {
		t.Error("a flag matching Default was stored explicitly")
	}
	if got.CaptchaProvider != (Captcha{}) {
		t.Errorf("the captcha block matched Default but was stored: %+v", got.CaptchaProvider)
	}

	// And the round trip is faithful: what the operator sees is what they set.
	c := ChallengeConfig{Default: def, Sites: map[string]ChallengeValues{"s": got}}
	res := c.Resolve("s")
	if res.PowDifficulty != 22 || res.PowCookieValidSeconds != def.PowCookieValidSeconds {
		t.Errorf("resolve after sparsify lost values: %+v", res)
	}
}

// TestSparsifyKeepsExplicitFalse: turning a flag off for one site while the
// global has it on is a real override, and the one case a plain bool could not
// express.  It must survive the strip.
func TestSparsifyKeepsExplicitFalse(t *testing.T) {
	def := ChallengeValues{PublicTestPages: BoolPtr(true)}
	got := SparsifyChallenge(ChallengeValues{PublicTestPages: BoolPtr(false)}, def)
	if got.PublicTestPages == nil {
		t.Fatal("an explicit off was stripped and will inherit the global on")
	}
	c := ChallengeConfig{Default: def, Sites: map[string]ChallengeValues{"s": got}}
	if c.Resolve("s").IsPublicTestPages() {
		t.Error("the site ended up with public test pages on after asking for off")
	}
}

// TestSparsifySkipsDisabledRecords: Disabled means "inherit for now, remember
// my values".  Stripping the values of a disabled record would delete exactly
// what the operator is being promised will come back.
func TestSparsifySkipsDisabledRecords(t *testing.T) {
	def := ChallengeValues{PowDifficulty: 18}
	v := ChallengeValues{PowDifficulty: 18, CaptchaCookieValidSeconds: 999, Disabled: true}
	got := SparsifyChallenge(v, def)
	if got.PowDifficulty != 18 || got.CaptchaCookieValidSeconds != 999 {
		t.Errorf("a disabled record lost its remembered values: %+v", got)
	}
}

// TestBrandingSparsifyAndMerge: same contract on the appearance record -- a
// site that only wants its own logo keeps inheriting the operator's copy
// preset, rather than freezing a copy of it.
func TestBrandingSparsifyAndMerge(t *testing.T) {
	def := BrandingValues{
		SiteName:   "MyCo",
		CopyPreset: BrandingPresetFriendly,
		Theme:      "auto",
		ShowCredit: BoolPtr(true),
	}
	submitted := def
	submitted.LogoPath = "/etc/unmask/shop.svg"

	got := SparsifyBranding(submitted, def)
	if got.LogoPath != "/etc/unmask/shop.svg" {
		t.Errorf("the changed field was stripped: %q", got.LogoPath)
	}
	if got.SiteName != "" || got.CopyPreset != "" || got.Theme != "" || got.ShowCredit != nil {
		t.Errorf("fields matching Default were stored: %+v", got)
	}

	b := Branding{Default: def, Sites: map[string]BrandingValues{"s": got}}
	res := b.Resolve("s")
	if res.LogoPath != "/etc/unmask/shop.svg" || res.SiteName != "MyCo" || !res.IsShowCredit() {
		t.Errorf("resolve after sparsify: %+v", res)
	}
	// Moving the global reaches the site, which is the whole point.
	b.Default.CopyPreset = BrandingPresetMinimal
	if b.Resolve("s").CopyPreset != BrandingPresetMinimal {
		t.Error("a Default change did not reach a site that overrides a different field")
	}
}

// TestOverridesForReportsWhatIsSet: the settings page marks fields as inherited
// from this map, so a wrong answer here mislabels the form.
func TestOverridesForReportsWhatIsSet(t *testing.T) {
	c := ChallengeConfig{
		Default: ChallengeValues{PowDifficulty: 18},
		Sites: map[string]ChallengeValues{
			"own":      {PowDifficulty: 22, ObserveOnly: BoolPtr(false)},
			"disabled": {PowDifficulty: 22, Disabled: true},
		},
	}
	own := ChallengeOverridesFor(c, "own")
	if !own["pow_difficulty"] {
		t.Error("a set int is not reported as an override")
	}
	// An explicit false is a decision, not silence.
	if !own["observe_only"] {
		t.Error("an explicitly-false flag is not reported as an override")
	}
	if own["captcha_cookie_valid_seconds"] {
		t.Error("an unset field is reported as an override")
	}
	// A disabled record is not applied, so nothing on it is live.
	for k, v := range ChallengeOverridesFor(c, "disabled") {
		if v {
			t.Errorf("disabled record reports %q as active", k)
		}
	}
	// A site with no record at all overrides nothing.
	if len(ChallengeOverridesFor(c, "absent")) != 0 {
		t.Error("a site with no record reported overrides")
	}
}

// TestNormalizeDefaultsKeepsSiteFalse: Save normalizes an explicit false to
// unset on Default (nothing sits above it, and persisting the pointer would
// rewrite the file on every save).  It must not touch site records, where false
// is the override.
func TestNormalizeDefaultsKeepsSiteFalse(t *testing.T) {
	s := Settings{}
	s.Challenge.Default.PublicTestPages = BoolPtr(false)
	s.Challenge.Sites = map[string]ChallengeValues{
		"s": {PublicTestPages: BoolPtr(false)},
	}
	s.Branding.Default.ShowCredit = BoolPtr(false)

	normalizeDefaults(&s)

	if s.Challenge.Default.PublicTestPages != nil || s.Branding.Default.ShowCredit != nil {
		t.Error("an explicit false survived on a Default record and will churn the file")
	}
	if s.Challenge.Sites["s"].PublicTestPages == nil {
		t.Fatal("a site's explicit off was normalized away; it would inherit the global")
	}
}
