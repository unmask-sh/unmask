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
	def.LogoHeight = 48
	submitted := def
	submitted.LogoPath = "/etc/unmask/shop.svg"
	submitted.LogoHeight = 64

	got := SparsifyBranding(submitted, def)
	if got.LogoPath != "/etc/unmask/shop.svg" || got.LogoHeight != 64 {
		t.Errorf("the changed fields were stripped: %+v", got)
	}
	if got.SiteName != "" || got.CopyPreset != "" || got.Theme != "" || got.ShowCredit != nil {
		t.Errorf("fields matching Default were stored: %+v", got)
	}
	same := def
	if s := SparsifyBranding(same, def); s.LogoHeight != 0 {
		t.Errorf("a logo height equal to Default was stored: %d", s.LogoHeight)
	}

	b := Branding{Default: def, Sites: map[string]BrandingValues{"s": got}}
	res := b.Resolve("s")
	if res.LogoPath != "/etc/unmask/shop.svg" || res.LogoHeight != 64 || res.SiteName != "MyCo" || !res.IsShowCredit() {
		t.Errorf("resolve after sparsify: %+v", res)
	}
	// Keyed by the names the form's fields carry: the page looks each field
	// up by its name.
	if ov := BrandingOverridesFor(b, "s"); !ov["branding_logo_height"] || !ov["branding_logo_file"] || ov["branding_site_name"] {
		t.Errorf("overrides map: %v", ov)
	}
	// A site that leaves the height unset inherits Default's.
	b.Sites["t"] = BrandingValues{SiteName: "Other"}
	if h := b.Resolve("t").LogoHeight; h != 48 {
		t.Errorf("unset site height did not inherit Default: %d", h)
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

// How the page is shown is a site's to set like the rest.  The four fields
// were stored on the site's record and left out of the merge: the form showed
// "invisible" selected for the site and the site got Default's page.
func TestDisplayFieldsFollowTheSite(t *testing.T) {
	zero, fade := 0, 50
	c := ChallengeConfig{
		Default: ChallengeValues{},
		Sites: map[string]ChallengeValues{
			"s": {DisplayStyle: ChallengeDisplayInvisible, MinDisplayMS: &zero, InvisibleRevealMS: 3000, RevealFadeMS: &fade},
			"t": {PowDifficulty: 20},
		},
	}
	got := c.Resolve("s")
	if got.ResolvedDisplayStyle() != ChallengeDisplayInvisible || got.ResolvedMinDisplayMS() != 0 || got.ResolvedInvisibleRevealMS() != 3000 || got.ResolvedRevealFadeMS() != 50 {
		t.Errorf("the site's display settings are not what the site gets: style=%s min=%d reveal=%d fade=%d",
			got.ResolvedDisplayStyle(), got.ResolvedMinDisplayMS(), got.ResolvedInvisibleRevealMS(), got.ResolvedRevealFadeMS())
	}
	ov := ChallengeOverridesFor(c, "s")
	for _, k := range []string{"challenge_display_style", "min_display_ms", "invisible_reveal_ms", "reveal_fade_ms"} {
		if !ov[k] {
			t.Errorf("%s, which the site sets, is not reported as its own", k)
		}
	}
	// A site that sets something else follows Default in these, also after
	// Default moves.
	c.Default.DisplayStyle = ChallengeDisplayInvisible
	c.Default.InvisibleRevealMS = 2000
	if got := c.Resolve("t"); got.ResolvedDisplayStyle() != ChallengeDisplayInvisible || got.ResolvedInvisibleRevealMS() != 2000 || got.PowDifficulty != 20 {
		t.Errorf("a site that set only its difficulty: style=%s reveal=%d difficulty=%d", got.ResolvedDisplayStyle(), got.ResolvedInvisibleRevealMS(), got.PowDifficulty)
	}
	// And under an invisible Default a site can be given the visible page:
	// said outright, since unset would inherit.
	c.Sites["v"] = SparsifyChallenge(ChallengeValues{DisplayStyle: ChallengeDisplayVisible}, c.Default)
	if c.Sites["v"].DisplayStyle != ChallengeDisplayVisible || c.Resolve("v").ResolvedDisplayStyle() != ChallengeDisplayVisible {
		t.Errorf("the visible page for a site under an invisible Default: stored %q, the site gets %s", c.Sites["v"].DisplayStyle, c.Resolve("v").ResolvedDisplayStyle())
	}
}

// What matches Default is decided by what a value comes to.  The form states
// the built-in values outright -- a seven-day cookie, "friendly", "auto", an
// unticked box -- and a Default that leaves the field unset comes to the same:
// compared as written the two differed, and the first save of a site's form
// stored the built-in value for the site, which stayed when Default was given
// another.
func TestSparsifyComparesWhatTheValuesComeTo(t *testing.T) {
	min, fade := 800, 200
	got := SparsifyChallenge(ChallengeValues{
		PowCookieValidSeconds:     86400 * 7,
		CaptchaCookieValidSeconds: 86400 * 14,
		PowDifficulty:             PowDifficultyDefault,
		DisplayStyle:              ChallengeDisplayVisible,
		MinDisplayMS:              &min,
		InvisibleRevealMS:         1200,
		RevealFadeMS:              &fade,
		PublicTestPages:           BoolPtr(false),
		PublicTestPagesSitePicker: BoolPtr(true),
	}, ChallengeValues{})
	if got.PowCookieValidSeconds != 0 || got.CaptchaCookieValidSeconds != 0 || got.PowDifficulty != 0 || got.DisplayStyle != "" ||
		got.MinDisplayMS != nil || got.InvisibleRevealMS != 0 || got.RevealFadeMS != nil || got.PublicTestPages != nil || got.PublicTestPagesSitePicker != nil {
		t.Errorf("the built-in values, stated outright, were stored over a Default that says nothing: %+v", got)
	}
	b := SparsifyBranding(BrandingValues{
		CopyPreset: BrandingPresetFriendly, Theme: "auto", ShowCredit: BoolPtr(false),
		DenyRateTheme: DenyThemeAuto, DenyRateCopyPreset: BrandingPresetFriendly,
		DenyBanTheme: DenyThemeAuto, DenyBanCopyPreset: BrandingPresetFriendly,
	}, BrandingValues{})
	if b.CopyPreset != "" || b.Theme != "" || b.ShowCredit != nil || b.DenyRateTheme != "" || b.DenyRateCopyPreset != "" || b.DenyBanTheme != "" || b.DenyBanCopyPreset != "" {
		t.Errorf("the built-in appearance values, stated outright, were stored over a Default that says nothing: %+v", b)
	}
	// Where Default says something else, the built-in value is the site's
	// own choice and stays.
	def := BrandingValues{CopyPreset: BrandingPresetNeutral, Theme: "dark", ShowCredit: BoolPtr(true), DenyRateTheme: DenyThemeDark}
	b = SparsifyBranding(BrandingValues{CopyPreset: BrandingPresetFriendly, Theme: "auto", ShowCredit: BoolPtr(false), DenyRateTheme: DenyThemeAuto}, def)
	if b.CopyPreset != BrandingPresetFriendly || b.Theme != "auto" || b.ShowCredit == nil || b.DenyRateTheme != DenyThemeAuto {
		t.Errorf("a site's choice of the built-in value under a Default that says another was stripped: %+v", b)
	}
	// A field the site leaves unset stays unset, whatever Default says: it
	// is not the built-in value stated, it is nothing stated.
	if got := SparsifyChallenge(ChallengeValues{}, ChallengeValues{PowCookieValidSeconds: 86400, PowDifficulty: 20, DisplayStyle: ChallengeDisplayInvisible}); got != (ChallengeValues{}) {
		t.Errorf("an empty record came out of Sparsify saying something: %+v", got)
	}
}

// Shown is what the site's form shows: the record over Default, in force or
// not.  Resolve is what the site gets.
func TestShownIsTheRecordOverDefaultInForceOrNot(t *testing.T) {
	c := ChallengeConfig{
		Default: ChallengeValues{PowCookieValidSeconds: 86400, PowDifficulty: 18},
		Sites: map[string]ChallengeValues{
			"on":  {PowDifficulty: 22},
			"off": {PowDifficulty: 22, Disabled: true},
		},
	}
	for _, site := range []string{"on", "off"} {
		if got := c.Shown(site); got.PowDifficulty != 22 || got.PowCookieValidSeconds != 86400 {
			t.Errorf("Shown(%s): difficulty=%d PoW cookie=%d, want the site's 22 over Default's 86400", site, got.PowDifficulty, got.PowCookieValidSeconds)
		}
	}
	if got := c.Resolve("off"); got.PowDifficulty != 18 {
		t.Errorf("a record that is off: the site gets difficulty %d, want Default's 18", got.PowDifficulty)
	}
	if got := c.Shown("absent"); got.PowDifficulty != 18 {
		t.Errorf("a site with no record is shown difficulty %d, want Default's 18", got.PowDifficulty)
	}
	b := Branding{
		Default: BrandingValues{SiteName: "MyCo", Theme: "dark"},
		Sites:   map[string]BrandingValues{"off": {Theme: "paper", Disabled: true}},
	}
	if got := b.Shown("off"); got.Theme != "paper" || got.SiteName != "MyCo" {
		t.Errorf("Shown of an appearance record that is off: theme=%q name=%q", got.Theme, got.SiteName)
	}
}
