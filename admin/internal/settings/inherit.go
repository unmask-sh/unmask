package settings

// Per-field inheritance for the per-site records.
//
// A site record used to be inherited whole or owned whole: Resolve returned
// Sites[host] outright and never consulted Default.  Setting one knob for one
// site therefore detached that site from Default for every OTHER knob too, and
// silently: raising the global PoW difficulty afterwards skipped every site
// that had ever been given a per-site setting, with nothing in the UI saying
// so.  The settings page had to paper over this by seeding each new record with
// a full snapshot of Default, which is what froze the values in the first
// place.
//
// Now a record carries only what the operator actually set for that site, and
// Resolve lays it over Default field by field.  "Not set" is the Go zero for
// most fields -- an empty string, a nil map, a zero int that already meant
// "fall back" -- and an explicit pointer for the handful of bools where false
// is a real answer that must not read as silence.
//
// The save path (Sparsify) is the other half: it strips fields matching Default
// before storing, so a form that submits every field still produces a record
// that says only what differs.  Without it the merge would be correct but never
// exercised, since every save would write every field explicitly.

// BoolPtr returns a pointer to v, for setting an optional bool explicitly.
func BoolPtr(v bool) *bool { return &v }

// boolValue reads an optional bool, treating "not set" as false: after a merge
// a nil means neither the site nor Default said anything, and every one of
// these flags is off unless turned on.
func boolValue(p *bool) bool { return p != nil && *p }

// IsPublicTestPages / IsPublicTestPagesSitePicker / IsObserveOnly: read the
// optional flags without every caller having to nil-check.
func (c ChallengeValues) IsPublicTestPages() bool { return boolValue(c.PublicTestPages) }

// IsPublicTestPagesSitePicker: unset means ON, unlike the other flags here.
// The picker only ever renders when PublicTestPages is also on, and that one
// ships OFF -- so the operator turning the pages public is looking at this
// checkbox (already ticked) and the Basic Auth field in the same block.  With
// the decision point covered, the default favours a public test page that can
// actually exercise a per-site challenge instead of one that silently only
// tests the default site.
func (c ChallengeValues) IsPublicTestPagesSitePicker() bool {
	return c.PublicTestPagesSitePicker == nil || *c.PublicTestPagesSitePicker
}
func (c ChallengeValues) IsObserveOnly() bool { return boolValue(c.ObserveOnly) }

// IsShowCredit reports whether the challenge page shows the credit line.
func (b BrandingValues) IsShowCredit() bool { return boolValue(b.ShowCredit) }

// mergeChallenge lays a site's record over Default, field by field.  Only what
// the site actually set wins; everything else keeps tracking Default, so a
// later change to Default reaches the site.
//
// Disabled is not merged: it says whether this record applies at all, which is
// a property of the record and not a value to inherit.
func mergeChallenge(base, over ChallengeValues) ChallengeValues {
	out := base
	if over.PowCookieValidSeconds != 0 {
		out.PowCookieValidSeconds = over.PowCookieValidSeconds
	}
	if over.CaptchaCookieValidSeconds != 0 {
		out.CaptchaCookieValidSeconds = over.CaptchaCookieValidSeconds
	}
	if over.DebugRateLimitPer5Min != 0 {
		out.DebugRateLimitPer5Min = over.DebugRateLimitPer5Min
	}
	if over.ChallengeHTMLPath != "" {
		out.ChallengeHTMLPath = over.ChallengeHTMLPath
	}
	if over.PublicTestPages != nil {
		out.PublicTestPages = over.PublicTestPages
	}
	if over.PublicTestPagesPassword != "" {
		out.PublicTestPagesPassword = over.PublicTestPagesPassword
	}
	if over.PublicTestPagesSitePicker != nil {
		out.PublicTestPagesSitePicker = over.PublicTestPagesSitePicker
	}
	// The CAPTCHA provider is merged as a unit: a provider's key pair is only
	// meaningful next to the provider that uses it, so taking the site's
	// provider but Default's keys (or the reverse) would produce a combination
	// the operator never configured.
	if over.CaptchaProvider.Provider != "" {
		out.CaptchaProvider = over.CaptchaProvider
	}
	if over.PowDifficulty != 0 {
		out.PowDifficulty = over.PowDifficulty
	}
	if over.ObserveOnly != nil {
		out.ObserveOnly = over.ObserveOnly
	}
	out.Disabled = over.Disabled
	return out
}

// mergeBranding: same rule for the appearance record.
func mergeBranding(base, over BrandingValues) BrandingValues {
	out := base
	if over.LogoPath != "" {
		out.LogoPath = over.LogoPath
	}
	if over.SiteName != "" {
		out.SiteName = over.SiteName
	}
	if over.FooterText != "" {
		out.FooterText = over.FooterText
	}
	if over.CopyPreset != "" {
		out.CopyPreset = over.CopyPreset
	}
	if over.Theme != "" {
		out.Theme = over.Theme
	}
	if over.CustomColors != nil {
		out.CustomColors = over.CustomColors
	}
	if over.ShowCredit != nil {
		out.ShowCredit = over.ShowCredit
	}
	if over.DenyRateTheme != "" {
		out.DenyRateTheme = over.DenyRateTheme
	}
	if over.DenyRateCopyPreset != "" {
		out.DenyRateCopyPreset = over.DenyRateCopyPreset
	}
	if over.DenyRateColors != nil {
		out.DenyRateColors = over.DenyRateColors
	}
	if over.DenyBanTheme != "" {
		out.DenyBanTheme = over.DenyBanTheme
	}
	if over.DenyBanCopyPreset != "" {
		out.DenyBanCopyPreset = over.DenyBanCopyPreset
	}
	if over.DenyBanColors != nil {
		out.DenyBanColors = over.DenyBanColors
	}
	out.Disabled = over.Disabled
	return out
}

// SparsifyChallenge strips fields that match Default, so a form submitting every
// field still stores only what differs for this site.  Skipped for a Disabled
// record: Disabled means "inherit for now, remember my values", and stripping
// them is exactly what that state promises not to do.
//
// Consequence worth knowing: a site cannot pin a value by setting it to the
// same value Default already has -- that reads as "unchanged", and the site
// follows Default if Default later moves.  Pinning would need a per-field
// control in the UI, and the cost of that lands on every operator who does not
// want one; following the global is what "I left it alone" normally means.
func SparsifyChallenge(v, def ChallengeValues) ChallengeValues {
	if v.Disabled {
		return v
	}
	if v.PowCookieValidSeconds == def.PowCookieValidSeconds {
		v.PowCookieValidSeconds = 0
	}
	if v.CaptchaCookieValidSeconds == def.CaptchaCookieValidSeconds {
		v.CaptchaCookieValidSeconds = 0
	}
	if v.DebugRateLimitPer5Min == def.DebugRateLimitPer5Min {
		v.DebugRateLimitPer5Min = 0
	}
	if v.ChallengeHTMLPath == def.ChallengeHTMLPath {
		v.ChallengeHTMLPath = ""
	}
	if boolEq(v.PublicTestPages, def.PublicTestPages) {
		v.PublicTestPages = nil
	}
	if v.PublicTestPagesPassword == def.PublicTestPagesPassword {
		v.PublicTestPagesPassword = ""
	}
	if boolEq(v.PublicTestPagesSitePicker, def.PublicTestPagesSitePicker) {
		v.PublicTestPagesSitePicker = nil
	}
	if v.CaptchaProvider == def.CaptchaProvider {
		v.CaptchaProvider = Captcha{}
	}
	if v.PowDifficulty == def.PowDifficulty {
		v.PowDifficulty = 0
	}
	if boolEq(v.ObserveOnly, def.ObserveOnly) {
		v.ObserveOnly = nil
	}
	return v
}

// SparsifyBranding: same for the appearance record.
func SparsifyBranding(v, def BrandingValues) BrandingValues {
	if v.Disabled {
		return v
	}
	if v.LogoPath == def.LogoPath {
		v.LogoPath = ""
	}
	if v.SiteName == def.SiteName {
		v.SiteName = ""
	}
	if v.FooterText == def.FooterText {
		v.FooterText = ""
	}
	if v.CopyPreset == def.CopyPreset {
		v.CopyPreset = ""
	}
	if v.Theme == def.Theme {
		v.Theme = ""
	}
	if colorsEq(v.CustomColors, def.CustomColors) {
		v.CustomColors = nil
	}
	if boolEq(v.ShowCredit, def.ShowCredit) {
		v.ShowCredit = nil
	}
	if v.DenyRateTheme == def.DenyRateTheme {
		v.DenyRateTheme = ""
	}
	if v.DenyRateCopyPreset == def.DenyRateCopyPreset {
		v.DenyRateCopyPreset = ""
	}
	if colorsEq(v.DenyRateColors, def.DenyRateColors) {
		v.DenyRateColors = nil
	}
	if v.DenyBanTheme == def.DenyBanTheme {
		v.DenyBanTheme = ""
	}
	if v.DenyBanCopyPreset == def.DenyBanCopyPreset {
		v.DenyBanCopyPreset = ""
	}
	if colorsEq(v.DenyBanColors, def.DenyBanColors) {
		v.DenyBanColors = nil
	}
	return v
}

func boolEq(a, b *bool) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

func colorsEq(a, b map[string]ChallengeThemeColors) bool {
	if len(a) != len(b) {
		return false
	}
	for k, av := range a {
		bv, ok := b[k]
		if !ok || av != bv {
			return false
		}
	}
	return true
}

// ChallengeOverridesFor / BrandingOverridesFor report which fields a site
// actually sets, keyed by the form field name.  The settings page uses this to
// mark the rest as inherited, so an operator can see at a glance which values
// on the per-site form are the site's own and which are following the global
// record -- without that, a form pre-filled with resolved values looks
// identical whether a number is pinned or borrowed.
func ChallengeOverridesFor(c ChallengeConfig, site string) map[string]bool {
	v, ok := c.Sites[site]
	if !ok || v.Disabled {
		return map[string]bool{}
	}
	return map[string]bool{
		"pow_cookie_valid_seconds":      v.PowCookieValidSeconds != 0,
		"captcha_cookie_valid_seconds":  v.CaptchaCookieValidSeconds != 0,
		"debug_rate_limit_per_5min":     v.DebugRateLimitPer5Min != 0,
		"challenge_html_path":           v.ChallengeHTMLPath != "",
		"public_test_pages":             v.PublicTestPages != nil,
		"public_test_pages_password":    v.PublicTestPagesPassword != "",
		"public_test_pages_site_picker": v.PublicTestPagesSitePicker != nil,
		"captcha":                       v.CaptchaProvider.Provider != "",
		"pow_difficulty":                v.PowDifficulty != 0,
		"observe_only":                  v.ObserveOnly != nil,
	}
}

func BrandingOverridesFor(b Branding, site string) map[string]bool {
	v, ok := b.Sites[site]
	if !ok || v.Disabled {
		return map[string]bool{}
	}
	return map[string]bool{
		"logo_path":             v.LogoPath != "",
		"site_name":             v.SiteName != "",
		"footer_text":           v.FooterText != "",
		"copy_preset":           v.CopyPreset != "",
		"theme":                 v.Theme != "",
		"custom_colors":         v.CustomColors != nil,
		"show_credit":           v.ShowCredit != nil,
		"deny_rate_theme":       v.DenyRateTheme != "",
		"deny_rate_copy_preset": v.DenyRateCopyPreset != "",
		"deny_rate_colors":      v.DenyRateColors != nil,
		"deny_ban_theme":        v.DenyBanTheme != "",
		"deny_ban_copy_preset":  v.DenyBanCopyPreset != "",
		"deny_ban_colors":       v.DenyBanColors != nil,
	}
}

// normalizeDefaults turns an explicit false into "unset" on the Default
// records.  On a site record the difference matters -- false means "off here
// even though the global says on" -- but Default is the bottom of the chain,
// with nothing above it to inherit from, so there the two say the same thing.
// Keeping the pointer would rewrite the config file on every save (yaml's
// omitempty drops a nil pointer but keeps one aimed at false), which turns a
// no-op save into a diff and buries real changes in churn.
func normalizeDefaults(s *Settings) {
	if s.Challenge.Default.PublicTestPages != nil && !*s.Challenge.Default.PublicTestPages {
		s.Challenge.Default.PublicTestPages = nil
	}
	if s.Challenge.Default.PublicTestPagesSitePicker != nil && !*s.Challenge.Default.PublicTestPagesSitePicker {
		s.Challenge.Default.PublicTestPagesSitePicker = nil
	}
	if s.Challenge.Default.ObserveOnly != nil && !*s.Challenge.Default.ObserveOnly {
		s.Challenge.Default.ObserveOnly = nil
	}
	if s.Branding.Default.ShowCredit != nil && !*s.Branding.Default.ShowCredit {
		s.Branding.Default.ShowCredit = nil
	}
}
