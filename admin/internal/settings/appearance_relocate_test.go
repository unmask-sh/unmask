package settings

import (
	"strings"
	"testing"
)

// TestLegacyAppearanceMovesAndPrunes: a config written before the appearance
// move must keep working, and the sites it pinned must come back to
// inheritance.  The uic.io shape below is copied from a live install: the
// operator picked a theme, and the theme tab responded by writing a verbatim
// snapshot of Challenge.Default beside it -- which is what made the site read
// as "has challenge overrides" and stopped it tracking Default afterwards.
func TestLegacyAppearanceMovesAndPrunes(t *testing.T) {
	// Shape copied from a live install: the theme tab wrote a verbatim snapshot
	// of Challenge.Default beside the theme the operator picked, which is what
	// made the site read as "has challenge overrides" and stopped it tracking
	// Default afterwards.  uic.io is still identical to Default; shop diverged
	// on pow_difficulty.
	const legacy = `
challenge:
    default:
        pow_cookie_valid_seconds: 259200
        captcha_cookie_valid_seconds: 604800
        debug_rate_limit_per_5min: 20
        challenge_html_path: ""
        captcha:
            provider: builtin
            builtin_score_threshold: 0.5
            recaptcha_min_score: 0.5
        theme: auto
        pow_difficulty: 18
        show_credit: true
    sites:
        uic.io:
            pow_cookie_valid_seconds: 259200
            captcha_cookie_valid_seconds: 604800
            debug_rate_limit_per_5min: 20
            challenge_html_path: ""
            captcha:
                provider: builtin
                builtin_score_threshold: 0.5
                recaptcha_min_score: 0.5
            theme: paper
            pow_difficulty: 18
        shop.example.com:
            pow_cookie_valid_seconds: 259200
            captcha_cookie_valid_seconds: 604800
            debug_rate_limit_per_5min: 20
            challenge_html_path: ""
            captcha:
                provider: builtin
                builtin_score_threshold: 0.5
                recaptcha_min_score: 0.5
            theme: terminal
            pow_difficulty: 20
branding:
    default:
        copy_preset: friendly
    sites:
        uic.io:
            site_name: uic.io
`
	s, err := LoadFromYAML(legacy)
	if err != nil {
		t.Fatal(err)
	}

	// The appearance survives the move, on the record that now owns it.
	if s.Branding.Default.Theme != "auto" || !s.Branding.Default.IsShowCredit() {
		t.Errorf("default appearance lost: theme=%q credit=%v",
			s.Branding.Default.Theme, s.Branding.Default.IsShowCredit())
	}
	if got := s.Branding.Sites["uic.io"].Theme; got != "paper" {
		t.Errorf("uic.io theme = %q, want paper carried onto its branding record", got)
	}
	// ...without disturbing what that record already held.
	if got := s.Branding.Sites["uic.io"].SiteName; got != "uic.io" {
		t.Errorf("uic.io site_name = %q, want it untouched by the move", got)
	}
	// A site with a theme but no branding record still gets one.
	if got := s.Branding.Sites["shop.example.com"].Theme; got != "terminal" {
		t.Errorf("shop theme = %q, want a branding record minted to hold it", got)
	}

	// uic.io's challenge entry said nothing Default did not, so it goes: the
	// site returns to inheritance, which is what "I picked a theme" meant.
	if _, ok := s.Challenge.Sites["uic.io"]; ok {
		t.Error("uic.io still has a challenge override; it only ever carried a theme")
	}
	// shop really does differ (pow_difficulty 20), so it stays -- deleting a
	// diverged record would silently change how that site is challenged.
	shop, ok := s.Challenge.Sites["shop.example.com"]
	if !ok {
		t.Fatal("a genuine challenge override was deleted")
	}
	if shop.PowDifficulty != 20 {
		t.Errorf("kept override lost its value: difficulty=%d", shop.PowDifficulty)
	}
}

// TestPruneLeavesRecordsThatDivergedFromDefault: a snapshot taken long ago no
// longer matches a Default that has moved on since -- exactly the drift this
// change exists to stop creating.  Those records must survive the move: from
// the file alone there is no way to tell "the operator wanted this off here"
// from "Default gained it later", and guessing wrong changes live behaviour.
// (Observed on tool1-jp, whose uic.io snapshot predates public_test_pages.)
func TestPruneLeavesRecordsThatDivergedFromDefault(t *testing.T) {
	const drifted = `
challenge:
    default:
        pow_difficulty: 18
        public_test_pages: true
        theme: auto
    sites:
        uic.io:
            pow_difficulty: 18
            theme: paper
`
	s, err := LoadFromYAML(drifted)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Challenge.Sites["uic.io"]; !ok {
		t.Error("a record that differs from Default (public_test_pages) was pruned")
	}
	if got := s.Branding.Sites["uic.io"].Theme; got != "paper" {
		t.Errorf("theme = %q, want it relocated even though the record stayed", got)
	}
}

// TestLegacyAppearanceDoesNotOverwriteNewShape: once a file has been saved in
// the new shape, a stale challenge-side copy may still sit beside it.  Reading
// that copy back over the branding value would silently revert the operator's
// most recent edit, so the new location wins.
func TestLegacyAppearanceDoesNotOverwriteNewShape(t *testing.T) {
	const mixed = `
challenge:
    default:
        theme: terminal
        show_credit: true
branding:
    default:
        theme: paper
`
	s, err := LoadFromYAML(mixed)
	if err != nil {
		t.Fatal(err)
	}
	if s.Branding.Default.Theme != "paper" {
		t.Errorf("theme = %q, want the branding value to win over the stale challenge copy",
			s.Branding.Default.Theme)
	}
	// A field absent from the new location still comes across.
	if !s.Branding.Default.IsShowCredit() {
		t.Error("show_credit was not carried over even though branding did not set it")
	}
}

// TestPruneKeepsDisabledOverrides: Disabled means "inherit for now, but keep my
// values so I can switch back".  Pruning those would delete the very thing the
// toggle exists to preserve.
func TestPruneKeepsDisabledOverrides(t *testing.T) {
	const withDisabled = `
challenge:
    default:
        pow_difficulty: 18
    sites:
        aaaa:
            pow_difficulty: 18
            theme: default
            disabled: true
`
	s, err := LoadFromYAML(withDisabled)
	if err != nil {
		t.Fatal(err)
	}
	v, ok := s.Challenge.Sites["aaaa"]
	if !ok {
		t.Fatal("a disabled override was pruned; its stored values are meant to survive")
	}
	if !v.Disabled {
		t.Error("the disabled flag was lost")
	}
}

// TestNoLegacyKeysIsANoOp: a file already free of the legacy shape must pass
// through untouched -- in particular, the prune must not eat a site whose
// override is real.
func TestNoLegacyKeysIsANoOp(t *testing.T) {
	const modern = `
challenge:
    default:
        pow_difficulty: 18
    sites:
        shop.example.com:
            pow_difficulty: 22
branding:
    default:
        theme: paper
    sites:
        shop.example.com:
            theme: terminal
`
	s, err := LoadFromYAML(modern)
	if err != nil {
		t.Fatal(err)
	}
	if got := s.Challenge.Sites["shop.example.com"].PowDifficulty; got != 22 {
		t.Errorf("challenge override = %d, want 22 preserved", got)
	}
	if got := s.Branding.Sites["shop.example.com"].Theme; got != "terminal" {
		t.Errorf("branding theme = %q, want terminal preserved", got)
	}
}

// TestRelocatedKeysDoNotWarn: the strict probe exists to tell an operator that
// a key in their file was thrown away.  For the relocated appearance keys that
// would be untrue -- they are read and applied -- so reporting them would send
// the operator hunting for a theme that is in fact in force.  Anything else the
// probe finds must still come through.
func TestRelocatedKeysDoNotWarn(t *testing.T) {
	only := "yaml: unmarshal errors:\n" +
		"  line 35: field theme not found in type settings.ChallengeValues\n" +
		"  line 37: field show_credit not found in type settings.ChallengeValues\n" +
		"  line 40: field custom_colors not found in type settings.ChallengeValues"
	if got := withoutRelocatedAppearanceKeys(only); got != "" {
		t.Errorf("a file carrying only relocated keys still warns:\n%s", got)
	}

	mixed := "yaml: unmarshal errors:\n" +
		"  line 35: field theme not found in type settings.ChallengeValues\n" +
		"  line 41: field pow_dificulty not found in type settings.ChallengeValues"
	got := withoutRelocatedAppearanceKeys(mixed)
	if !strings.Contains(got, "pow_dificulty") {
		t.Errorf("a genuine typo was swallowed with the relocated keys:\n%s", got)
	}
	if strings.Contains(got, "field theme") {
		t.Errorf("a relocated key survived the filter:\n%s", got)
	}
}
