package settings

import "testing"

// The three public-test-page controls sit in one block, and their shipped
// defaults are the answer to "what does a fresh install do".  Pin them: the
// pages are off, there is no Basic Auth password, and the site picker is on so
// that switching the pages public gives a page that can exercise a per-site
// challenge rather than only the default site.
func TestPublicTestPageDefaults(t *testing.T) {
	var c ChallengeValues // nothing configured = a fresh install
	if c.IsPublicTestPages() {
		t.Error("the public test pages must ship OFF -- turning them on is an explicit choice")
	}
	if c.PublicTestPagesPassword != "" {
		t.Errorf("the Basic Auth password must ship empty, got %q", c.PublicTestPagesPassword)
	}
	if !c.IsPublicTestPagesSitePicker() {
		t.Error("the site picker should default ON; it is inert until the pages are published")
	}
}

// Unset means ON here, but an explicit off has to stick -- otherwise the
// operator cannot turn the picker off at all, and the disclosure it carries
// (the list of sites with custom settings) would have no control.
func TestSitePickerExplicitOffIsHonoured(t *testing.T) {
	c := ChallengeValues{PublicTestPagesSitePicker: BoolPtr(false)}
	if c.IsPublicTestPagesSitePicker() {
		t.Error("an explicit false was ignored; the picker cannot be switched off")
	}
	c.PublicTestPagesSitePicker = BoolPtr(true)
	if !c.IsPublicTestPagesSitePicker() {
		t.Error("an explicit true did not read as on")
	}
}

// Per-site inheritance still means inheritance: a site that says nothing
// tracks Default, including Default's explicit off.  "unset = on" must not
// short-circuit that and re-enable the picker for a site.
func TestSitePickerSiteInheritsDefault(t *testing.T) {
	c := ChallengeConfig{
		Default: ChallengeValues{
			PublicTestPages:           BoolPtr(true),
			PublicTestPagesSitePicker: BoolPtr(false), // operator switched it off
		},
		Sites: map[string]ChallengeValues{
			"a.example": {}, // says nothing about the picker
		},
	}
	if c.Resolve("a.example").IsPublicTestPagesSitePicker() {
		t.Error("a site with no opinion re-enabled the picker instead of inheriting Default's off")
	}
	// And a site may still override the other way.
	c.Sites["b.example"] = ChallengeValues{PublicTestPagesSitePicker: BoolPtr(true)}
	if !c.Resolve("b.example").IsPublicTestPagesSitePicker() {
		t.Error("a site's explicit on did not win over Default's off")
	}
}

// A site pinning the picker ON while Default has it OFF must survive
// sparsification: the two differ, so the site's value is its own.  (The
// mirror case -- collapsing Default's redundant "true" back to unset -- is
// the handler's job, since Default has no parent to compare against.)
func TestSitePickerSparsifyKeepsARealDifference(t *testing.T) {
	def := ChallengeValues{PublicTestPagesSitePicker: BoolPtr(false)}
	site := ChallengeValues{PublicTestPagesSitePicker: BoolPtr(true)}
	got := SparsifyChallenge(site, def)
	if got.PublicTestPagesSitePicker == nil || !*got.PublicTestPagesSitePicker {
		t.Error("the site's explicit ON was collapsed away against a Default of OFF")
	}
	// Same value as Default = nothing of its own.
	same := SparsifyChallenge(ChallengeValues{PublicTestPagesSitePicker: BoolPtr(false)}, def)
	if same.PublicTestPagesSitePicker != nil {
		t.Error("a site matching Default should store nothing")
	}
}
