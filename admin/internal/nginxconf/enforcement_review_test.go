package nginxconf

import (
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

func TestEnforcementHeld(t *testing.T) {
	cases := []struct {
		name     string
		policy   string
		reviewed string
		addedIn  string
		want     bool
	}{
		{"apply never holds", settings.UpgradeReviewApply, "v0.1.0", "v9.9.9", false},
		{"empty policy = apply", "", "v0.1.0", "v9.9.9", false},
		{"review holds a newer preset", settings.UpgradeReviewReview, "v0.1.6", "v0.1.7", true},
		{"review keeps same version", settings.UpgradeReviewReview, "v0.1.7", "v0.1.7", false},
		{"review keeps older-than-reviewed", settings.UpgradeReviewReview, "v0.1.7", "v0.1.6", false},
		{"review empty reviewed = runs tip", settings.UpgradeReviewReview, "", "v0.1.7", false},
		{"review dev reviewed = runs tip", settings.UpgradeReviewReview, "vdeadbeef", "v0.1.7", false},
		{"review empty AddedIn = baseline, never held", settings.UpgradeReviewReview, "v0.1.0", "", false},
	}
	for _, c := range cases {
		n := settings.Nginx{UpgradeReviewPolicy: c.policy, EnforcementReviewedVersion: c.reviewed}
		if got := EnforcementHeld(n, c.addedIn); got != c.want {
			t.Errorf("%s: EnforcementHeld(policy=%q reviewed=%q added=%q)=%v want %v",
				c.name, c.policy, c.reviewed, c.addedIn, got, c.want)
		}
	}
}

// withSyntheticVerdict appends a future-dated JA4 verdict preset so the tests do
// not depend on which shipped presets happen to carry an AddedIn (baseline
// presets deliberately omit it).  Restores the global on cleanup.
func withSyntheticVerdict(t *testing.T, addedIn string) {
	t.Helper()
	saved := JA4VerdictGroups
	JA4VerdictGroups = append(append([]JA4VerdictGroup{}, saved...), JA4VerdictGroup{
		ID:      "test_future_verdict",
		Label:   "synthetic future verdict",
		AddedIn: addedIn,
		Rules:   []JA4VerdictRule{{ID: 9001, Pattern: "t13dtestfuture_", Verdict: "test_future", Action: JA4ActionBot}},
	})
	t.Cleanup(func() { JA4VerdictGroups = saved })
}

func TestHeldEnforcementPresets(t *testing.T) {
	withSyntheticVerdict(t, "v9.9.9")

	// apply: nothing is ever held.
	var s settings.Settings
	s.Nginx.UpgradeReviewPolicy = settings.UpgradeReviewApply
	s.Nginx.EnforcementReviewedVersion = "v0.1.0"
	if got := HeldEnforcementPresets(s); len(got) != 0 {
		t.Errorf("apply policy: want 0 held, got %d", len(got))
	}

	// review + reviewed older than the synthetic preset: it is held, and every
	// held item is a tightening category (never a rescue/bypass one).
	s.Nginx.UpgradeReviewPolicy = settings.UpgradeReviewReview
	held := HeldEnforcementPresets(s)
	foundSynthetic := false
	for _, h := range held {
		switch h.Category {
		case "ja4", "challenge-target", "honeypot":
		default:
			t.Errorf("held a non-tightening category %q (rescue presets must never be held)", h.Category)
		}
		if h.ID == "test_future_verdict" {
			foundSynthetic = true
		}
	}
	if !foundSynthetic {
		t.Error("review + old reviewed: the synthetic future verdict should be held")
	}

	// review + reviewed at/after the preset: nothing held (acknowledged).
	s.Nginx.EnforcementReviewedVersion = "v9.9.9"
	if got := HeldEnforcementPresets(s); len(got) != 0 {
		t.Errorf("review + reviewed==AddedIn: want 0 held, got %d", len(got))
	}
}

func TestRenderHoldsNewTighteningButNeverRescue(t *testing.T) {
	withSyntheticVerdict(t, "v9.9.9")

	verdictRendered := func(policy, reviewed string) (verdict bool, rescue bool) {
		var s settings.Settings
		s.Nginx.UpgradeReviewPolicy = policy
		s.Nginx.EnforcementReviewedVersion = reviewed
		d, err := buildRenderData(s, "", "0.1.0")
		if err != nil {
			t.Fatalf("buildRenderData(policy=%q): %v", policy, err)
		}
		for _, r := range d.JA4Verdicts {
			if r.Verdict == "test_future" {
				verdict = true
			}
		}
		for _, p := range d.BypassPathsGlobal {
			if p == `^/robots\.txt$` { // a default-on rescue preset pattern
				rescue = true
			}
		}
		return
	}

	// apply: the new tightening preset renders immediately.
	if v, _ := verdictRendered(settings.UpgradeReviewApply, "v0.1.0"); !v {
		t.Error("apply: a new tightening preset must render immediately")
	}

	// review + older reviewed: the tightening preset is held inert, but a rescue
	// preset is NEVER held (search bots must always get through).
	v, rescue := verdictRendered(settings.UpgradeReviewReview, "v0.1.0")
	if v {
		t.Error("review + old reviewed: the new tightening preset must be held inert")
	}
	if !rescue {
		t.Error("review: a rescue (bypass) preset must NEVER be held")
	}

	// review + reviewed at the preset version: acknowledged, so it renders.
	if v, _ := verdictRendered(settings.UpgradeReviewReview, "v9.9.9"); !v {
		t.Error("review + acknowledged: the preset must render once reviewed up to its version")
	}
}
