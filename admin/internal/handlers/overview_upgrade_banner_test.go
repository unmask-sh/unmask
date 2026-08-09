package handlers

import (
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/nginxconf"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The dashboard banner must appear (listing the held preset) under the review
// policy when an upgrade holds a preset, and stay absent under apply -- the
// handler->template wiring, end to end.
func TestOverviewUpgradeReviewBanner(t *testing.T) {
	saved := nginxconf.JA4VerdictGroups
	nginxconf.JA4VerdictGroups = append(append([]nginxconf.JA4VerdictGroup{}, saved...),
		nginxconf.JA4VerdictGroup{
			ID:      "test_future_verdict",
			Label:   "synthetic future verdict",
			AddedIn: "v9.9.9",
			Rules:   []nginxconf.JA4VerdictRule{{ID: 9001, Pattern: "t13dfuture_", Verdict: "test_future", Action: nginxconf.JA4ActionBot}},
		})
	t.Cleanup(func() { nginxconf.JA4VerdictGroups = saved })

	h := newTestHandler(t)

	s := *h.cfg()
	s.Nginx.UpgradeReviewPolicy = settings.UpgradeReviewReview
	s.Nginx.EnforcementReviewedVersion = "v0.1.0" // older than the synthetic preset
	h.SetSettings(s)
	html := renderOverview(t, h)
	if !strings.Contains(html, "test_future_verdict") {
		t.Error("review + held preset: the dashboard must show the upgrade-review banner listing it")
	}
	// The banner's i18n keys must resolve (a missing key renders the raw key),
	// and the apply form must carry its action and the CSRF field.
	if strings.Contains(html, "overview.upgrade_review") {
		t.Error("banner shows a raw i18n key -- a translation is missing")
	}
	if !strings.Contains(html, "/admin/upgrade-review/apply") {
		t.Error("banner is missing the apply form action")
	}
	if !strings.Contains(html, `name="_csrf"`) {
		t.Error("banner apply form is missing the CSRF field")
	}

	s.Nginx.UpgradeReviewPolicy = settings.UpgradeReviewApply
	h.SetSettings(s)
	if html := renderOverview(t, h); strings.Contains(html, "test_future_verdict") {
		t.Error("apply policy: the dashboard must not show the upgrade-review banner")
	}
}
