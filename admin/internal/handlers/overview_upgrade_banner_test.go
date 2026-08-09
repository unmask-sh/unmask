package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/nginxconf"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The dashboard banner must appear (listing the held preset) under the review
// policy when an upgrade holds a preset, and stay absent under apply.  The apply
// form is admin-only: a viewer sees the banner but not the button.
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

	// render the dashboard as the given role (session injected into the context,
	// the way the auth middleware does in production).
	render := func(role string) string {
		r := httptest.NewRequest(http.MethodGet, "/unmask/admin/", nil)
		r = r.WithContext(context.WithValue(r.Context(), sessionCtxKey{}, &SessionPayload{UserID: 1, Role: role}))
		rr := httptest.NewRecorder()
		h.AdminTopOverview(rr, r)
		if rr.Code != http.StatusOK {
			t.Fatalf("overview status %d (role %s)", rr.Code, role)
		}
		return rr.Body.String()
	}

	s := *h.cfg()
	s.Nginx.UpgradeReviewPolicy = settings.UpgradeReviewReview
	s.Nginx.EnforcementReviewedVersion = "v0.1.0" // older than the synthetic preset
	h.SetSettings(s)

	// admin sees the banner, its i18n resolved, and the apply form.
	admin := render("superadmin")
	if !strings.Contains(admin, "test_future_verdict") {
		t.Error("review + held preset: the dashboard must show the upgrade-review banner listing it")
	}
	if strings.Contains(admin, "overview.upgrade_review") {
		t.Error("banner shows a raw i18n key -- a translation is missing")
	}
	if !strings.Contains(admin, "/admin/upgrade-review/apply") {
		t.Error("admin: the apply form action is missing")
	}
	if !strings.Contains(admin, `name="_csrf"`) {
		t.Error("admin: the apply form is missing the CSRF field")
	}

	// viewer sees the banner (informational) but not the apply form.
	viewer := render("viewer")
	if !strings.Contains(viewer, "test_future_verdict") {
		t.Error("viewer: the banner should still list the held preset")
	}
	if strings.Contains(viewer, "/admin/upgrade-review/apply") {
		t.Error("viewer: the apply form must be hidden (a viewer cannot apply)")
	}

	// apply policy: no banner at all.
	s.Nginx.UpgradeReviewPolicy = settings.UpgradeReviewApply
	h.SetSettings(s)
	if strings.Contains(render("superadmin"), "test_future_verdict") {
		t.Error("apply policy: the dashboard must not show the upgrade-review banner")
	}
}
