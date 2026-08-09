package handlers

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/nginxconf"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// Applying from the banner advances enforcement_reviewed_version to this binary,
// so every held preset activates (nothing stays held afterward).
func TestUpgradeReviewApplyAdvancesReviewedVersion(t *testing.T) {
	saved := nginxconf.JA4VerdictGroups
	nginxconf.JA4VerdictGroups = append(append([]nginxconf.JA4VerdictGroup{}, saved...),
		nginxconf.JA4VerdictGroup{
			ID:      "test_future_verdict",
			Label:   "synthetic future verdict",
			AddedIn: "v9.9.9",
			Rules:   []nginxconf.JA4VerdictRule{{ID: 9001, Pattern: "t13dfuture_", Verdict: "test_future", Action: nginxconf.JA4ActionBot}},
		})
	t.Cleanup(func() { nginxconf.JA4VerdictGroups = saved })

	var base settings.Settings
	base.Server.BasePath = "/unmask"
	base.Nginx.OutputDir = t.TempDir() // keep the post-apply Render off the real FHS path
	base.Nginx.UpgradeReviewPolicy = settings.UpgradeReviewReview
	base.Nginx.EnforcementReviewedVersion = "v0.1.0" // older than the synthetic preset

	h := newTestHandler(t)
	h.Version = "9.9.9" // "v"+Version must parse, and equal the synthetic AddedIn
	cfgPath := filepath.Join(t.TempDir(), "config.yml")
	if err := settings.Save(base, cfgPath); err != nil {
		t.Fatal(err)
	}
	h.ConfigPath = cfgPath
	h.SetSettings(base)

	if len(nginxconf.HeldEnforcementPresets(base)) == 0 {
		t.Fatal("precondition: the synthetic preset should be held before apply")
	}

	req := httptest.NewRequest(http.MethodPost, "/unmask/admin/upgrade-review/apply", nil)
	req.AddCookie(issueSessionCookie(h.cfg().Secret.BVSecret, 1, "superadmin", false, false))
	rr := httptest.NewRecorder()
	h.AdminUpgradeReviewApply(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("apply status %d, want 302", rr.Code)
	}

	loaded, err := settings.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := loaded.Nginx.EnforcementReviewedVersion; got != "v9.9.9" {
		t.Errorf("reviewed version = %q, want v9.9.9", got)
	}
	if n := len(nginxconf.HeldEnforcementPresets(loaded)); n != 0 {
		t.Errorf("after apply: %d preset(s) still held, want 0", n)
	}
}
