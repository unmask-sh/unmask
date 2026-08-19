package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestProfileOptOutReflectsMailTo: the per-user alert opt-out only matters on
// the fallback path (alerts to admin users).  With notifications.mail_to set,
// that path is never taken -- so the profile keeps the checkbox EDITABLE (the
// stored value matters again the moment mail_to is emptied) and annotates why
// it is currently moot.  No setting may look effective while doing nothing.
func TestProfileOptOutReflectsMailTo(t *testing.T) {
	h, _ := newInviteTestHandler(t)
	ctx := context.Background()
	u, err := h.UserRepo.CreateWithProfile(ctx, "opty", "test-password-opty", "superadmin", "opty@example.com", true /* opted out */)
	if err != nil {
		t.Fatal(err)
	}
	render := func() string {
		req := httptest.NewRequest(http.MethodGet, "/unmask/admin/profile/", nil)
		req = req.WithContext(context.WithValue(req.Context(), sessionCtxKey{},
			&SessionPayload{UserID: u.ID, Role: "superadmin"}))
		rr := httptest.NewRecorder()
		h.AdminProfileIndex(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("profile: want 200, got %d", rr.Code)
		}
		return rr.Body.String()
	}
	liveCheckbox := `<input type="checkbox" name="alert_opt_out" value="1" checked`

	// mail_to unset: a normal checkbox, no annotation.
	body := render()
	if !strings.Contains(body, liveCheckbox) {
		t.Error("without mail_to the opt-out must be a live checkbox")
	}
	if strings.Contains(body, "mail_to") {
		t.Error("without mail_to there is nothing to annotate")
	}

	// mail_to set: the checkbox stays live and editable; an annotation says
	// the setting is currently moot and why.
	h.updateSettingsInMemory(func(s *settings.Settings) { s.Notifications.MailTo = "alerts@example.com" })
	body = render()
	if !strings.Contains(body, liveCheckbox) {
		t.Error("with mail_to set the opt-out must STAY editable")
	}
	if strings.Contains(body, `<input type="checkbox" disabled`) || strings.Contains(body, `type="hidden" name="alert_opt_out"`) {
		t.Error("with mail_to set the checkbox must not be disabled or shadowed by a hidden field")
	}
	if !strings.Contains(body, "mail_to") {
		t.Error("with mail_to set the annotation must say why the toggle is currently moot")
	}
}
