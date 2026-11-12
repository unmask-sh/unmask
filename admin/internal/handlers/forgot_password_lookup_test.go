package handlers

import (
	"context"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// hasResetToken: was a reset link issued for the account?
func hasResetToken(t *testing.T, h *Handler, id int64) bool {
	t.Helper()
	u, err := h.UserRepo.GetByID(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return u.ResetToken.Valid && u.ResetToken.String != ""
}

// The forgot-password form takes a user name or an address.  The address was
// looked up first, and it is a profile field its owner fills in unchecked:
// an account that put another's user name there was the one found, and the
// account the name belongs to could not ask for its own link.  The name is
// looked up first now.
func TestForgotPasswordFindsTheUserNameBeforeAnAddress(t *testing.T) {
	h, stub := newInviteTestHandler(t)
	h.updateSettingsInMemory(func(s *settings.Settings) { s.Server.BasePath = "/unmask" })
	ctx := context.Background()
	boss, err := h.UserRepo.CreateWithProfile(ctx, "boss@example.com", "test-password-boss1", "superadmin", "boss-inbox@example.com", false)
	if err != nil {
		t.Fatal(err)
	}
	// Another account, whose address is the first one's user name.
	other, err := h.UserRepo.CreateWithProfile(ctx, "mallory", "test-password-mallory", "viewer", "boss@example.com", false)
	if err != nil {
		t.Fatal(err)
	}
	forgotPost(t, h, "boss@example.com", "en")
	mail := stub.waitMessage(t)
	if !strings.Contains(mail, "boss-inbox@example.com") {
		t.Errorf("the link did not go to the address of the account the name belongs to:\n%s", mail)
	}
	if !hasResetToken(t, h, boss.ID) || hasResetToken(t, h, other.ID) {
		t.Errorf("the link was issued for the wrong account (boss=%v other=%v)", hasResetToken(t, h, boss.ID), hasResetToken(t, h, other.ID))
	}
}

// An address still finds its account, when no account has it for a name.
func TestForgotPasswordStillTakesAnAddress(t *testing.T) {
	h, stub := newInviteTestHandler(t)
	h.updateSettingsInMemory(func(s *settings.Settings) { s.Server.BasePath = "/unmask" })
	carol, err := h.UserRepo.CreateWithProfile(context.Background(), "carol", "test-password-carol", "admin", "carol@example.com", false)
	if err != nil {
		t.Fatal(err)
	}
	forgotPost(t, h, "carol@example.com", "en")
	if mail := stub.waitMessage(t); !strings.Contains(mail, "carol@example.com") {
		t.Errorf("the link did not go to the account's address:\n%s", mail)
	}
	if !hasResetToken(t, h, carol.ID) {
		t.Error("no link was issued for the account the address belongs to")
	}
}
