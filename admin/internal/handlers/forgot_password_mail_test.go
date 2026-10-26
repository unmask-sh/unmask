package handlers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

var resetPathRE = regexp.MustCompile(`/unmask/admin/reset-password\?token=([0-9a-f]{64})`)

func forgotPost(t *testing.T, h *Handler, identifier, acceptLanguage string) {
	t.Helper()
	form := url.Values{"identifier": {identifier}}
	req := httptest.NewRequest(http.MethodPost, "/unmask/admin/forgot-password", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept-Language", acceptLanguage)
	req.Host = "attacker.example"
	rr := httptest.NewRecorder()
	h.AdminForgotPasswordPost(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("forgot: %d %s", rr.Code, rr.Body.String())
	}
}

// With no public address and no allowed host, the reset mail still goes --
// with the path alone and the sentence that says where to open it, never a
// link built on the request's Host header -- and what the database keeps
// of the mailed token is its hash.
func TestForgotPasswordMailsPathWithoutAHost(t *testing.T) {
	h, stub := newInviteTestHandler(t)
	h.updateSettingsInMemory(func(s *settings.Settings) { s.Server.BasePath = "/unmask" })
	ctx := context.Background()
	u, err := h.UserRepo.CreateWithProfile(ctx, "carol", "test-password-carol", "admin", "carol@example.com", false)
	if err != nil {
		t.Fatal(err)
	}
	forgotPost(t, h, "carol@example.com", "en")
	body := stub.waitMessage(t)
	m := resetPathRE.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("the mail carries no reset path:\n%s", body)
	}
	if strings.Contains(body, "attacker.example") || strings.Contains(body, "http") {
		t.Errorf("the mail carries a host:\n%s", body)
	}
	if !strings.Contains(body, "the address you always use") {
		t.Errorf("the mail does not say where to open the path:\n%s", body)
	}
	sum := sha256.Sum256([]byte(m[1]))
	if again, _ := h.UserRepo.GetByID(ctx, u.ID); !again.ResetToken.Valid || again.ResetToken.String != hex.EncodeToString(sum[:]) {
		t.Errorf("the column holds %q, want the token's hash", again.ResetToken.String)
	}
	if got, err := h.UserRepo.ConsumeResetToken(ctx, m[1]); err != nil || got.ID != u.ID {
		t.Errorf("the mailed token does not redeem: %v", err)
	}
	if _, err := h.UserRepo.ConsumeResetToken(ctx, hex.EncodeToString(sum[:])); err == nil {
		t.Error("the stored hash redeems as a token")
	}
}

// With admin_public_url set the mail carries the link on it, in the
// language the account last used the admin in (the request's before the
// account used it).
func TestForgotPasswordMailsPublicAddressLink(t *testing.T) {
	h, stub := newInviteTestHandler(t)
	h.updateSettingsInMemory(func(s *settings.Settings) {
		s.Server.BasePath = "/unmask"
		s.Nginx.AdminPublicURL = "https://ops.example.net/unmask"
	})
	if _, err := h.UserRepo.CreateWithProfile(context.Background(), "dave", "test-password-dave", "admin", "dave@example.com", false); err != nil {
		t.Fatal(err)
	}
	forgotPost(t, h, "dave", "ja")
	body := stub.waitMessage(t)
	if !strings.Contains(body, "https://ops.example.net/unmask/admin/reset-password?token=") {
		t.Errorf("the mail does not carry the link on the public address:\n%s", body)
	}
	if !strings.Contains(body, "ユーザー名: dave") {
		t.Errorf("the mail is not in the request's language:\n%s", body)
	}
}
