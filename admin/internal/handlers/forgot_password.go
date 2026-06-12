// Password reminder (= forgot-password / reset-password) handlers.
//
// Flow:
//  1. Enter email or username on /admin/forgot-password.
//  2. If the user exists, has an email, and the Mailer is enabled →
//     issue a token → write to DB → send mail.
//  3. Even when the user does not exist / has no email, the UI still
//     shows the same "we sent the mail" message (= enumeration protection).
//  4. Enter the new password at /admin/reset-password?token=...
//  5. If the token is valid and unexpired, update the password + consume the token.
//
// When SMTP is unconfigured (= h.Mailer.Enabled()=false), even visiting
// /admin/forgot-password announces "mail cannot be sent."  The link on the
// login page is also hidden.
package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"log"
	"net/http"
	"strings"

	"github.com/unmask-sh/unmask/admin/internal/i18n"
)

const (
	resetTokenTTLSec = 3600 // 1 hour
)

// AdminForgotPasswordGet: GET {base}/admin/forgot-password — render the form.
func (h *Handler) AdminForgotPasswordGet(w http.ResponseWriter, r *http.Request) {
	tmpl, err := loadDashboardTemplate()
	if err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	data := map[string]any{
		"Lang":        i18n.Resolve(r),
		"BasePath":    h.cfg().Server.BasePath,
		"MailEnabled": h.Mailer != nil && h.Mailer.Enabled(),
		"Sent":        r.URL.Query().Get("sent") == "1",
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.ExecuteTemplate(w, "forgot_password.html", data); err != nil {
		log.Printf("forgot password render: %v", err)
	}
}

// AdminForgotPasswordPost: POST {base}/admin/forgot-password — issue a token + send mail.
//
// Account-enumeration mitigation:
//   - User absent / no email / mail send failure all surface the same "sent" UI.
//   - We record the cause in the log but never leak it to the client.
func (h *Handler) AdminForgotPasswordPost(w http.ResponseWriter, r *http.Request) {
	base := h.cfg().Server.BasePath
	if h.UserRepo == nil || h.Mailer == nil || !h.Mailer.Enabled() {
		http.Error(w, "mail not configured", http.StatusServiceUnavailable)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	identifier := strings.TrimSpace(r.FormValue("identifier"))
	if identifier == "" {
		http.Redirect(w, r, base+"/admin/forgot-password?sent=1", http.StatusFound)
		return
	}

	// 1) Look up by email.  On miss, look up by username.
	ctx := r.Context()
	u, err := h.UserRepo.GetByEmail(ctx, identifier)
	if err != nil {
		u, err = h.UserRepo.GetByUsername(ctx, identifier)
	}
	if err != nil {
		log.Printf("forgot password: identifier %q not found", identifier)
		http.Redirect(w, r, base+"/admin/forgot-password?sent=1", http.StatusFound)
		return
	}
	if !u.Email.Valid || strings.TrimSpace(u.Email.String) == "" {
		log.Printf("forgot password: user %s has no email", u.Username)
		http.Redirect(w, r, base+"/admin/forgot-password?sent=1", http.StatusFound)
		return
	}

	// 2) Issue the token (= 32-byte hex).
	tok, err := newResetToken()
	if err != nil {
		log.Printf("forgot password: token gen: %v", err)
		http.Redirect(w, r, base+"/admin/forgot-password?sent=1", http.StatusFound)
		return
	}
	if err := h.UserRepo.IssueResetToken(ctx, u.ID, tok, resetTokenTTLSec); err != nil {
		log.Printf("forgot password: issue token: %v", err)
		http.Redirect(w, r, base+"/admin/forgot-password?sent=1", http.StatusFound)
		return
	}

	// 3) Send mail.  The URL prefix uses the client-visible Host (= built
	//    from the target site and the admin base_path).
	resetURL := buildResetURL(r, base, tok, h.snapshotSettings().Nginx.AdminAllowedHosts)
	subject := "[unmask] password reset link"
	body := "A password reset was requested for unmask.\n\n" +
		"Use the following link to set a new password (valid for 1 hour):\n" +
		resetURL + "\n\n" +
		"If you did not request this, ignore this email.\n" +
		"username: " + u.Username + "\n"
	if err := h.Mailer.Send(u.Email.String, subject, body); err != nil {
		log.Printf("forgot password: mail send to %s: %v", u.Email.String, err)
	}

	// audit (= record both successes and failures for audit).
	h.UserRepo.Record(ctx, u.ID, u.Username, "forgot_password_request", u.Username, "")

	http.Redirect(w, r, base+"/admin/forgot-password?sent=1", http.StatusFound)
}

// AdminResetPasswordGet: GET {base}/admin/reset-password?token=... — render the form.
func (h *Handler) AdminResetPasswordGet(w http.ResponseWriter, r *http.Request) {
	tmpl, err := loadDashboardTemplate()
	if err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	data := map[string]any{
		"Lang":     i18n.Resolve(r),
		"BasePath": h.cfg().Server.BasePath,
		"Token":    r.URL.Query().Get("token"),
		"Error":    r.URL.Query().Get("err"),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.ExecuteTemplate(w, "reset_password.html", data); err != nil {
		log.Printf("reset password render: %v", err)
	}
}

// AdminResetPasswordPost: POST {base}/admin/reset-password — validate the token + update the password.
func (h *Handler) AdminResetPasswordPost(w http.ResponseWriter, r *http.Request) {
	base := h.cfg().Server.BasePath
	if h.UserRepo == nil {
		http.Error(w, "user repo not configured", http.StatusInternalServerError)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	tok := strings.TrimSpace(r.FormValue("token"))
	pw := r.FormValue("password")
	pw2 := r.FormValue("password2")
	if tok == "" || pw == "" || pw2 == "" {
		http.Redirect(w, r, base+"/admin/reset-password?token="+tok+"&err=empty", http.StatusFound)
		return
	}
	if pw != pw2 {
		http.Redirect(w, r, base+"/admin/reset-password?token="+tok+"&err=mismatch", http.StatusFound)
		return
	}

	ctx := r.Context()
	u, err := h.UserRepo.ConsumeResetToken(ctx, tok)
	if err != nil {
		http.Redirect(w, r, base+"/admin/reset-password?token=&err=invalid", http.StatusFound)
		return
	}
	if err := h.UserRepo.SetPassword(ctx, u.ID, pw); err != nil {
		log.Printf("reset password set: %v", err)
		http.Redirect(w, r, base+"/admin/reset-password?token=&err=set", http.StatusFound)
		return
	}

	h.UserRepo.Record(ctx, u.ID, u.Username, "password_reset_via_email", u.Username, "")
	log.Printf("password reset via email for user: %s", u.Username)

	http.Redirect(w, r, base+"/admin/login?reset=1", http.StatusFound)
}

// newResetToken: random 32-byte hex (= 64 chars).  url-safe.
func newResetToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// buildResetURL: build the client-visible URL.  Trust X-Forwarded-Proto /
// -Host (= behind a reverse proxy).  Fall back to r.Host + inferred scheme.
func buildResetURL(r *http.Request, base, token string, allowedHosts []string) string {
	scheme := "https"
	if v := r.Header.Get("X-Forwarded-Proto"); v != "" {
		scheme = v
	} else if r.TLS == nil {
		scheme = "http"
	}
	host := r.Header.Get("X-Forwarded-Host")
	if host == "" {
		host = r.Host
	}
	// Reset-link poisoning guard: the email is sent to the victim, so a
	// client-supplied Host / X-Forwarded-Host of `attacker.com` would yield
	// a body saying "click https://attacker.com/admin/reset-password?token=XXX"
	// and a one-click leak of the token (= account takeover).  When the
	// operator has configured an AdminAllowedHosts allowlist, only honor
	// hosts inside it; otherwise pin to the first entry.  An empty
	// allowlist means "single-admin install, trust r.Host" (= preserves the
	// current behavior on default installs).
	if len(allowedHosts) > 0 {
		ok := false
		for _, a := range allowedHosts {
			if strings.EqualFold(host, strings.TrimSpace(a)) {
				ok = true
				break
			}
		}
		if !ok {
			host = strings.TrimSpace(allowedHosts[0])
		}
	}
	// On internal-IP access, host becomes localhost / 127.0.0.1.  The flow
	// still works, but the link inside the mail won't be reachable
	// externally.  That's an operator responsibility (= reverse-proxy setup).
	return scheme + "://" + host + base + "/admin/reset-password?token=" + token
}
