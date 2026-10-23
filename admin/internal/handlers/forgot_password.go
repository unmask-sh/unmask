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
	"time"

	"github.com/unmask-sh/unmask/admin/internal/i18n"

	"github.com/unmask-sh/unmask/admin/internal/settings"
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
	// The reset token is written to the database, which a schema update
	// holds.  Said so, rather than the usual "sent" page for a mail that
	// never goes out.
	if h.DB.WritesHeld() {
		h.respondWritesHeld(w, r)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	// Per-IP request cap.  For this endpoint the REQUEST is the cost -- every
	// accepted one sends mail and mints a reset token -- so unlike the login
	// lockout there is no failure to count: the cap is on requests, before the
	// user lookup even runs.
	ip := adminClientIP(r, *h.cfg())
	now := time.Now()
	t := h.throttle()
	if d := t.lockedFor(forgotKey(ip), now); d > 0 {
		tooManyLoginAttempts(w, d)
		return
	}
	if d := t.note(forgotKey(ip), now, t.forgotLimit, t.forgotWindow, t.forgotWindow); d > 0 {
		tooManyLoginAttempts(w, d)
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
	if u.PasswordLocked {
		// An administrator keeps this account from changing its own
		// password (a login shared by a team): no link, the same answer as
		// for an unknown name, so the page tells nobody which it was.  A
		// setup link an administrator sends from the users page still works.
		log.Printf("forgot password: user %s may not change its own password", u.Username)
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
	//    from the target site and the admin base_path).  No host the link
	//    can safely be built on -> no mail; the token expires unused.
	resetURL := buildResetURL(r, h.snapshotSettings(), tok)
	if resetURL == "" {
		log.Printf("forgot password: no host to build the reset link on (admin_allowed_hosts names none; request host %q); mail not sent", LogSafe(r.Host))
	} else {
		subject := "[unmask] password reset link"
		body := "A password reset was requested for unmask.\n\n" +
			"Use the following link to set a new password (valid for 1 hour):\n" +
			resetURL + "\n\n" +
			"If you did not request this, ignore this email.\n" +
			"username: " + u.Username + "\n"
		if err := h.Mailer.Send(u.Email.String, subject, body); err != nil {
			log.Printf("forgot password: mail send to %s: %v", u.Email.String, err)
		}
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
	// The new password and the spent token are written to the database,
	// which a schema update holds: "invalid token" would be untrue, and the
	// token stays good for when the update has finished.
	if h.DB.WritesHeld() {
		h.respondWritesHeld(w, r)
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

// buildResetURL: the client-visible reset / setup link, or "" when there is
// no host it can safely be built on (resetLinkHost).
//
// On internal-IP access, host becomes localhost / 127.0.0.1.  The flow
// still works, but the link inside the mail won't be reachable
// externally.  That's an operator responsibility (= reverse-proxy setup).
func buildResetURL(r *http.Request, cfg settings.Settings, token string) string {
	host := resetLinkHost(r, cfg)
	if host == "" {
		return ""
	}
	return resetLinkScheme(r, cfg) + "://" + host + cfg.Server.BasePath + "/admin/reset-password?token=" + token
}

// resetLinkHost is the host the reset link is built on, "" when none can be
// trusted.
//
// The mail goes to the account's own address, so a link built on a host the
// client named is a one-click leak of the token to that host: a visitor who
// sends "Host: attacker.example" (or X-Forwarded-Host) for the victim's
// username would have the victim deliver their own token.  So:
//   - X-Forwarded-Host is read off a trusted proxy only (adminClientHost, the
//     same reading admin_allowed_hosts is enforced with); from anyone else the
//     host is what the connection's own Host header says.
//   - With admin_allowed_hosts set, the host has to match it the way the admin
//     gate matches (hostMatchesPattern: exact:, subdomain:, anchored regex).
//     This used to compare the raw entries, so a list saved by the settings
//     page -- whose rows carry a mode marker -- never matched, and the link
//     was then built on the literal first entry, "exact:admin.example.com".
//   - A host outside the list is replaced by the first entry that names a
//     host (literalHost).  A list of patterns alone names none, and then
//     there is no safe host and no link: the caller logs it and sends no
//     mail.
//   - An empty list (the default) keeps trusting the request host: a single-
//     admin install, where the name the operator reached the admin by is the
//     name the link should carry.
func resetLinkHost(r *http.Request, cfg settings.Settings) string {
	host := strings.TrimSpace(adminClientHost(r, cfg))
	allowed := settings.EnabledValues(cfg.Nginx.AdminAllowedHosts, cfg.Nginx.AdminAllowedHostsDisabled)
	if host != "" && hostAllowed(host, allowed) {
		return host
	}
	for _, entry := range allowed {
		if lit := literalHost(strings.TrimSpace(entry)); lit != "" {
			return lit
		}
	}
	return ""
}

// literalHost is the host an allowlist entry names, "" for a pattern.  An
// exact: entry names its text, a subdomain: entry names the domain itself,
// and a bare entry that is a plain dotted name (plainHostRE, over_block.go)
// names that -- entries from before the mode markers existed are bare, and a
// name matches itself as a regex too.  A bare entry with any regex syntax in
// it names nothing.  Also what adminURL builds an alert's links from.
func literalHost(entry string) string {
	switch settings.PatternModeOf(entry) {
	case settings.ModeExact, settings.ModeContains, settings.ModeSubdomain:
		return strings.TrimSpace(settings.PatternText(entry))
	}
	if plainHostRE.MatchString(entry) {
		return entry
	}
	return ""
}

// resetLinkScheme: the scheme the link is built with.  X-Forwarded-Proto is
// read off a trusted proxy only, as the host is: a link downgraded to http
// would carry the token over the wire in the clear when the mail is opened.
// Direct to the daemon, the connection itself says.
func resetLinkScheme(r *http.Request, cfg settings.Settings) string {
	if peerIsTrustedProxy(r.RemoteAddr, forwardAuthTrustedPeers(cfg)) || peerIsUnixSocket(r.RemoteAddr) {
		if v := strings.ToLower(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto"))); v == "http" || v == "https" {
			return v
		}
	}
	if r.TLS != nil {
		return "https"
	}
	return "http"
}
