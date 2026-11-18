// profile tab: settings page for the currently logged-in user.
//
// Available to all roles (= superadmin / admin / viewer).  Distinct from the
// superadmin "edit other users" feature at /admin/users/:
//   - Profile (= email / alert opt-out / nickname later, etc.) does not need
//     the current password (= identity already confirmed by session).
//     POST op=profile
//   - Password change requires the current password.  POST op=password
package handlers

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/i18n"
	"github.com/unmask-sh/unmask/admin/internal/user"
)

// AdminProfileIndex: GET /admin/profile/ — self-settings page (= edit email + password).
func (h *Handler) AdminProfileIndex(w http.ResponseWriter, r *http.Request) {
	if h.UserRepo == nil {
		http.Error(w, "user repo not configured", http.StatusInternalServerError)
		return
	}
	tmpl, err := loadDashboardTemplate()
	if err != nil {
		log.Printf("profile: template: %v", err)
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	pay := SessionFromContext(r)
	if pay == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	me, err := h.UserRepo.GetByID(r.Context(), pay.UserID)
	if err != nil {
		http.Error(w, "user not found", http.StatusInternalServerError)
		return
	}
	data := map[string]any{
		"Lang":     i18n.Resolve(r),
		"TZ":       resolveTZ(r),
		"BasePath": h.cfg().Server.BasePath,
		"Version":  h.Version,
		"Saved":    r.URL.Query().Get("saved") != "",
		"Error":    readFlash(w, r, h.cfg().Server.BasePath, "err"),
		"Me":       pay,
		"User":     me,
		// PasswordLocked: an administrator keeps this account from changing
		// its own password (a login shared by a team).  The template draws a
		// note in place of the form; the save op refuses as well.
		"PasswordLocked": me.PasswordLocked,
		// MailToActive: notifications.mail_to is set, so alert mail goes to
		// that explicit list and the per-user opt-out is never consulted.  The
		// template disables the checkbox and says why, instead of showing a
		// setting that silently does nothing.
		"MailToActive": len(h.snapshotSettings().Notifications.MailToResolved()) > 0,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	h.addMeToData(r, data)
	if err := tmpl.ExecuteTemplate(w, "profile.html", data); err != nil {
		log.Printf("profile render: %v", err)
	}
}

// checkOwnPassword is the profile page's question "and your current
// password?", asked before it changes the password or the address a reset
// link goes to.  It reports whether given is the account's password; when it
// is not, the response has been written -- by wrong for a password that does
// not match, which is the page's own message, and here for the two cases
// that are not about the password.
//
// The checks are counted by account.  A session is all it takes to reach
// them, and the login's own count is by address and does not see them: with
// a session in hand -- a cookie taken from a browser, an unlocked desk --
// the password could be guessed here without end, and the password is what
// turns a session that ends into an account that does not.  After as many
// wrong answers as the login allows an address (loginThrottle.failLimit) the
// account's checks are refused for as long as a locked address is, before
// the password is looked at.  A right answer in between does not wipe the
// count: the holder of a session who also knew the password would not be
// here guessing.
func (h *Handler) checkOwnPassword(w http.ResponseWriter, r *http.Request, me *user.User, given string, wrong func()) bool {
	t := h.throttle()
	now := time.Now()
	key := ownPasswordKey(me.ID)
	if d := t.lockedFor(key, now); d > 0 {
		tooManyLoginAttempts(w, d)
		return false
	}
	err := user.CheckPassword(me.PasswordHash, given)
	if err == nil {
		return true
	}
	if errors.Is(err, user.ErrBusy) {
		// Not checked at all (the hashing slots stayed full), so neither
		// "the current password is wrong" nor one for the count.
		passwordCheckBusy(w)
		return false
	}
	if d := t.note(key, now, t.failLimit, t.failWindow, t.lockFor); d > 0 {
		h.UserRepo.Record(r.Context(), me.ID, me.Username, "own_password_check_locked", me.Username, adminClientIP(r, *h.cfg()))
		log.Printf("profile: %d wrong answers to the current-password question for user %d (%s); refused for %s", t.failLimit, me.ID, LogSafe(me.Username), d.Round(time.Second))
		tooManyLoginAttempts(w, d)
		return false
	}
	wrong()
	return false
}

// AdminProfileSave: POST /admin/profile/save — dispatch on op.
//
//	op="profile"  : update email / alert_opt_out.  Current password not required.
//	op="password" : verify current password + set new password.
func (h *Handler) AdminProfileSave(w http.ResponseWriter, r *http.Request) {
	if h.UserRepo == nil {
		http.Error(w, "user repo not configured", http.StatusInternalServerError)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	base := h.cfg().Server.BasePath
	lang := i18n.Resolve(r)
	redir := func(msgKey string) {
		dst := base + "/admin/profile/"
		if msgKey == "" {
			dst += "?saved=1"
		} else {
			setFlash(w, r, base, "err", i18n.T(lang, msgKey))
		}
		http.Redirect(w, r, dst, http.StatusFound)
	}
	pay := SessionFromContext(r)
	if pay == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	me, err := h.UserRepo.GetByID(r.Context(), pay.UserID)
	if err != nil {
		http.Error(w, "user not found", http.StatusInternalServerError)
		return
	}

	switch r.FormValue("op") {
	case "profile":
		email := strings.TrimSpace(r.FormValue("email"))
		alertOptOut := r.FormValue("alert_opt_out") == "1"
		// The address is where a password reset goes: changing it takes the
		// current password, as changing the password does.  With the
		// session alone, whoever held it could move the reset to an
		// address of their own and set the password from there.
		curEmail := ""
		if me.Email.Valid {
			curEmail = me.Email.String
		}
		if !strings.EqualFold(email, strings.TrimSpace(curEmail)) {
			if !h.checkOwnPassword(w, r, me, r.FormValue("email_current_password"), func() { redir("profile.err.email_current") }) {
				return
			}
		}
		if err := h.UserRepo.SetProfile(r.Context(), me.ID, email, alertOptOut); err != nil {
			log.Printf("profile: set profile for user %d: %v", me.ID, err)
			http.Error(w, "the profile could not be saved", http.StatusInternalServerError)
			return
		}
		h.UserRepo.Record(r.Context(), pay.UserID, me.Username, "user_update_own_profile", me.Username,
			fmt.Sprintf(`{"email":%q,"alert_opt_out":%v}`, email, alertOptOut))
		log.Printf("user updated own profile: %d %s", me.ID, me.Username)
		redir("")
		return

	case "password":
		if me.PasswordLocked {
			redir("profile.err.locked")
			return
		}
		cur := r.FormValue("current_password")
		newPass := r.FormValue("new_password")
		confirm := r.FormValue("confirm_password")
		if newPass == "" {
			redir("profile.err.empty")
			return
		}
		if newPass != confirm {
			redir("profile.err.mismatch")
			return
		}
		// Use the shared argon2 limit (1024), not the old bcrypt 72-byte cap:
		// the operator can reset another user's >72-char passphrase, so blocking
		// it only here left them unable to change their own password.
		if len(newPass) > user.MaxPasswordLen {
			redir("profile.err.too_long")
			return
		}
		// The floor the setup wizard and the CLI hold a new password to.
		// This page set whatever it was given, a single character included.
		if len(newPass) < user.MinPasswordLen {
			redir("profile.err.too_short")
			return
		}
		if !h.checkOwnPassword(w, r, me, cur, func() { redir("profile.err.current") }) {
			return
		}
		if err := h.UserRepo.SetPassword(r.Context(), me.ID, newPass); err != nil {
			log.Printf("profile: set password for user %d: %v", me.ID, err)
			http.Error(w, "the password could not be saved", http.StatusInternalServerError)
			return
		}
		// SetPassword ended the account's sessions; keep this one, which is
		// the operator making the change, on a cookie under the new
		// generation.  Every other device of theirs is signed out.
		h.reissueSessionAfterPasswordChange(w, r, me.ID)
		h.UserRepo.Record(r.Context(), pay.UserID, me.Username, "user_change_own_password", me.Username, "")
		log.Printf("user changed own password: %d %s", me.ID, me.Username)
		redir("")
		return

	default:
		redir("profile.err.unknown_op")
	}
}
