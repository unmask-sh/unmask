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
	"fmt"
	"log"
	"net/http"
	"strings"

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
		http.Error(w, "template: "+err.Error(), http.StatusInternalServerError)
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
		"BasePath": h.Settings.Server.BasePath,
		"Version":  h.Version,
		"Saved":    r.URL.Query().Get("saved") != "",
		"Error":    readFlash(w, r, h.Settings.Server.BasePath, "err"),
		"Me":       pay,
		"User":     me,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	h.addMeToData(r, data)
	if err := tmpl.ExecuteTemplate(w, "profile.html", data); err != nil {
		log.Printf("profile render: %v", err)
	}
}

// AdminProfileSave: POST /admin/profile/save — dispatch on op.
//   op="profile"  : update email / alert_opt_out.  Current password not required.
//   op="password" : verify current password + set new password.
func (h *Handler) AdminProfileSave(w http.ResponseWriter, r *http.Request) {
	if h.UserRepo == nil {
		http.Error(w, "user repo not configured", http.StatusInternalServerError)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	base := h.Settings.Server.BasePath
	lang := i18n.Resolve(r)
	redir := func(msgKey string) {
		dst := base + "/admin/profile/"
		if msgKey == "" {
			dst += "?saved=1"
		} else {
			setFlash(w, base, "err", i18n.T(lang, msgKey))
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
		if err := h.UserRepo.SetProfile(r.Context(), me.ID, email, alertOptOut); err != nil {
			http.Error(w, "set profile: "+err.Error(), http.StatusInternalServerError)
			return
		}
		h.UserRepo.Record(r.Context(), pay.UserID, me.Username, "user_update_own_profile", me.Username,
			fmt.Sprintf(`{"email":%q,"alert_opt_out":%v}`, email, alertOptOut))
		log.Printf("user updated own profile: %d %s", me.ID, me.Username)
		redir("")
		return

	case "password", "":
		// "" is backward-compat (= legacy form had no op).
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
		if len(newPass) > 72 {
			redir("profile.err.too_long")
			return
		}
		if err := user.CheckPassword(me.PasswordHash, cur); err != nil {
			redir("profile.err.current")
			return
		}
		if err := h.UserRepo.SetPassword(r.Context(), me.ID, newPass); err != nil {
			http.Error(w, "set password: "+err.Error(), http.StatusInternalServerError)
			return
		}
		h.UserRepo.Record(r.Context(), pay.UserID, me.Username, "user_change_own_password", me.Username, "")
		log.Printf("user changed own password: %d %s", me.ID, me.Username)
		redir("")
		return

	default:
		redir("profile.err.unknown_op")
	}
}
