// users management tab: superadmin only.
//
// Row UI list + a "new user" form at the bottom + edit / reset / delete on each row.
// Everything is received by a single endpoint (= POST /admin/users/save) and dispatched by op:
//
//	op=create                 → create new with username + password + role
//	op=set_role&id=<id>       → change role
//	op=reset_password&id=<id> → change password
//	op=delete&id=<id>         → delete
//
// The schema is simple, so we do not "bulk-save the row UI"; each operation is one atomic POST.
package handlers

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/unmask-sh/unmask/admin/internal/i18n"
	"github.com/unmask-sh/unmask/admin/internal/user"
)

// AdminUsersIndex: GET /admin/users/ — user list + new-user form.
func (h *Handler) AdminUsersIndex(w http.ResponseWriter, r *http.Request) {
	if h.UserRepo == nil {
		http.Error(w, "user repo not configured", http.StatusInternalServerError)
		return
	}
	users, err := h.UserRepo.List(r.Context())
	if err != nil {
		http.Error(w, "list users: "+err.Error(), http.StatusInternalServerError)
		return
	}
	tmpl, err := loadDashboardTemplate()
	if err != nil {
		http.Error(w, "template: "+err.Error(), http.StatusInternalServerError)
		return
	}
	pay := SessionFromContext(r)
	data := map[string]any{
		"Lang":     i18n.Resolve(r),
		"TZ":       resolveTZ(r),
		"BasePath": h.cfg().Server.BasePath,
		"Version":  h.Version,
		"Users":    users,
		"Saved":    r.URL.Query().Get("saved") != "",
		"Error":    readFlash(w, r, h.cfg().Server.BasePath, "err"),
		"Me":       pay,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	h.addMeToData(r, data)
	if err := tmpl.ExecuteTemplate(w, "users.html", data); err != nil {
		log.Printf("users render: %v", err)
	}
}

// AdminUsersNew: GET /admin/users/new — new-user form on its own page.
// The inline form that used to sit at the bottom of the list page has been removed and moved here.
func (h *Handler) AdminUsersNew(w http.ResponseWriter, r *http.Request) {
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
	data := map[string]any{
		"Lang":     i18n.Resolve(r),
		"TZ":       resolveTZ(r),
		"BasePath": h.cfg().Server.BasePath,
		"Version":  h.Version,
		"Error":    readFlash(w, r, h.cfg().Server.BasePath, "err"),
		"Me":       pay,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	h.addMeToData(r, data)
	if err := tmpl.ExecuteTemplate(w, "users_new.html", data); err != nil {
		log.Printf("users_new render: %v", err)
	}
}

// AdminUsersEdit: GET /admin/users/{id}/edit — detail-edit page for a single user.
// The list page (= AdminUsersIndex) is read-only, so editing is consolidated here.
// role / profile / password reset / delete live as separate cards, one POST per action.
func (h *Handler) AdminUsersEdit(w http.ResponseWriter, r *http.Request) {
	if h.UserRepo == nil {
		http.Error(w, "user repo not configured", http.StatusInternalServerError)
		return
	}
	uid, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || uid <= 0 {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	target, err := h.UserRepo.GetByID(r.Context(), uid)
	if err != nil {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}
	tmpl, err := loadDashboardTemplate()
	if err != nil {
		http.Error(w, "template: "+err.Error(), http.StatusInternalServerError)
		return
	}
	pay := SessionFromContext(r)
	data := map[string]any{
		"Lang":     i18n.Resolve(r),
		"TZ":       resolveTZ(r),
		"BasePath": h.cfg().Server.BasePath,
		"Version":  h.Version,
		"User":     target,
		"Saved":    r.URL.Query().Get("saved") != "",
		"Error":    readFlash(w, r, h.cfg().Server.BasePath, "err"),
		"Me":       pay,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	h.addMeToData(r, data)
	if err := tmpl.ExecuteTemplate(w, "users_edit.html", data); err != nil {
		log.Printf("users_edit render: %v", err)
	}
}

// AdminUsersSave: POST /admin/users/save — dispatch by op parameter.
func (h *Handler) AdminUsersSave(w http.ResponseWriter, r *http.Request) {
	if h.UserRepo == nil {
		http.Error(w, "user repo not configured", http.StatusInternalServerError)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	base := h.cfg().Server.BasePath
	// Redirect target: the form's hidden "redirect" field can route back to
	// the detail page.  Values are restricted to be under base (= open
	// redirect prevention) + "?saved=1" appended as a query.
	redirTo := strings.TrimSpace(r.FormValue("redirect"))
	if !strings.HasPrefix(redirTo, base+"/admin/") {
		redirTo = base + "/admin/users/"
	}
	redir := func(msg string) {
		dst := redirTo
		if msg == "" {
			sep := "?"
			if strings.Contains(dst, "?") {
				sep = "&"
			}
			dst += sep + "saved=1"
		} else {
			setFlash(w, r, base, "err", msg)
		}
		http.Redirect(w, r, dst, http.StatusFound)
	}

	pay := SessionFromContext(r)
	if pay == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	meUsername := ""
	if me, err := h.UserRepo.GetByID(r.Context(), pay.UserID); err == nil {
		meUsername = me.Username
	}

	op := r.FormValue("op")
	switch op {
	case "update":
		// Single-form save from the detail edit page: apply role / email /
		// alert_opt_out / (optional) password in one request.  Empty password
		// is skipped (= no change).
		uid, err := strconv.ParseInt(r.FormValue("id"), 10, 64)
		if err != nil || uid <= 0 {
			redir("invalid id")
			return
		}
		newRole := r.FormValue("role")
		if !user.IsValidRole(newRole) {
			redir("invalid role: " + newRole)
			return
		}
		email := strings.TrimSpace(r.FormValue("email"))
		alertOptOut := r.FormValue("alert_opt_out") == "1"
		newPass := r.FormValue("password")

		// Call SetRole if the role differs from the current one.  The
		// "cannot demote the last superadmin" check is done inside SetRole.
		current, err := h.UserRepo.GetByID(r.Context(), uid)
		if err != nil {
			redir("user not found")
			return
		}
		if current.Role != newRole {
			if err := h.UserRepo.SetRole(r.Context(), uid, newRole); err != nil {
				redir(roleErrMsg(err))
				return
			}
		}
		// profile (= email / alert_opt_out) is always SetProfile-d.
		if err := h.UserRepo.SetProfile(r.Context(), uid, email, alertOptOut); err != nil {
			redir("set profile: " + err.Error())
			return
		}
		// Apply password if non-empty.  Track via a bool for audit branching.
		passChanged := false
		if newPass != "" {
			if err := h.UserRepo.SetPassword(r.Context(), uid, newPass); err != nil {
				redir("reset password: " + err.Error())
				return
			}
			passChanged = true
		}
		targetUsername := current.Username
		h.UserRepo.Record(r.Context(), pay.UserID, meUsername, "user_update", targetUsername,
			fmt.Sprintf(`{"role":%q,"email":%q,"alert_opt_out":%v,"password_changed":%v}`, newRole, email, alertOptOut, passChanged))
		redir("")
		return

	case "create":
		username := strings.TrimSpace(r.FormValue("username"))
		password := r.FormValue("password")
		role := r.FormValue("role")
		if username == "" || password == "" {
			redir("username and password are required")
			return
		}
		if !user.IsValidRole(role) {
			redir("invalid role: " + role)
			return
		}
		email := strings.TrimSpace(r.FormValue("email"))
		alertOptOut := r.FormValue("alert_opt_out") == "1"
		u, err := h.UserRepo.CreateWithProfile(r.Context(), username, password, role, email, alertOptOut)
		if err != nil {
			redir("create: " + err.Error())
			return
		}
		h.UserRepo.Record(r.Context(), pay.UserID, meUsername, "user_create", username, fmt.Sprintf(`{"role":%q,"email":%q}`, role, email))
		log.Printf("user created: %d %s role=%s by=%s", u.ID, u.Username, u.Role, meUsername)
		redir("")
		return

	case "set_profile":
		uid, err := strconv.ParseInt(r.FormValue("id"), 10, 64)
		if err != nil || uid <= 0 {
			redir("invalid id")
			return
		}
		email := strings.TrimSpace(r.FormValue("email"))
		alertOptOut := r.FormValue("alert_opt_out") == "1"
		if err := h.UserRepo.SetProfile(r.Context(), uid, email, alertOptOut); err != nil {
			redir("set profile: " + err.Error())
			return
		}
		targetUsername := ""
		if u, err := h.UserRepo.GetByID(r.Context(), uid); err == nil {
			targetUsername = u.Username
		}
		h.UserRepo.Record(r.Context(), pay.UserID, meUsername, "user_set_profile", targetUsername, fmt.Sprintf(`{"email":%q,"alert_opt_out":%v}`, email, alertOptOut))
		redir("")
		return

	case "set_role":
		uid, err := strconv.ParseInt(r.FormValue("id"), 10, 64)
		if err != nil || uid <= 0 {
			redir("invalid id")
			return
		}
		newRole := r.FormValue("role")
		if !user.IsValidRole(newRole) {
			redir("invalid role: " + newRole)
			return
		}
		if err := h.UserRepo.SetRole(r.Context(), uid, newRole); err != nil {
			redir(roleErrMsg(err))
			return
		}
		// Resolve the target username for the audit record too.
		targetUsername := ""
		if u, err := h.UserRepo.GetByID(r.Context(), uid); err == nil {
			targetUsername = u.Username
		}
		h.UserRepo.Record(r.Context(), pay.UserID, meUsername, "user_set_role", targetUsername, fmt.Sprintf(`{"role":%q}`, newRole))
		redir("")
		return

	case "reset_password":
		uid, err := strconv.ParseInt(r.FormValue("id"), 10, 64)
		if err != nil || uid <= 0 {
			redir("invalid id")
			return
		}
		newPass := r.FormValue("password")
		if newPass == "" {
			redir("password is empty")
			return
		}
		if err := h.UserRepo.SetPassword(r.Context(), uid, newPass); err != nil {
			redir("reset: " + err.Error())
			return
		}
		targetUsername := ""
		if u, err := h.UserRepo.GetByID(r.Context(), uid); err == nil {
			targetUsername = u.Username
		}
		h.UserRepo.Record(r.Context(), pay.UserID, meUsername, "user_reset_password", targetUsername, "")
		redir("")
		return

	case "delete":
		// After delete the target user is gone, so we can't return to the
		// detail page.  Force the user back to the list.
		redirTo = base + "/admin/users/"
		uid, err := strconv.ParseInt(r.FormValue("id"), 10, 64)
		if err != nil || uid <= 0 {
			redir("invalid id")
			return
		}
		// Cannot delete yourself (= the UI hides the button, but be defensive)
		if uid == pay.UserID {
			redir("cannot delete yourself")
			return
		}
		// target username (= for logging)
		targetUsername := ""
		if u, err := h.UserRepo.GetByID(r.Context(), uid); err == nil {
			targetUsername = u.Username
		}
		if err := h.UserRepo.Delete(r.Context(), uid); err != nil {
			redir(roleErrMsg(err))
			return
		}
		h.UserRepo.Record(r.Context(), pay.UserID, meUsername, "user_delete", targetUsername, "")
		redir("")
		return

	default:
		redir("unknown op: " + op)
	}
}

// roleErrMsg: convert business errors like "the last superadmin" into a user-facing message.
func roleErrMsg(err error) string {
	if errors.Is(err, user.ErrLastSuperadmin) {
		return "cannot remove the last superadmin"
	}
	if errors.Is(err, user.ErrNotFound) {
		return "user not found"
	}
	return err.Error()
}
