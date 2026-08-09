package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/unmask-sh/unmask/admin/internal/nginxconf"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// AdminUpgradeReviewApply acknowledges the held enforcement upgrade posted from
// the dashboard banner: it advances enforcement_reviewed_version to this binary's
// version so every held preset activates, records an audit entry, and (native
// mode) re-renders the conf so a reload picks the presets up.  A no-op when
// nothing is held (already acknowledged, or the policy is "apply").
func (h *Handler) AdminUpgradeReviewApply(w http.ResponseWriter, r *http.Request) {
	base := h.cfg().Server.BasePath
	dash := base + "/admin/"
	if h.ConfigPath == "" {
		setFlash(w, r, base, "err", "config path unknown — cannot persist")
		http.Redirect(w, r, dash, http.StatusFound)
		return
	}
	cur, err := settings.Load(h.ConfigPath)
	if err != nil {
		setFlash(w, r, base, "err", "load: "+err.Error())
		http.Redirect(w, r, dash, http.StatusFound)
		return
	}
	held := nginxconf.HeldEnforcementPresets(cur)
	if len(held) == 0 {
		http.Redirect(w, r, dash, http.StatusFound) // nothing to acknowledge
		return
	}

	// reload-prompt only when the rendered conf actually changed (it will, since
	// held presets become active); errors conservatively assume a reload.
	reloadNeeded := true
	if beforeSig, beforeErr := nginxconf.RenderSignature(cur, "", h.Version); beforeErr == nil {
		cur.Nginx.EnforcementReviewedVersion = "v" + h.Version
		if afterSig, afterErr := nginxconf.RenderSignature(cur, "", h.Version); afterErr == nil {
			reloadNeeded = afterSig != beforeSig
		}
	} else {
		cur.Nginx.EnforcementReviewedVersion = "v" + h.Version
	}

	if err := settings.Save(cur, h.ConfigPath); err != nil {
		setFlash(w, r, base, "err", "save: "+err.Error())
		http.Redirect(w, r, dash, http.StatusFound)
		return
	}
	if err := nginxconf.Render(cur, "", h.Version); err != nil {
		setFlash(w, r, base, "err", "saved, but nginx render failed: "+err.Error())
		http.Redirect(w, r, dash, http.StatusFound)
		return
	}
	// Publish to the running config, exactly as AdminSettingsSave does -- without
	// this the in-memory snapshot stays stale, so the banner would persist and
	// the forward-auth matcher would keep holding the presets until a restart.
	h.SetSettings(cur)

	if pay := SessionFromContext(r); pay != nil && h.UserRepo != nil {
		username := ""
		if u, uerr := h.UserRepo.GetByID(r.Context(), pay.UserID); uerr == nil && u != nil {
			username = u.Username
		}
		ids := make([]string, 0, len(held))
		for _, hp := range held {
			ids = append(ids, hp.Category+":"+hp.ID)
		}
		blob, _ := json.Marshal(map[string]any{
			"reviewed_version": cur.Nginx.EnforcementReviewedVersion,
			"applied":          ids,
		})
		h.UserRepo.Record(r.Context(), pay.UserID, username, "upgrade_review_apply",
			cur.Nginx.EnforcementReviewedVersion, string(blob))
	}

	dst := dash + "?upgrade_applied=1"
	if reloadNeeded {
		dst += "&reload=1"
	}
	http.Redirect(w, r, dst, http.StatusFound)
}
