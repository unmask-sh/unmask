// advisor_admin.go — /admin/advisor/: the deterministic ban-candidate page
// (Phase 1 of the AI-advisor design).  The engine (internal/advisor) proposes;
// this page shows the evidence and hands each row to a human, who either
// applies a ban through the ordinary /admin/bans/save path or dismisses the
// suggestion.  Nothing is ever applied automatically.
package handlers

import (
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"gorm.io/gorm/clause"

	"github.com/unmask-sh/unmask/admin/internal/advisor"
	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/i18n"
)

// AdminAdvisorIndex: GET {base}/admin/advisor/
func (h *Handler) AdminAdvisorIndex(w http.ResponseWriter, r *http.Request) {
	tmpl, err := loadDashboardTemplate()
	if err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}

	windowH := 24
	if v, err := strconv.Atoi(r.URL.Query().Get("window")); err == nil && v >= 1 && v <= 24*14 {
		windowH = v
	}

	excl, err := h.advisorExclusions(r)
	if err != nil {
		log.Printf("advisor exclusions: %v", err)
	}
	cands, err := advisor.Candidates(r.Context(), h.DB, h.IPGeo, excl,
		advisor.Options{WindowMinutes: windowH * 60})
	engineErr := ""
	if err != nil {
		// Render the page with the error rather than a bare 500: the operator
		// still gets the frame, the window picker and the explanation.
		engineErr = err.Error()
	}

	data := map[string]any{
		"Lang":       i18n.Resolve(r),
		"TZ":         resolveTZ(r),
		"BasePath":   h.cfg().Server.BasePath,
		"Version":    h.Version,
		"Candidates": cands,
		"WindowH":    windowH,
		"EngineErr":  engineErr,
		"Saved":      r.URL.Query().Get("saved") != "",
		"Dismissed":  r.URL.Query().Get("dismissed") != "",
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	h.addMeToData(r, data)
	if err := tmpl.ExecuteTemplate(w, "advisor.html", data); err != nil {
		log.Printf("advisor render: %v", err)
	}
}

// AdminAdvisorDismiss: POST {base}/admin/advisor/dismiss — remember that the
// operator rejected one candidate so it stops being proposed.
func (h *Handler) AdminAdvisorDismiss(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	base := h.cfg().Server.BasePath
	targetType := strings.TrimSpace(r.FormValue("target_type"))
	target := strings.TrimSpace(r.FormValue("target"))
	if (targetType != "ip" && targetType != "ja4") || target == "" || len(target) > 64 {
		http.Error(w, "bad target", http.StatusBadRequest)
		return
	}
	me := ""
	if pay := SessionFromContext(r); pay != nil {
		if u, err := h.UserRepo.GetByID(r.Context(), pay.UserID); err == nil {
			me = u.Username
		}
	}
	row := db.AdvisorDismiss{
		TargetType:  targetType,
		Target:      target,
		DismissedBy: me,
		DismissedAt: time.Now().UTC().Unix(),
	}
	if err := h.DB.Gorm.WithContext(r.Context()).
		Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "target_type"}, {Name: "target"}},
			DoUpdates: clause.AssignmentColumns([]string{"dismissed_by", "dismissed_at"}),
		}).Create(&row).Error; err != nil {
		log.Printf("advisor dismiss: %v", err)
		http.Error(w, "store error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, base+"/admin/advisor/?dismissed=1", http.StatusFound)
}

// advisorExclusions assembles everything the engine must never propose:
// existing bans, dismissed candidates, and the install's own monitoring
// addresses (stats_exclude_ips).
func (h *Handler) advisorExclusions(r *http.Request) (advisor.Exclusions, error) {
	excl := advisor.Exclusions{
		BannedIPs:    map[string]bool{},
		BannedJA4s:   map[string]bool{},
		DismissedIP:  map[string]bool{},
		DismissedJA4: map[string]bool{},
		ExcludeIPs:   map[string]bool{},
	}
	for _, ip := range h.cfg().Nginx.StatsExcludeIPs {
		excl.ExcludeIPs[strings.TrimSpace(ip)] = true
	}
	var bans []db.Ban
	if err := h.DB.Gorm.WithContext(r.Context()).Find(&bans).Error; err != nil {
		return excl, err
	}
	for _, b := range bans {
		if b.IP != "" {
			excl.BannedIPs[b.IP] = true
		}
		if b.JA4 != "" {
			excl.BannedJA4s[b.JA4] = true
		}
	}
	var dis []db.AdvisorDismiss
	if err := h.DB.Gorm.WithContext(r.Context()).Find(&dis).Error; err != nil {
		return excl, err
	}
	for _, d := range dis {
		if d.TargetType == "ja4" {
			excl.DismissedJA4[d.Target] = true
		} else {
			excl.DismissedIP[d.Target] = true
		}
	}
	return excl, nil
}
