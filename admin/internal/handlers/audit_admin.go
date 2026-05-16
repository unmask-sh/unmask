// audit log viewer tab: visible to admin and above.
//
// Display: reverse chronological. 5 columns (user / action / target / detail / at).  paging via ?offset=N.
package handlers

import (
	"log"
	"net/http"
	"strconv"

	"github.com/unmask-sh/unmask/admin/internal/i18n"
)

const auditPageSize = 100

func (h *Handler) AdminAuditIndex(w http.ResponseWriter, r *http.Request) {
	if h.UserRepo == nil {
		http.Error(w, "user repo not configured", http.StatusInternalServerError)
		return
	}
	offset := 0
	if s := r.URL.Query().Get("offset"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n >= 0 {
			offset = n
		}
	}
	entries, err := h.UserRepo.ListAudit(r.Context(), auditPageSize, offset, 0)
	if err != nil {
		http.Error(w, "list audit: "+err.Error(), http.StatusInternalServerError)
		return
	}
	tmpl, err := loadDashboardTemplate()
	if err != nil {
		http.Error(w, "template: "+err.Error(), http.StatusInternalServerError)
		return
	}
	hasMore := len(entries) == auditPageSize
	data := map[string]any{
		"Lang":     i18n.Resolve(r),
		"TZ":       resolveTZ(r),
		"BasePath": h.Settings.Server.BasePath,
		"Version":  h.Version,
		"Entries":  entries,
		"Offset":   offset,
		"NextOffset": offset + auditPageSize,
		"PrevOffset": maxInt(offset-auditPageSize, 0),
		"HasMore":  hasMore,
		"HasPrev":  offset > 0,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	h.addMeToData(r, data)
	if err := tmpl.ExecuteTemplate(w, "audit.html", data); err != nil {
		log.Printf("audit render: %v", err)
	}
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
