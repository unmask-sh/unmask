package handlers

import (
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/unmask-sh/unmask/admin/internal/communitybans"
	"github.com/unmask-sh/unmask/admin/internal/i18n"
)

// Hub-operator removal review screen.
//
// Only the operator running unmask.sh sees this -- gated on
// CommunityBans.OperatorEndpoint + OperatorTokenFile being set.  Everyone
// else gets a 404 so a bug report that mentions it doesn't pretend it's
// available to non-operators.

func (h *Handler) operatorClient() *communitybans.OperatorClient {
	cur := h.snapshotSettings()
	return &communitybans.OperatorClient{
		Endpoint:  cur.CommunityBans.OperatorEndpoint,
		TokenFile: cur.CommunityBans.OperatorTokenFile,
	}
}

// AdminRemovalRequestsIndex: GET /admin/community-bans/removals.  Lists
// removal requests for the operator.  Filterable by ?status= (pending /
// done / rejected / all; default pending).
func (h *Handler) AdminRemovalRequestsIndex(w http.ResponseWriter, r *http.Request) {
	tmpl, err := loadDashboardTemplate()
	if err != nil {
		log.Printf("removal-requests load template: %v", err)
		http.Error(w, "template", http.StatusInternalServerError)
		return
	}
	cli := h.operatorClient()
	if !cli.IsConfigured() {
		http.NotFound(w, r)
		return
	}
	status := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("status")))
	if status == "" {
		status = "pending"
	}
	rows, fetchErr := cli.ListRemovals(r.Context(), status)
	flash := strings.TrimSpace(r.URL.Query().Get("flash"))
	flashErr := strings.TrimSpace(r.URL.Query().Get("err"))

	// Counts per status for the filter tabs.  Best-effort: a hub error
	// degrades to "—" in the UI without breaking the page.
	counts := map[string]int{"pending": 0, "done": 0, "rejected": 0}
	if all, err := cli.ListRemovals(r.Context(), "all"); err == nil {
		for _, row := range all {
			counts[row.Status]++
		}
	}

	data := map[string]any{
		"Lang":          i18n.Resolve(r),
		"TZ":            resolveTZ(r),
		"BasePath":      h.cfg().Server.BasePath,
		"Version":       h.Version,
		"FilterStatus":  status,
		"Rows":          rows,
		"FetchErr":      fetchErr,
		"Flash":         flash,
		"FlashErr":      flashErr,
		"CountPending":  counts["pending"],
		"CountDone":     counts["done"],
		"CountRejected": counts["rejected"],
	}
	h.addMeToData(r, data)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.ExecuteTemplate(w, "removal_requests.html", data); err != nil {
		log.Printf("removal-requests render: %v", err)
	}
}

// AdminRemovalRequestPatch: POST /admin/community-bans/removals/{id}.
// Form fields: status=done|rejected.  PATCHes the hub then redirects back
// to the list with a flash (= no JSON / fetch -- keeps the screen working
// without JS).
func (h *Handler) AdminRemovalRequestPatch(w http.ResponseWriter, r *http.Request) {
	cli := h.operatorClient()
	if !cli.IsConfigured() {
		http.NotFound(w, r)
		return
	}
	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id <= 0 {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	status := strings.ToLower(strings.TrimSpace(r.FormValue("status")))
	if status != "done" && status != "rejected" {
		http.Error(w, "bad status", http.StatusBadRequest)
		return
	}
	base := h.cfg().Server.BasePath + "/admin/community-bans/removals"
	back := base + "?status=pending"
	if err := cli.PatchRemoval(r.Context(), id, status); err != nil {
		log.Printf("removal patch id=%d status=%s: %v", id, LogSafe(status), err)
		http.Redirect(w, r, back+"&err=patch+failed", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, back+"&flash=updated", http.StatusSeeOther)
}
