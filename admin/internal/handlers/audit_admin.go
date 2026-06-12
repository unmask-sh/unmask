// audit log viewer tab: visible to admin and above.
//
// Display: reverse chronological. 5 columns (user / action / target / detail / at).  paging via ?offset=N.
//
// Settings-save rows carry a JSON payload in `detail` (= before/after yaml
// snapshots + computed unified diff).  The template renders an expandable
// diff block per row plus a "restore" form to re-apply the captured `before`
// snapshot.  Limit: only the last 7 days are retained for rollback purposes
// (= pruned by PruneOldAudit on a daily schedule, configured elsewhere).
package handlers

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/unmask-sh/unmask/admin/internal/i18n"
	"github.com/unmask-sh/unmask/admin/internal/nginxconf"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

const auditPageSize = 100

// AuditSettingsDetail is the JSON payload stored on settings_save audit rows.
type AuditSettingsDetail struct {
	Section string `json:"section"`
	Before  string `json:"before,omitempty"` // full yaml snapshot pre-save
	After   string `json:"after,omitempty"`  // full yaml snapshot post-save
	Diff    string `json:"diff,omitempty"`   // unified-diff-ish text (changed lines only)
}

// auditEnriched: row + parsed detail (= the template renders Diff inline and
// shows the Restore button only when Before is present).
type auditEnriched struct {
	ID          int64
	UserID      int64
	UserIDValid bool
	Username    string
	Action      string
	Target      string
	At          string
	Section     string // settings_save only
	Diff        string
	HasBefore   bool
}

func (h *Handler) AdminAuditIndex(w http.ResponseWriter, r *http.Request) {
	if h.UserRepo == nil {
		http.Error(w, "user repo not configured", http.StatusInternalServerError)
		return
	}
	offset := 0
	// Pager partial (= pager_full) emits "?page=N" links; older bookmarks
	// may still use "?offset=N".  Accept both.
	if s := r.URL.Query().Get("page"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n >= 1 {
			offset = (n - 1) * auditPageSize
		}
	} else if s := r.URL.Query().Get("offset"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n >= 0 {
			offset = n
		}
	}
	entries, err := h.UserRepo.ListAudit(r.Context(), auditPageSize, offset, 0)
	if err != nil {
		http.Error(w, "list audit: "+err.Error(), http.StatusInternalServerError)
		return
	}
	enriched := make([]auditEnriched, 0, len(entries))
	for _, e := range entries {
		row := auditEnriched{
			ID:          e.ID,
			Username:    e.Username,
			Action:      e.Action,
			At:          e.At,
			UserIDValid: e.UserID.Valid,
		}
		if e.UserID.Valid {
			row.UserID = e.UserID.Int64
		}
		if e.Target.Valid {
			row.Target = e.Target.String
		}
		if (e.Action == "settings_save" || e.Action == "settings_snapshot") && e.Detail.Valid {
			var d AuditSettingsDetail
			if err := json.Unmarshal([]byte(e.Detail.String), &d); err == nil {
				row.Section = d.Section
				row.Diff = d.Diff
				row.HasBefore = d.Before != ""
			}
		}
		enriched = append(enriched, row)
	}
	tmpl, err := loadDashboardTemplate()
	if err != nil {
		http.Error(w, "template: "+err.Error(), http.StatusInternalServerError)
		return
	}
	hasMore := len(entries) == auditPageSize
	// Numbered pager: unmask_user_audit is small enough that COUNT(*) is
	// instant.  Use offset → 1-indexed page so the shared pager_full partial
	// can render "‹ 1 [2] 3 ›".
	totalRows, err := h.UserRepo.CountAudit(r.Context(), 0)
	if err != nil {
		log.Printf("audit count: %v", err)
		// Fall back to a "1 of 1+" view: total = offset+len(entries) (= the
		// best lower-bound we have without the count).  The pager will still
		// render but jump-by-number is degraded.
		totalRows = offset + len(entries)
	}
	page := offset/auditPageSize + 1
	totalPages := (totalRows + auditPageSize - 1) / auditPageSize
	if totalPages < 1 {
		totalPages = 1
	}
	pager := buildPagerData(i18n.Resolve(r), page, totalPages, auditPageSize, totalRows, "?")
	// Audit query string keeps "offset" semantics on the URL so existing
	// bookmarks keep working; pager_full emits "page=" links, so translate
	// inside the partial by overriding BaseURL to use a custom query param.
	// We simply convert page → offset by encoding a "page=N" link and letting
	// the handler accept either page= or offset=.
	data := map[string]any{
		"Lang":       i18n.Resolve(r),
		"TZ":         resolveTZ(r),
		"BasePath":   h.cfg().Server.BasePath,
		"Version":    h.Version,
		"Entries":    enriched,
		"Offset":     offset,
		"NextOffset": offset + auditPageSize,
		"PrevOffset": maxInt(offset-auditPageSize, 0),
		"HasMore":    hasMore,
		"HasPrev":    offset > 0,
		"Saved":      r.URL.Query().Get("saved") != "",
		"Error":      readFlash(w, r, h.cfg().Server.BasePath, "err"),
		"Pager":      pager,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	h.addMeToData(r, data)
	if err := tmpl.ExecuteTemplate(w, "audit.html", data); err != nil {
		log.Printf("audit render: %v", err)
	}
}

// AdminSettingsSnapshot: POST {base}/admin/settings/snapshot — captures the
// current live settings yaml as a named "settings_snapshot" audit row so the
// user can revert to this exact state later via the standard restore flow.
//
// Form fields:
//
//	name : optional label (e.g., "pre-promo", "v0.1-baseline").  Empty -> "manual".
//	note : free-text description (stored in detail.note for the UI).
//
// Differs from settings_save audit rows in that nothing is changed; this is a
// pure capture.  Listed alongside save rows on /admin/audit/ with its own pill.
func (h *Handler) AdminSettingsSnapshot(w http.ResponseWriter, r *http.Request) {
	if h.UserRepo == nil {
		http.Error(w, "user repo not configured", http.StatusInternalServerError)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		name = "manual"
	}
	if len(name) > 80 {
		name = name[:80]
	}
	curYAML, err := settings.MarshalYAML(h.snapshotSettings())
	if err != nil {
		http.Error(w, "marshal: "+err.Error(), http.StatusInternalServerError)
		return
	}
	det := AuditSettingsDetail{
		Section: "_snapshot:" + name,
		Before:  curYAML, // `before` is what restore will re-apply
		After:   curYAML, // same value: no mutation occurred
		Diff:    "(snapshot — no diff)",
	}
	if pay := SessionFromContext(r); pay != nil {
		username := ""
		if u, err := h.UserRepo.GetByID(r.Context(), pay.UserID); err == nil {
			username = u.Username
		}
		blob, _ := json.Marshal(det)
		h.UserRepo.Record(r.Context(), pay.UserID, username,
			"settings_snapshot", name, string(blob))
	}
	http.Redirect(w, r, h.cfg().Server.BasePath+"/admin/audit/?saved=1", http.StatusFound)
}

// AdminSettingsExport: GET {base}/admin/settings/export — sends the current
// settings yaml as a downloadable file.  No auth modification; admin-or-above
// only (= scoped by the route registration in main.go).
func (h *Handler) AdminSettingsExport(w http.ResponseWriter, r *http.Request) {
	// Redact secrets: the export is a config backup, not a secret dump.  Leaking
	// bv_secret (the session-signing key) would let an admin forge a superadmin
	// session + mint _bv bypass cookies; DB/SMTP/hub creds are likewise sensitive.
	body, err := settings.MarshalYAML(h.snapshotSettings().WithSecretsRedacted())
	if err != nil {
		http.Error(w, "marshal: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/x-yaml; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="unmask-config.yml"`)
	_, _ = w.Write([]byte(body))
}

// AdminAuditRestore: POST {base}/admin/audit/restore?id=N — re-applies the
// `before` yaml snapshot from audit row N as the live settings, then records
// a new audit row for the restore itself.
func (h *Handler) AdminAuditRestore(w http.ResponseWriter, r *http.Request) {
	if h.ConfigPath == "" {
		http.Error(w, "config path unknown", http.StatusBadRequest)
		return
	}
	if h.UserRepo == nil {
		http.Error(w, "user repo not configured", http.StatusInternalServerError)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	idStr := r.URL.Query().Get("id")
	if idStr == "" {
		idStr = r.FormValue("id")
	}
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id <= 0 {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	base := h.cfg().Server.BasePath
	redir := func(msg string) {
		dst := base + "/admin/audit/"
		if msg == "" {
			dst += "?saved=1"
		} else {
			setFlash(w, base, "err", msg)
		}
		http.Redirect(w, r, dst, http.StatusFound)
	}

	entry, err := h.UserRepo.GetAuditByID(r.Context(), id)
	if err != nil || entry == nil {
		redir("audit row not found")
		return
	}
	if (entry.Action != "settings_save" && entry.Action != "settings_snapshot") || !entry.Detail.Valid {
		redir("audit row is not a restorable settings_save / settings_snapshot")
		return
	}
	var d AuditSettingsDetail
	if err := json.Unmarshal([]byte(entry.Detail.String), &d); err != nil {
		redir("audit detail parse: " + err.Error())
		return
	}
	if d.Before == "" {
		redir("audit row has no `before` snapshot to restore")
		return
	}
	restored, err := settings.LoadFromYAML(d.Before)
	if err != nil {
		redir("snapshot parse: " + err.Error())
		return
	}
	// Capture current state for the new audit row (= "restore" is itself a save).
	curBefore, _ := settings.MarshalYAML(h.snapshotSettings())
	if err := settings.Save(restored, h.ConfigPath); err != nil {
		redir("save: " + err.Error())
		return
	}
	if err := nginxconf.Render(restored, "", h.Version); err != nil {
		redir("save ok / render failed: " + err.Error())
		return
	}
	settingsMu.Lock()
	h.settingsPtr.Store(&restored)
	settingsMu.Unlock()
	if h.IPGeo != nil {
		h.IPGeo.Reload(restored.IPGeo.MMDBPath, restored.IPGeo.MMDBASNPath)
	}

	// New audit row documenting the restore: target = source-row id;
	// detail = the diff from current state back to the restored snapshot.
	curAfter, _ := settings.MarshalYAML(restored)
	det := AuditSettingsDetail{
		Section: "_restore",
		Before:  curBefore,
		After:   curAfter,
		Diff:    UnifiedDiff(curBefore, curAfter),
	}
	if pay := SessionFromContext(r); pay != nil {
		username := ""
		if u, err := h.UserRepo.GetByID(r.Context(), pay.UserID); err == nil {
			username = u.Username
		}
		blob, _ := json.Marshal(det)
		h.UserRepo.Record(r.Context(), pay.UserID, username,
			"settings_save", "_restore:from_audit_"+strconv.FormatInt(id, 10), string(blob))
	}
	redir("")
}

// UnifiedDiff produces a compact unified-diff-style text from two snapshots.
// Only changed lines are emitted (= no surrounding context) so storage stays
// bounded — large preset / extra list edits otherwise blow the audit row past
// reasonable JSON sizes.  Truncated to 500 emitted lines.
func UnifiedDiff(before, after string) string {
	a := strings.Split(strings.TrimRight(before, "\n"), "\n")
	b := strings.Split(strings.TrimRight(after, "\n"), "\n")
	m, n := len(a), len(b)
	dp := make([][]int, m+1)
	for i := range dp {
		dp[i] = make([]int, n+1)
	}
	for i := 1; i <= m; i++ {
		for j := 1; j <= n; j++ {
			if a[i-1] == b[j-1] {
				dp[i][j] = dp[i-1][j-1] + 1
			} else if dp[i-1][j] >= dp[i][j-1] {
				dp[i][j] = dp[i-1][j]
			} else {
				dp[i][j] = dp[i][j-1]
			}
		}
	}
	const maxLines = 500
	out := make([]string, 0, 64)
	var walk func(i, j int)
	walk = func(i, j int) {
		if len(out) > maxLines {
			return
		}
		switch {
		case i > 0 && j > 0 && a[i-1] == b[j-1]:
			walk(i-1, j-1)
		case j > 0 && (i == 0 || dp[i][j-1] >= dp[i-1][j]):
			walk(i, j-1)
			out = append(out, "+ "+b[j-1])
		case i > 0:
			walk(i-1, j)
			out = append(out, "- "+a[i-1])
		}
	}
	walk(m, n)
	if len(out) > maxLines {
		out = append(out[:maxLines], "  ... (diff truncated)")
	}
	if len(out) == 0 {
		return "(no changes)"
	}
	return strings.Join(out, "\n")
}

// auditWriteSettingsSave: shared between AdminSettingsSave and any other
// caller that needs to record a settings_save audit with before/after diff.
// Pass nil ctx to fall back to context.Background.
func auditWriteSettingsSave(ctx context.Context, h *Handler, userID int64,
	username, section, beforeYAML, afterYAML string) {
	if h.UserRepo == nil {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	det := AuditSettingsDetail{
		Section: section,
		Before:  beforeYAML,
		After:   afterYAML,
		Diff:    UnifiedDiff(beforeYAML, afterYAML),
	}
	blob, _ := json.Marshal(det)
	h.UserRepo.Record(ctx, userID, username, "settings_save", section, string(blob))
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
