// audit log viewer tab: visible to admin and above.
//
// Display: reverse chronological. 5 columns (user / action / target / detail / at).  paging via ?offset=N.
//
// Settings-save rows carry a JSON payload in `detail` (= before/after yaml
// snapshots, secrets redacted, + computed unified diff).  The template
// renders an expandable diff block per row plus a "restore" form to re-apply
// the captured `before` snapshot (with the live secrets put back).  Limit:
// only the last 7 days are retained for rollback purposes (= pruned by
// PruneOldAudit on a daily schedule, configured elsewhere).
package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/unmask-sh/unmask/admin/internal/i18n"
	"github.com/unmask-sh/unmask/admin/internal/nginxconf"
	"github.com/unmask-sh/unmask/admin/internal/settings"
	"github.com/unmask-sh/unmask/admin/internal/user"
)

const auditPageSize = 100

// AuditSettingsDetail is the JSON payload stored on settings_save audit rows.
type AuditSettingsDetail struct {
	Section string `json:"section"`
	Before  string `json:"before,omitempty"` // full yaml snapshot pre-save, secrets redacted (auditSnapshotYAML)
	After   string `json:"after,omitempty"`  // full yaml snapshot post-save, likewise
	Diff    string `json:"diff,omitempty"`   // unified-diff-ish text (changed lines only)
}

// auditSnapshotYAML is the yaml an audit row stores for a Settings: the
// canonical form (settings.MarshalYAML) with every credential replaced by
// the redaction marker.  A row is kept for the retention window and shown,
// diffed, to the admin role, so a key that passed through one in the clear
// would outlive its rotation there -- bv_secret among them, which signs the
// admin sessions.  AdminAuditRestore puts the live values back where the
// marker is (Settings.WithSecretsFrom).  One consequence to know: a rotated
// secret redacts to the same marker on both sides, so the row's diff does
// not show that it changed.
func auditSnapshotYAML(s settings.Settings) (string, error) {
	return settings.MarshalYAML(s.WithSecretsRedacted())
}

// auditEnriched: row + parsed detail (= the template renders Diff inline and
// shows the Restore button only when Before is present).
type auditEnriched struct {
	ID          int64
	UserID      int64
	UserIDValid bool
	// System: the daemon's own entry (an install, an update, a schema update)
	// or a shell's -- no account, and not anonymous either.
	System    bool
	Username  string
	Action    string
	Target    string
	IP        string // where the action came from; empty for pre-0024 rows and CLI callers
	At        string
	Section   string // settings_save only
	Diff      string
	HasBefore bool
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
		log.Printf("audit: list: %v", err)
		http.Error(w, "the audit log could not be read", http.StatusInternalServerError)
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
			System:      !e.UserID.Valid && user.IsSystemActor(e.Username),
			IP:          e.IP.String,
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
		"Lang":            i18n.Resolve(r),
		"SnapshotNameMax": snapshotNameMax,
		"TZ":              resolveTZ(r),
		"BasePath":        h.cfg().Server.BasePath,
		"Version":         h.Version,
		"Entries":         enriched,
		"Offset":          offset,
		"NextOffset":      offset + auditPageSize,
		"PrevOffset":      maxInt(offset-auditPageSize, 0),
		"HasMore":         hasMore,
		"HasPrev":         offset > 0,
		"Saved":           r.URL.Query().Get("saved") != "",
		"Error":           readFlash(w, r, h.cfg().Server.BasePath, "err"),
		"Pager":           pager,
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
// snapshotNameMax bounds a snapshot's name; audit.html carries it on the field.
const snapshotNameMax = 80

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
	// Refused with the limit, as the page refuses it while typing; this is for
	// a request that did not come through the page.  In characters: a byte
	// count cut a Japanese name at a third of that, mid-character.
	if utf8.RuneCountInString(name) > snapshotNameMax {
		http.Error(w, i18n.Tf(i18n.Resolve(r), "err.value_long", snapshotNameMax), http.StatusBadRequest)
		return
	}
	curYAML, err := auditSnapshotYAML(h.snapshotSettings())
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
			setFlash(w, r, base, "err", msg)
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
	// The snapshot carries the redaction marker where a secret was
	// (auditSnapshotYAML), so each takes its live value back before the
	// write; the marker would otherwise replace the real key -- bv_secret
	// first of all, which logs every admin out.  A row from before the
	// redaction holds the key itself and restores as it always did.
	// The live values are taken under the settings lock, from the file this
	// restore replaces, so a save that lands between reading them and writing
	// the snapshot is not what gets overwritten, and no secret of it is lost.
	var curBefore string
	restored, err = h.mutateSettings(func(live *settings.Settings) error {
		// Capture current state for the new audit row (= "restore" is itself a save).
		curBefore, _ = auditSnapshotYAML(*live)
		*live = restored.WithSecretsFrom(*live)
		return nil
	})
	if err != nil {
		redir(err.Error())
		return
	}
	if err := nginxconf.RenderFor(restored, "", h.Version, nginxconf.RenderCause{Kind: nginxconf.RenderByRestore}); err != nil {
		redir("save ok / render failed: " + err.Error())
		return
	}
	if h.IPGeo != nil {
		h.IPGeo.Reload(restored.IPGeo.MMDBPath, restored.IPGeo.MMDBASNPath)
	}

	// New audit row documenting the restore: target = source-row id;
	// detail = the diff from current state back to the restored snapshot.
	curAfter, _ := auditSnapshotYAML(restored)
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

// maxDiffCells bounds the table UnifiedDiff builds, in cells (four bytes
// each).  See the note where it is used.
const maxDiffCells = 4 << 20

// diffMaxLines is how many changed lines an audit row keeps.
const diffMaxLines = 500

// UnifiedDiff produces a compact unified-diff-style text from two snapshots.
// Only changed lines are emitted (= no surrounding context) so storage stays
// bounded — large preset / extra list edits otherwise blow the audit row past
// reasonable JSON sizes.  Truncated to 500 emitted lines.
func UnifiedDiff(before, after string) string {
	a := strings.Split(strings.TrimRight(before, "\n"), "\n")
	b := strings.Split(strings.TrimRight(after, "\n"), "\n")
	// A save changes a few lines of a snapshot that an install with long
	// lists makes tens of thousands of lines long, and the table of a
	// longest-common-subsequence diff is quadratic in what it is given: the
	// whole of two 10,000-line snapshots was 100 million cells, most of a
	// gigabyte allocated in the daemon that is also serving challenges, for
	// a diff of one line.  The lines the two share at the start and at the
	// end belong to a longest common subsequence whatever lies between, so
	// they are set aside first and the table covers the middle alone.
	for len(a) > 0 && len(b) > 0 && a[0] == b[0] {
		a, b = a[1:], b[1:]
	}
	for len(a) > 0 && len(b) > 0 && a[len(a)-1] == b[len(b)-1] {
		a, b = a[:len(a)-1], b[:len(b)-1]
	}
	m, n := len(a), len(b)
	if m == 0 && n == 0 {
		return "(no changes)"
	}
	var out []string
	if (m+1)*(n+1) > maxDiffCells {
		// A change that spans thousands of lines on both sides (a list
		// pasted over wholesale).  Line order is given up rather than the
		// diff: what left and what came, each in its own order.
		out = bagDiff(a, b)
	} else {
		out = lcsDiff(a, b)
	}
	if len(out) > diffMaxLines {
		out = append(out[:diffMaxLines], "  ... (diff truncated)")
	}
	if len(out) == 0 {
		return "(no changes)"
	}
	return strings.Join(out, "\n")
}

// lcsDiff: the lines of a not in a longest common subsequence with b as
// "- line", those of b as "+ line", in the order of the two texts.  The
// caller keeps len(a)*len(b) within maxDiffCells.
func lcsDiff(a, b []string) []string {
	m, n := len(a), len(b)
	w := n + 1
	dp := make([]int32, (m+1)*w)
	for i := 1; i <= m; i++ {
		for j := 1; j <= n; j++ {
			switch {
			case a[i-1] == b[j-1]:
				dp[i*w+j] = dp[(i-1)*w+j-1] + 1
			case dp[(i-1)*w+j] >= dp[i*w+j-1]:
				dp[i*w+j] = dp[(i-1)*w+j]
			default:
				dp[i*w+j] = dp[i*w+j-1]
			}
		}
	}
	// Walked back from the end, so the lines come out last first.
	var rev []string
	for i, j := m, n; i > 0 || j > 0; {
		switch {
		case i > 0 && j > 0 && a[i-1] == b[j-1]:
			i, j = i-1, j-1
		case j > 0 && (i == 0 || dp[i*w+j-1] >= dp[(i-1)*w+j]):
			rev = append(rev, "+ "+b[j-1])
			j--
		default:
			rev = append(rev, "- "+a[i-1])
			i--
		}
	}
	for l, r := 0, len(rev)-1; l < r; l, r = l+1, r-1 {
		rev[l], rev[r] = rev[r], rev[l]
	}
	return rev
}

// bagDiff: the lines a has more of than b as "- line", then those b has more
// of as "+ line", each in its text's order, under a first line that says the
// order was not compared.  Linear in the two texts.
func bagDiff(a, b []string) []string {
	out := []string{fmt.Sprintf("  (%d lines became %d: too many to align line by line, so shown as what left and what came)", len(a), len(b))}
	left := make(map[string]int, len(b))
	for _, l := range b {
		left[l]++
	}
	for _, l := range a {
		if left[l] > 0 {
			left[l]--
			continue
		}
		out = append(out, "- "+l)
	}
	left = make(map[string]int, len(a))
	for _, l := range a {
		left[l]++
	}
	for _, l := range b {
		if left[l] > 0 {
			left[l]--
			continue
		}
		out = append(out, "+ "+l)
	}
	if len(out) == 1 {
		// The same lines in another order.
		out = append(out, "  (the same lines, in a different order)")
	}
	return out
}

// auditWriteSettingsSave: shared between AdminSettingsSave and any other
// caller that needs to record a settings_save audit with before/after diff.
// beforeYAML / afterYAML come from auditSnapshotYAML -- the row stores and
// diffs exactly what it is given, so a raw settings.MarshalYAML here would
// put the secrets back in.  Pass nil ctx to fall back to context.Background.
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
