// The admin's notification list (internal/notice): the bell in the top bar
// with the count of what the account has not opened the list to, the panel
// under it with the latest, and the page with everything, by kind.
//
// A row is the event's fields; the line the reader sees is written here, in
// the reader's language, from the same keys the over-block mail uses where
// there is one.  Opening the panel or the page moves the account's read mark
// to the newest row it may see.
package handlers

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/i18n"
	"github.com/unmask-sh/unmask/admin/internal/notice"
	"github.com/unmask-sh/unmask/admin/internal/user"
)

const (
	noticePageSize  = 50
	noticePanelSize = 20
)

// noticeKinds is the order the page's filter lists the kinds in.
var noticeKinds = []string{notice.KindBan, notice.KindBurst, notice.KindPreview, notice.KindOverBlock, notice.KindFailsafe, notice.KindAdvisor}

// noticeRow is one line of the list as the templates render it.
type noticeRow struct {
	ID        int64
	Kind      string
	KindLabel string
	Severity  string
	At        int64  // unix seconds, for <time data-ts>
	AtText    string // the same in UTC, shown until the page's script formats it
	Events    int
	Site      string
	Personal  bool // for this account alone
	Unread    bool // above the account's read mark when the list was opened
	Title     string
	Body      string
	Href      string
}

// noticeUnread is the badge's count for the account: 0 for a viewer (the
// list is the administrators'), when there is no store, or when the database
// does not answer in time.
func (h *Handler) noticeUnread(ctx context.Context, pay *SessionPayload) int {
	if h.Notices == nil || pay == nil || !roleAtLeast(pay.Role, user.RoleAdmin) {
		return 0
	}
	ctx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()
	n, err := h.Notices.Unread(ctx, pay.UserID)
	if err != nil {
		if ctx.Err() == nil {
			log.Printf("notice unread: %v", err)
		}
		return 0
	}
	return n
}

// AdminNoticesIndex: GET {base}/admin/notices/ -- the page.  ?kind= narrows
// to one kind, ?page= pages.  Opening it marks the list read.
func (h *Handler) AdminNoticesIndex(w http.ResponseWriter, r *http.Request) {
	if h.Notices == nil {
		http.Error(w, "notices not configured", http.StatusInternalServerError)
		return
	}
	pay := SessionFromContext(r)
	if pay == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	lang := i18n.Resolve(r)
	base := h.cfg().Server.BasePath
	kind := r.URL.Query().Get("kind")
	if !noticeKindKnown(kind) {
		kind = ""
	}
	page := 1
	if n, err := strconv.Atoi(r.URL.Query().Get("page")); err == nil && n >= 1 {
		page = n
	}
	offset := (page - 1) * noticePageSize
	ctx := r.Context()
	entries, err := h.Notices.List(ctx, pay.UserID, kind, noticePageSize, offset)
	if err != nil {
		http.Error(w, "list notices: "+err.Error(), http.StatusInternalServerError)
		return
	}
	total, err := h.Notices.Count(ctx, pay.UserID, kind)
	if err != nil {
		log.Printf("notice count: %v", err)
		total = offset + len(entries)
	}
	seen, _ := h.Notices.SeenID(ctx, pay.UserID)
	rows := h.noticeRows(entries, seen, lang, base)
	h.noticeMarkRead(ctx, pay.UserID, seen)

	totalPages := max((total+noticePageSize-1)/noticePageSize, 1)
	kinds := make([]map[string]any, 0, len(noticeKinds)+1)
	kinds = append(kinds, map[string]any{"Key": "", "Label": i18n.T(lang, "notice.filter.all"), "Active": kind == "", "Href": base + "/admin/notices/"})
	for _, k := range noticeKinds {
		kinds = append(kinds, map[string]any{"Key": k, "Label": i18n.T(lang, "notice.kind."+k), "Active": kind == k, "Href": base + "/admin/notices/?kind=" + k})
	}
	retention := i18n.T(lang, "notice.retention_forever")
	if d := h.cfg().NoticeRetentionDays; d > 0 {
		retention = i18n.Tf(lang, "notice.retention", d)
	}
	data := map[string]any{
		"Lang":         lang,
		"BasePath":     base,
		"Version":      h.Version,
		"Rows":         rows,
		"GhostSites":   h.ghostSiteSet(noticeSites(rows)),
		"Kind":         kind,
		"Kinds":        kinds,
		"Total":        total,
		"Retention":    retention,
		"Pager":        buildPagerData(lang, page, totalPages, noticePageSize, total, buildQueryBase([2]string{"kind", kind})),
		"NoticeUnread": 0, // just read
	}
	tmpl, err := loadDashboardTemplate()
	if err != nil {
		http.Error(w, "template: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	h.addMeToData(r, data)
	if err := tmpl.ExecuteTemplate(w, "notices.html", data); err != nil {
		log.Printf("notices render: %v", err)
	}
}

// AdminNoticesPanel: POST {base}/admin/notices/panel -- the bell's panel,
// an HTML fragment of the latest rows.  Opening it marks the list read,
// which is why it is a POST.
func (h *Handler) AdminNoticesPanel(w http.ResponseWriter, r *http.Request) {
	if h.Notices == nil {
		http.Error(w, "notices not configured", http.StatusInternalServerError)
		return
	}
	pay := SessionFromContext(r)
	if pay == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	lang := i18n.Resolve(r)
	base := h.cfg().Server.BasePath
	ctx := r.Context()
	entries, err := h.Notices.List(ctx, pay.UserID, "", noticePanelSize, 0)
	if err != nil {
		http.Error(w, "list notices: "+err.Error(), http.StatusInternalServerError)
		return
	}
	seen, _ := h.Notices.SeenID(ctx, pay.UserID)
	rows := h.noticeRows(entries, seen, lang, base)
	h.noticeMarkRead(ctx, pay.UserID, seen)
	tmpl, err := loadDashboardTemplate()
	if err != nil {
		http.Error(w, "template: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := tmpl.ExecuteTemplate(w, "notice_panel", map[string]any{"Lang": lang, "BasePath": base, "Rows": rows, "GhostSites": h.ghostSiteSet(noticeSites(rows))}); err != nil {
		log.Printf("notice panel render: %v", err)
	}
}

// noticeMarkRead moves the account's mark to the newest row it may see.
// Skipped while a schema update holds the database's writes: the list still
// opens, and the mark catches up on the next opening.
func (h *Handler) noticeMarkRead(ctx context.Context, userID, seen int64) {
	if h.DB != nil && h.DB.WritesHeld() {
		return
	}
	newest, err := h.Notices.Newest(ctx, userID)
	if err != nil || newest <= seen {
		return
	}
	if _, err := h.Notices.MarkSeen(ctx, userID, newest); err != nil {
		log.Printf("notice mark read: %v", err)
	}
}

func noticeKindKnown(kind string) bool {
	for _, k := range noticeKinds {
		if k == kind {
			return true
		}
	}
	return false
}

// noticeRows writes the lines for the entries in lang.
func (h *Handler) noticeRows(entries []notice.Entry, seen int64, lang i18n.Lang, base string) []noticeRow {
	rows := make([]noticeRow, 0, len(entries))
	for _, e := range entries {
		row := noticeRow{
			ID: e.ID, Kind: e.Kind, Severity: e.Severity, Events: e.Events, Site: e.Site,
			At:        e.UpdatedAt,
			AtText:    time.Unix(e.UpdatedAt, 0).UTC().Format(time.DateTime + " UTC"),
			Personal:  e.UserID != nil,
			Unread:    e.ID > seen,
			KindLabel: e.Kind,
		}
		if noticeKindKnown(e.Kind) {
			row.KindLabel = i18n.T(lang, "notice.kind."+e.Kind)
		}
		row.Title, row.Body, row.Href = noticeText(e, lang, base)
		rows = append(rows, row)
	}
	return rows
}

// noticeText is the line for one entry: a title, a body, and where to look.
func noticeText(e notice.Entry, lang i18n.Lang, base string) (title, body, href string) {
	switch e.Kind {
	case notice.KindBan:
		href = base + "/admin/bans/"
		ip := e.Str("ip")
		latest := ip
		if reason := e.Str("reason"); reason != "" {
			latest += " (" + reason + ")"
		}
		if e.Events <= 1 {
			title = i18n.Tf(lang, "notice.ban.one", ip)
			parts := []string{e.Str("source")}
			if reason := e.Str("reason"); reason != "" {
				parts = append(parts, reason)
			}
			if by := e.Str("banned_by"); by != "" {
				parts = append(parts, i18n.Tf(lang, "notice.ban.by", by))
			}
			body = strings.Join(parts, " · ")
			return
		}
		title = i18n.Tf(lang, "notice.ban.many", e.Events)
		var srcs []string
		for _, s := range e.Sources() {
			srcs = append(srcs, fmt.Sprintf("%s %d", s.Source, s.N))
		}
		body = strings.Join(srcs, " / ") + " · " + i18n.Tf(lang, "notice.ban.latest", latest)
	case notice.KindBurst:
		href = base + "/admin/hunt/?range=1h"
		title = i18n.Tf(lang, "notice.burst.title", e.Int("count_per_5m"))
		// A burst is measured against the hour before it; a row from before
		// that has only the fixed threshold it passed.
		if _, measured := e.Detail["baseline_per_5m"]; measured {
			body = i18n.Tf(lang, "notice.burst.body_hour", e.Int("baseline_per_5m"))
		} else {
			body = i18n.Tf(lang, "notice.burst.body", e.Int("threshold"))
		}
	case notice.KindOverBlock:
		href = base + "/admin/hunt/?range=1h"
		minutes, stuck, loaders, pct := e.Int("window_minutes"), e.Int("stuck"), e.Int("ran_challenge"), e.Int("stuck_percent")
		if e.Bool("tripped") {
			title = i18n.T(lang, "mail.overblock.title_tripped")
			body = i18n.Tf(lang, "mail.overblock.summary_tripped", minutes, stuck, loaders, pct)
			if e.Bool("auto_passthrough") {
				body += " " + i18n.T(lang, "mail.overblock.protection_passthrough")
			} else {
				body += " " + i18n.T(lang, "mail.overblock.protection_unchanged")
			}
		} else {
			title = i18n.T(lang, "mail.overblock.title_cleared")
			body = i18n.Tf(lang, "mail.overblock.summary_cleared", minutes, stuck, loaders, pct, e.Int("min_stuck"), e.Int("min_percent"))
		}
	case notice.KindPreview:
		// The rule that stopped them is on the country tab, or the ASN tab.
		href = base + "/admin/settings/geo/"
		if e.Str("axis") == "asn" {
			href = base + "/admin/settings/asn/"
		}
		title = i18n.Tf(lang, "notice.preview.title", e.Int("count"))
		body = i18n.Tf(lang, "notice.preview.body", e.Str("crawlers"))
	case notice.KindFailsafe:
		// The About tab carries the version and the update commands, the
		// nearest thing to the host's package state; `unmask doctor` has
		// the cause.
		href = base + "/admin/settings/about/"
		if e.Bool("active") {
			title = i18n.T(lang, "notice.failsafe.title_active")
			body = i18n.T(lang, "notice.failsafe.body_active")
			if reason := e.Str("reason"); reason != "" {
				body += " " + i18n.Tf(lang, "notice.failsafe.reason", reason)
			}
		} else {
			title = i18n.T(lang, "notice.failsafe.title_cleared")
			body = i18n.T(lang, "notice.failsafe.body_cleared")
		}
	case notice.KindAdvisor:
		href = base + "/admin/advisor/"
		title = i18n.Tf(lang, "notice.advisor.title", e.Int("new_candidates"))
		body = i18n.Tf(lang, "notice.advisor.body", e.Int("total_candidates"))
	default:
		title = e.Kind
	}
	return
}

// noticeSites: the sites the listed notices name, for the ghost colouring
// of the site in a notice's meta line (a host not in the defined list).
func noticeSites(rows []noticeRow) []string {
	out := make([]string, 0, len(rows))
	for _, row := range rows {
		out = append(out, row.Site)
	}
	return out
}
