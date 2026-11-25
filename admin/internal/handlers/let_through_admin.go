package handlers

import (
	"log"
	"net/http"
	"sort"
	"strings"

	"github.com/unmask-sh/unmask/admin/internal/dashboard"
	"github.com/unmask-sh/unmask/admin/internal/i18n"
	"github.com/unmask-sh/unmask/admin/internal/nginxconf"
	"github.com/unmask-sh/unmask/admin/internal/nginxlog"
)

// The "Let through" tab of the BAN pages: what the site answered without a
// challenge, by the ground it passed on, with the addresses behind each
// ground and a BAN button beside them.  The grounds are the configuration's
// (the access log's why=, counted by nginxlog/let_through.go); nothing here
// is banned automatically.
//
// What it is for: a ground for passing that somebody leans on shows here and
// nowhere else -- a request that is let through fires no challenge and writes
// no event.  A crawler's name anyone can send, a bypass path wider than it
// was meant, a location left without protect.inc; and, last on the page,
// "no ground found": a request that got through on none unmask can name,
// which is a fault to report.

// letReasonOrder: the order the page lists the grounds in -- the grounds a
// stranger can use first, then the operator's own exemptions, then what
// nginx answered by itself ahead of the check (a return or a redirect of the
// site's: no file, no backend), then the pass cookie.  A ground the daemon
// does not know (a newer configuration's) follows them, and the fault
// (letReasonLast) closes the page: it should be empty, the notification list
// says when it is not (notice.KindLetFault) and links to it, and the grounds
// an operator comes here to read are not pushed down by one that holds
// nothing.
var letReasonOrder = []string{
	nginxlog.LetName, nginxlog.LetPreview, nginxlog.LetNoGate, nginxlog.LetDown,
	nginxlog.LetWatch, nginxlog.LetSigned, nginxlog.LetGlobal, nginxlog.LetPath, nginxlog.LetIP,
	nginxlog.LetAhead, nginxlog.LetCookie,
}

// letReasonLast: the ground listed after every other, the unknown ones too.
const letReasonLast = nginxlog.LetNone

// letReasonSettings: the settings tab where each ground is set, "" for one
// that is not a setting.
var letReasonSettings = map[string]string{
	nginxlog.LetName:    "ua-filter",
	nginxlog.LetPreview: "ua-filter",
	nginxlog.LetWatch:   "sites",
	nginxlog.LetSigned:  "web-bot-auth",
	nginxlog.LetGlobal:  "global",
	nginxlog.LetPath:    "bypass-paths",
	nginxlog.LetIP:      "bypass-ips",
}

// letAddrLimit: the addresses listed under one ground.
const letAddrLimit = 50

type letDetailView struct {
	Label     string
	Own       bool // a row of the operator's own, as against a preset
	Requests  int
	Addresses int
}

type letAddrView struct {
	dashboard.LetAddrRow
	Country     string
	ASNOrg      string
	DetailLabel string
	DetailOwn   bool
	Banned      bool // already on the ban list
	Listed      bool // on the bypass list: the ban guard refuses a ban on it
}

type letSection struct {
	Reason    string
	Known     bool // a ground the page has words for
	Requests  int
	Addresses int
	Details   []letDetailView
	Rows      []letAddrView
	Unchecked int    // of Rows, the addresses nothing shows to have met the challenge
	Settings  string // the settings tab the ground is set on, "" for none
	Open      bool   // shown open: the fault, and the grounds a stranger can use
	// NoCheck: the ground is the operator's own exemption from every check
	// (a bypass address), so whether an address met the challenge is not a
	// question: no mark on its rows, no count in the summary.
	NoCheck bool
	Fault   bool // "no ground found"
	Counted bool // counted and not listed (the pass cookie)
}

// letDetailLabel turns a stored detail into what to show: the operator's own
// row without its prefix (own), a preset by its label rather than its id,
// anything else -- a crawler's name, a cookie's kind -- as it is.
func letDetailLabel(reason, detail string) (label string, own bool) {
	if strings.HasPrefix(detail, nginxconf.LetDetailOwn) {
		return strings.TrimPrefix(detail, nginxconf.LetDetailOwn), true
	}
	switch reason {
	case nginxlog.LetIP:
		for i := range nginxconf.BypassIPGroups {
			if g := &nginxconf.BypassIPGroups[i]; g.ID == detail && g.Label != "" {
				return g.Label, false
			}
		}
	case nginxlog.LetPath:
		for i := range nginxconf.BypassPathPresetGroups {
			if g := &nginxconf.BypassPathPresetGroups[i]; g.ID == detail && g.Label != "" {
				return g.Label, false
			}
		}
	}
	return detail, false
}

// letWindow: the page's window in hours -- an hour, a day (the default) or a
// week, which is as long as the addresses are kept.
func letWindow(v string) int {
	switch strings.TrimSpace(v) {
	case "1":
		return 1
	case "168":
		return 168
	}
	return 24
}

// AdminLetThroughIndex: GET /admin/let-through/{$}.
func (h *Handler) AdminLetThroughIndex(w http.ResponseWriter, r *http.Request) {
	tmpl, err := loadDashboardTemplate()
	if err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	hours := letWindow(r.URL.Query().Get("window"))
	site := resolveSiteFilter(r)
	cur := h.cfg()

	queryErr := ""
	reasons, err := dashboard.LetThroughReasons(r.Context(), h.DB, site, hours)
	if err != nil {
		// The frame, the window picker and the explanation still render.
		log.Printf("let-through: reasons: %v", err)
		queryErr = err.Error()
	}
	byReason := map[string]*letSection{}
	for _, row := range reasons {
		s := byReason[row.Reason]
		if s == nil {
			s = &letSection{Reason: row.Reason}
			byReason[row.Reason] = s
		}
		s.Requests += row.Requests
		// The addresses of two details may be the same address; the sum is
		// what the rows say, and the section's own figure is not claimed to
		// be more than that.
		s.Addresses += row.Addresses
		label, own := letDetailLabel(row.Reason, row.Detail)
		s.Details = append(s.Details, letDetailView{Label: label, Own: own, Requests: row.Requests, Addresses: row.Addresses})
	}

	banned := map[string]bool{}
	if h.BanMgr != nil {
		for _, e := range h.BanMgr.Snapshot() {
			if e.IP != "" {
				banned[e.IP] = true
			}
		}
	}

	known := map[string]bool{}
	var sections []*letSection
	add := func(reason string, isKnown bool) {
		s := byReason[reason]
		if s == nil {
			// A ground nothing passed on is listed all the same, with its
			// zero: the page says what it looked for.
			s = &letSection{Reason: reason}
		}
		s.Known = isKnown
		s.Settings = letReasonSettings[reason]
		s.Fault = reason == nginxlog.LetNone
		s.Counted = reason == nginxlog.LetCookie
		s.Open = s.Fault || reason == nginxlog.LetName
		s.NoCheck = reason == nginxlog.LetIP
		if !s.Counted && s.Requests > 0 && queryErr == "" {
			rows, err := dashboard.LetThroughAddresses(r.Context(), h.DB, site, hours, reason, letAddrLimit)
			if err != nil {
				log.Printf("let-through: addresses of %s: %v", reason, err)
				queryErr = err.Error()
			}
			for _, row := range rows {
				v := letAddrView{LetAddrRow: row, Banned: banned[row.IP]}
				v.DetailLabel, v.DetailOwn = letDetailLabel(reason, row.Detail)
				if h.IPGeo != nil {
					info := h.IPGeo.LookupInfo(row.IP)
					v.Country, v.ASNOrg = info.Country, info.ASNOrg
				}
				// A bypass address cannot be banned while it is on the list:
				// the guard refuses, so the row offers the list instead.
				v.Listed = reason == nginxlog.LetIP && h.BanBypassMatch(row.IP)
				if row.Unchecked() && !s.NoCheck {
					s.Unchecked++
				}
				s.Rows = append(s.Rows, v)
			}
		}
		sections = append(sections, s)
	}
	for _, reason := range letReasonOrder {
		known[reason] = true
		add(reason, true)
	}
	known[letReasonLast] = true
	var others []string
	for reason := range byReason {
		if !known[reason] {
			others = append(others, reason)
		}
	}
	sort.Strings(others)
	for _, reason := range others {
		add(reason, false)
	}
	add(letReasonLast, true)

	// A row names its site when the page holds more than one: the same
	// address on two sites is two rows, and nothing else tells them apart.
	// A page narrowed to one site, or an install with one, needs no label.
	var rowSites []string
	seenSite := map[string]bool{}
	for _, s := range sections {
		for _, row := range s.Rows {
			if row.Site != "" && !seenSite[row.Site] {
				seenSite[row.Site] = true
				rowSites = append(rowSites, row.Site)
			}
		}
	}

	banAct, banEffect := h.banDialogEffect()
	data := map[string]any{
		"BanTab":   "let",
		"Lang":     i18n.Resolve(r),
		"TZ":       resolveTZ(r),
		"BasePath": cur.Server.BasePath,
		"Version":  h.Version,
		"WindowH":  hours,
		"Sections": sections,
		"ShowSite": site == "" && len(rowSites) > 1,
		// A host that is not a defined site is coloured as it is on the other
		// pages that print one.
		"GhostSites": h.ghostSiteSet(rowSites),
		"Saved":      r.URL.Query().Get("saved") != "",
		"Error":      readFlash(w, r, cur.Server.BasePath, "err"),
		"QueryErr":   queryErr,
		// The addresses excluded from statistics pass without a challenge
		// and are not logged at all: the one blind spot of this page, named
		// on it.
		"NotRecorded": statsExcludeShown(cur.Nginx.StatsExcludeIPs),
		// The BAN dialog is the bot-hunt one (partial_ban_dialog.html): same
		// sharing gate, and here the reason row is always editable.
		"CommunityBansActive":   h.snapshotSettings().CommunityBans.SubmitActive(),
		"BanDialogReasonAlways": true,
		"BanDialogAction":       banAct,
		"BanDialogEffectKey":    banEffect,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	h.addMeToData(r, data)
	if err := tmpl.ExecuteTemplate(w, "let_through.html", data); err != nil {
		log.Printf("let-through render: %v", err)
	}
}

// statsExcludeShown: the ranges the page names as not recorded -- a few of
// them, and how many more.
func statsExcludeShown(ranges []string) []string {
	var out []string
	for _, r := range ranges {
		if r = strings.TrimSpace(r); r != "" {
			out = append(out, r)
		}
	}
	return out
}
