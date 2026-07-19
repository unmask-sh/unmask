// Web UI: /admin/settings/* — edit the nginx section of config.yml (and more)
// from the web.
//
// Only "runtime" values are editable. Bootstrap (= db / secret / listen) is not
// exposed to the web (= no form is rendered).
//
// Save flow:
//  1. receive POST → form parse → overlay onto a temporary Settings
//  2. validate (= regex compile / duplicates / empty values)
//  3. settings.Save() does the atomic write
//  4. nginxconf.Render() refreshes nginx-rendered*.conf immediately
//  5. update Handler.Settings (= in-memory copy) by mutex swap
//  6. redirect to dashboard (= banner asks the user to run "nginx -s reload")
package handlers

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/oschwald/maxminddb-golang"
	"github.com/unmask-sh/unmask/admin/internal/classify"
	"github.com/unmask-sh/unmask/admin/internal/dashboard"
	"github.com/unmask-sh/unmask/admin/internal/events"
	"github.com/unmask-sh/unmask/admin/internal/i18n"
	"github.com/unmask-sh/unmask/admin/internal/ipgeo"
	"github.com/unmask-sh/unmask/admin/internal/mail"
	"github.com/unmask-sh/unmask/admin/internal/nginxconf"
	"github.com/unmask-sh/unmask/admin/internal/notifier"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// osStat: a var so tests can override it. Real implementation is os.Stat.
var osStat = os.Stat

// humanSize: format a byte size as KB / MB / GB.
func humanSize(n int64) string {
	const k = 1024
	switch {
	case n >= k*k*k:
		return fmt.Sprintf("%.1f GB", float64(n)/(k*k*k))
	case n >= k*k:
		return fmt.Sprintf("%.1f MB", float64(n)/(k*k))
	case n >= k:
		return fmt.Sprintf("%.1f KB", float64(n)/k)
	default:
		return fmt.Sprintf("%d B", n)
	}
}

// settingsMu serializes settings writers (the read-modify-publish sequences in
// the save handlers, updateSettingsInMemory and UpdateSettings) so concurrent
// saves don't interleave.  Readers don't take it: they Load the atomic pointer
// via Handler.cfg() and get a race-free, consistent snapshot.
var settingsMu sync.Mutex

// AdminSettingsIndex: GET {base}/admin/settings/ — renders the tabbed UI.
//
// The "tab" query selects one of network / search-bots / ja4-verdicts / sites.
// A "saved" query shows a banner telling the user to run "nginx -s reload".
func (h *Handler) AdminSettingsIndex(w http.ResponseWriter, r *http.Request) {
	tmpl, err := loadDashboardTemplate()
	if err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	tab := r.URL.Query().Get("tab")
	switch tab {
	case "top", "network", "global", "ua-filter", "ja4-verdicts", "honeypot", "bypass-ips", "bypass-paths", "web-bot-auth", "privacy-pass", "protected", "captcha", "challenge", "rate-limit", "deny-design", "geo", "theme", "notifications", "smtp", "retention", "community-bans", "sites", "about":
		// ok
	case "search-bots", "challenge-targets":
		tab = "ua-filter"
	default:
		// no / unknown tab -> the overview landing page.
		tab = "top"
	}

	// Advanced-gated tabs: when the master switch is off they're hidden from the
	// nav, so a direct URL hit lands the operator on the About tab (where the
	// master toggle lives) instead of an inert-looking form.
	if (tab == "web-bot-auth" || tab == "privacy-pass") && !h.snapshotSettings().Nginx.AdvancedEnabled {
		http.Redirect(w, r, h.cfg().Server.BasePath+"/admin/settings/?tab=about", http.StatusSeeOther)
		return
	}

	data := h.settingsViewData(w, r, tab)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	h.addMeToData(r, data)
	if err := tmpl.ExecuteTemplate(w, "settings.html", data); err != nil {
		log.Printf("settings render: %v", err)
	}
}

// settingsViewData: passes the per-tab data needed by the template.
// Takes w so flash cookies can be cleared (= readFlash drops them via Set-Cookie).
func (h *Handler) settingsViewData(w http.ResponseWriter, r *http.Request, tab string) map[string]any {
	cur := h.snapshotSettings().Nginx
	seenVer := cur.SeenVersion
	// Operator's cookie TZ -- the `Format("...MST")` strings inside this view
	// (mtime / oldest event / oldest cookie minute) shift to it.  Falls back
	// to time.UTC when the cookie is empty / invalid.
	loc := resolveLocation(r)

	// upstream rescue summary: aggregate pattern counts for the UI banner.
	upstreamRescue := classify.UpstreamRescueList()
	upstreamDisabledSet := toSet(cur.SearchBots.UpstreamDisabled)
	upstreamTotal := 0
	upstreamEnabled := 0
	for _, entries := range upstreamRescue {
		for _, e := range entries {
			upstreamTotal++
			if !upstreamDisabledSet[e.Pattern] {
				upstreamEnabled++
			}
		}
	}
	upstreamGroupMode := map[string]string{}
	upstreamGroupAction := map[string]string{}
	for cat := range upstreamRescue {
		upstreamGroupMode[cat] = classify.ResolveGroupMode(cat, cur.SearchBots.UpstreamGroupMode)
		if cur.SearchBots.UpstreamGroupAction != nil {
			upstreamGroupAction[cat] = cur.SearchBots.UpstreamGroupAction[cat]
		}
	}
	// Range-verification badges for the detail modal: which patterns have a
	// published vendor IP range at all (backed), and which are currently
	// inverted to range verification (active = every preset enabled + past
	// the NEW gate).  catHasRV drives the per-category legend line.
	upstreamRangeBacked := make(map[string]bool, len(nginxconf.UARangePresets))
	for pat := range nginxconf.UARangePresets {
		upstreamRangeBacked[pat] = true
	}
	upstreamRangeActive := nginxconf.EffectiveRangeVerifiedPatterns(cur)
	upstreamCatHasRV := map[string]bool{}
	for cat, entries := range upstreamRescue {
		for _, e := range entries {
			if upstreamRangeBacked[e.Pattern] {
				upstreamCatHasRV[cat] = true
				break
			}
		}
	}

	// JA4 verdicts: same shape
	disabledV := toSet(cur.JA4Verdicts.DisabledPresets)
	ja4Groups := make([]map[string]any, 0, len(nginxconf.JA4VerdictGroups))
	for _, g := range nginxconf.JA4VerdictGroups {
		isNew := nginxconf.PresetIsNew(seenVer, g.AddedIn)
		enabled := !disabledV[g.ID]
		if isNew {
			enabled = false
		}
		ja4Groups = append(ja4Groups, map[string]any{
			"ID":      g.ID,
			"Label":   g.Label,
			"Rules":   g.Rules,
			"Enabled": enabled,
			"AddedIn": g.AddedIn,
			"IsNew":   isNew,
		})
	}
	// extra verdicts: row-UI struct slice (= same shape as UA filter + verdict column).
	ja4ExtraRules := pairJA4Rules(
		cur.JA4Verdicts.Extra,
		cur.JA4Verdicts.ExtraTitle,
		cur.JA4Verdicts.ExtraDisabled,
		cur.JA4Verdicts.ExtraUpdatedAt,
	)

	// challenge target groups: same shape
	disabledTgt := toSet(cur.ChallengeTargets.DisabledPresets)
	tgtGroups := make([]map[string]any, 0, len(nginxconf.ChallengeTargetGroups))
	for _, g := range nginxconf.ChallengeTargetGroups {
		isNew := nginxconf.PresetIsNew(seenVer, g.AddedIn)
		enabled := !disabledTgt[g.ID]
		if isNew {
			enabled = false
		}
		tgtGroups = append(tgtGroups, map[string]any{
			"ID":       g.ID,
			"Label":    g.Label,
			"Patterns": g.Patterns,
			"Enabled":  enabled,
			"AddedIn":  g.AddedIn,
			"IsNew":    isNew,
		})
	}

	// honeypot preset groups: same shape as search-bots etc.
	disabledHP := toSet(cur.Honeypot.DisabledPresets)
	honeypotGroups := make([]map[string]any, 0, len(nginxconf.HoneypotPresetGroups))
	for _, g := range nginxconf.HoneypotPresetGroups {
		isNew := nginxconf.PresetIsNew(seenVer, g.AddedIn)
		enabled := !disabledHP[g.ID]
		if isNew {
			enabled = false
		}
		honeypotGroups = append(honeypotGroups, map[string]any{
			"ID":       g.ID,
			"Label":    g.Label,
			"Patterns": g.Patterns,
			"Enabled":  enabled,
			"AddedIn":  g.AddedIn,
			"IsNew":    isNew,
		})
	}

	// bypass paths preset groups: allowlist-path preset.
	//
	// Checked = the effective state (per-preset DefaultOn + the operator's
	// recorded deviations), via the shared EffectiveBypassPathPresets so the
	// UI shows exactly what the renderer / forward-auth matcher act on.  A
	// NEW preset (added after the operator's last save) renders unchecked and
	// inert regardless of its default; its default applies from the first
	// save after review.
	enabledBPath := nginxconf.EffectiveBypassPathPresets(cur.BypassPaths.EnabledPresets, cur.BypassPaths.DisabledPresets)
	bypassPathGroups := make([]map[string]any, 0, len(nginxconf.BypassPathPresetGroups))
	for _, g := range nginxconf.BypassPathPresetGroups {
		isNew := nginxconf.PresetIsNew(seenVer, g.AddedIn)
		enabled := enabledBPath[g.ID]
		if isNew {
			enabled = false
		}
		bypassPathGroups = append(bypassPathGroups, map[string]any{
			"ID":        g.ID,
			"Label":     g.Label,
			"Rules":     g.Rules,
			"Enabled":   enabled,
			"AddedIn":   g.AddedIn,
			"IsNew":     isNew,
			"DefaultOn": g.DefaultOn,
		})
	}

	// HTTPS-redirect exemption presets.  Checked = the effective state
	// (per-preset DefaultOn + deviations).  No SeenVersion gate: a missing
	// exemption is the dangerous state, so default-on exemptions apply on
	// upgrade (a 301'd health check drops the node from the LB).
	enabledRE := nginxconf.EffectiveRedirectExemptPresets(cur.HTTPSRedirectExempt.EnabledPresets, cur.HTTPSRedirectExempt.DisabledPresets)
	redirectExemptGroups := make([]map[string]any, 0, len(nginxconf.RedirectExemptPresetGroups))
	for _, g := range nginxconf.RedirectExemptPresetGroups {
		redirectExemptGroups = append(redirectExemptGroups, map[string]any{
			"ID":        g.ID,
			"Label":     g.Label,
			"MatchType": g.MatchType,
			"Enabled":   enabledRE[g.ID],
			"DefaultOn": g.DefaultOn,
		})
	}
	redirectExemptRules := make([]map[string]any, 0, len(cur.HTTPSRedirectExempt.Rules))
	for _, rl := range cur.HTTPSRedirectExempt.Rules {
		mt := rl.Type
		if mt != nginxconf.RedirectExemptMatchUA {
			mt = nginxconf.RedirectExemptMatchPath
		}
		redirectExemptRules = append(redirectExemptRules, map[string]any{
			"Type":     mt,
			"Pattern":  rl.Pattern,
			"Title":    rl.Title,
			"Disabled": rl.Disabled,
		})
	}

	// protected paths preset groups: protected-path preset (= unmask / common-admin).
	// Opt-in: only IDs in EnabledPresets render as checked.  Turning a preset
	// on inserts a CAPTCHA before admin login, so default OFF is the safe
	// choice -- operators must opt in explicitly.
	enabledPP := toSet(cur.ProtectedPaths.EnabledPresets)
	protectedPresetGroups := make([]map[string]any, 0, len(nginxconf.ProtectedPathPresetGroups))
	for _, g := range nginxconf.ProtectedPathPresetGroups {
		isNew := nginxconf.PresetIsNew(seenVer, g.AddedIn)
		enabled := enabledPP[g.ID]
		if isNew {
			enabled = false
		}
		protectedPresetGroups = append(protectedPresetGroups, map[string]any{
			"ID":      g.ID,
			"Label":   g.Label,
			"Rules":   g.Rules,
			"Enabled": enabled,
			"AddedIn": g.AddedIn,
			"IsNew":   isNew,
		})
	}

	// AdminCaptchaGate: the "unmask itself" protected-path preset (= CAPTCHA in
	// front of /unmask/admin/) is enabled, so switching to a domain-locked 3rd
	// party CAPTCHA can lock the operator out when the admin host is not in the
	// provider's allowed-domains list.  Drives the captcha-tab warning banner.
	adminCaptchaGate := enabledPP["unmask"]

	// bypass IP preset groups: enabled/disabled for official IP ranges + creationTime + count.
	// EnabledPresets is an opt-in list; a group is on when its ID appears in the set.
	enabledBP := toSet(cur.BypassIPEnabledPresets)
	bypassPresetGroups := make([]map[string]any, 0, len(nginxconf.BypassIPGroups))
	for i := range nginxconf.BypassIPGroups {
		g := &nginxconf.BypassIPGroups[i]
		isNew := nginxconf.PresetIsNew(seenVer, g.AddedIn)
		enabled := enabledBP[g.ID]
		if isNew {
			enabled = false
		}
		ts := g.CreationTime().Unix()
		if ts < 0 {
			ts = 0
		}
		bypassPresetGroups = append(bypassPresetGroups, map[string]any{
			"ID":           g.ID,
			"Label":        g.Label,
			"Source":       g.Source,
			"Enabled":      enabled,
			"AddedIn":      g.AddedIn,
			"IsNew":        isNew,
			"PrefixCount":  g.PrefixCount(),
			"CreationTime": ts,
		})
	}

	// Web Bot Auth operator presets: checkbox rows (checked = the host is in the
	// allowlist) + the allowlist entries that aren't a preset (custom rows).
	// AllowedOperators stays the source of truth; presets just populate it.
	wbaPresetHosts := map[string]bool{}
	wbaPresets := make([]map[string]any, 0, len(settings.WebBotAuthOperatorPresets))
	for _, p := range settings.WebBotAuthOperatorPresets {
		wbaPresetHosts[strings.ToLower(p.Host)] = true
		checked := false
		for _, op := range cur.WebBotAuth.AllowedOperators {
			if strings.EqualFold(strings.TrimSpace(op), p.Host) {
				checked = true
				break
			}
		}
		wbaPresets = append(wbaPresets, map[string]any{
			"Host": p.Host, "Label": p.Label, "Since": p.Since, "Checked": checked,
		})
	}
	wbaCustom := make([]string, 0, len(cur.WebBotAuth.AllowedOperators))
	for _, op := range cur.WebBotAuth.AllowedOperators {
		if !wbaPresetHosts[strings.ToLower(strings.TrimSpace(op))] {
			wbaCustom = append(wbaCustom, op)
		}
	}

	// Privacy Pass issuer presets: checkbox rows (checked = the preset ID is in
	// EnabledIssuerPresets).  Custom issuers render separately from .PrivacyPass.
	ppEnabled := toSet(cur.PrivacyPass.EnabledIssuerPresets)
	ppPresets := make([]map[string]any, 0, len(settings.PrivacyPassIssuerPresets))
	for _, p := range settings.PrivacyPassIssuerPresets {
		ppPresets = append(ppPresets, map[string]any{
			"ID": p.ID, "Label": p.Label, "IssuerName": p.IssuerName,
			"Since": p.Since, "KeyCount": len(p.SnapshotKeys), "Checked": ppEnabled[p.ID],
		})
	}

	ipgeoCur := h.snapshotSettings().IPGeo

	// Sites tab: the acceptance config + the ghost report (= sites observed in
	// the last 30 days that are not in Sites.Defined).  Computed only for that
	// tab so other settings pages don't pay for the query.
	sitesConfig := h.snapshotSettings().Sites
	hostsConfig := h.snapshotSettings().Hosts
	hostDisabled := map[string]bool{}
	for _, d := range hostsConfig.Disabled {
		hostDisabled[d] = true
	}
	var siteGhosts []GhostSite
	var hostInventory []dashboard.HostInfo
	var sitesTimedOut bool
	if tab == "sites" {
		// 10s, not 3s: ghostSites + HostInventory both run GROUP BY aggregates
		// over unmask_event, and on a large DB the old 3s budget expired -- the
		// template then gated out the host table / ghost list as a false "none
		// observed".  Share one budget across both (sequential) and flag a
		// timeout so the template can warn instead of lying about empty data.
		gctx, gcancel := context.WithTimeout(r.Context(), 10*time.Second)
		siteGhosts = h.ghostSites(gctx, 24*30)
		if h.DB != nil {
			hostInventory, _ = dashboard.HostInventory(gctx, h.DB)
		}
		sitesTimedOut = gctx.Err() != nil
		gcancel()
		// Ensure every disabled host is listed (= re-enablable) even if it has
		// no events left — otherwise it would be unreachable from the UI.
		present := map[string]bool{}
		for _, hi := range hostInventory {
			present[hi.HostID] = true
		}
		for _, d := range hostsConfig.Disabled {
			if !present[d] {
				hostInventory = append(hostInventory, dashboard.HostInfo{HostID: d})
			}
		}
	}

	// Retention tab: surface the current size of the data the retention
	// knobs will prune.  Cheap (= a few COUNT(*) / MIN() queries) but only
	// needed when this tab is being viewed, so gate the work on `tab`.
	var retentionView retentionStatsView
	if tab == "retention" {
		// 10s, not 3s: COUNT(*)/MIN() over unmask_event is a full table scan, and
		// on a large sqlite DB (millions of rows -- tool1-us hit 2.1M / 1.9GB) the
		// 3s budget expired, so retentionStats returned zeros and the template
		// gated out the WHOLE "current size" line -- row count, oldest, AND the
		// os.Stat DB size.  The DB-size line is now rendered independently of the
		// row count below, so a slow COUNT no longer hides the (cheap) file size.
		rctx, rcancel := context.WithTimeout(r.Context(), 10*time.Second)
		retentionView = h.retentionStats(rctx, resolveLocation(r))
		rcancel()
	}

	// Scope picker (= theme / challenge tabs): one form, one save button,
	// scope=<host> selects which BrandingValues / ChallengeValues record the
	// form reads + writes.  Empty / "default" means cur.Branding.Default +
	// cur.Challenge.Default.  An unknown host (= operator just typed it in
	// the "+ Add new host" prompt) seeds from Default so the new entry can be
	// saved with one click of [Save] -- the entry only gets created when the
	// form is actually submitted to /admin/settings/branding/site/save?site=
	// or /admin/settings/challenge/site/save?site=.
	scope := strings.TrimSpace(r.URL.Query().Get("scope"))
	if scope == "default" {
		scope = ""
	}
	snap := h.snapshotSettings()
	scopeBranding := snap.Branding.Default
	scopeChallenge := snap.Challenge.Default
	scopeIsSite := false
	if scope != "" {
		scopeIsSite = true
		if bv, ok := snap.Branding.Sites[scope]; ok {
			scopeBranding = bv
		}
		if cv, ok := snap.Challenge.Sites[scope]; ok {
			scopeChallenge = cv
		}
	}
	// Sorted union of every host that has appeared anywhere in the config or
	// the dashboard's site picker.  Feeds both the scope picker (theme +
	// challenge tabs) and the per-row Site dropdowns on bypass / protected /
	// honeypot URLs / rate-limit zones, so the operator sees the same set
	// of suggestions across the settings page.  Sources:
	//   - Branding.Sites / Challenge.Sites keys (= already-configured per-
	//     site scalars)
	//   - per-row Site column on bypass / protected / honeypot URLs / zones
	//     (= sites the operator already typed somewhere else on this page)
	//   - observedSitesFilteredForPicker (= hosts the dashboard has seen
	//     traffic for, so a brand-new site that just started serving still
	//     shows up before the operator has typed it anywhere)
	scopeHostSet := map[string]bool{}
	for h := range snap.Branding.Sites {
		scopeHostSet[h] = true
	}
	for h := range snap.Challenge.Sites {
		scopeHostSet[h] = true
	}
	for _, p := range snap.Nginx.BypassPaths.Paths {
		if p.Site != "" {
			scopeHostSet[p.Site] = true
		}
	}
	for _, p := range snap.Nginx.ProtectedPaths.Paths {
		if p.Site != "" {
			scopeHostSet[p.Site] = true
		}
	}
	for _, u := range snap.Nginx.Honeypot.URLs {
		if u.Site != "" {
			scopeHostSet[u.Site] = true
		}
	}
	for _, z := range snap.RateLimit.Zones {
		if z.Site != "" {
			scopeHostSet[z.Site] = true
		}
	}
	for _, h := range h.observedSitesFilteredForPicker(r, h.cfg().Sites) {
		if h != "" {
			scopeHostSet[h] = true
		}
	}
	// Operator-declared sites (= Settings.Sites.Defined).  These are the
	// hosts the operator explicitly listed on the Sites tab and they should
	// stay visible in the scope picker even when no traffic has hit them
	// yet -- otherwise a brand new vhost the operator just declared would
	// not show up as a candidate until the first request lands.
	for _, host := range h.cfg().Sites.Defined {
		if host != "" {
			scopeHostSet[host] = true
		}
	}
	scopeHosts := make([]string, 0, len(scopeHostSet))
	for h := range scopeHostSet {
		scopeHosts = append(scopeHosts, h)
	}
	sort.Strings(scopeHosts)

	return map[string]any{
		"Lang":                i18n.Resolve(r),
		"TZ":                  resolveTZ(r),
		"BasePath":            h.cfg().Server.BasePath,
		"Version":             h.Version,
		"VersionStatus":       h.versionStatus(),
		"VersionCheckEnabled": h.cfg().VersionCheckURLResolved() != "",
		"ConfigPath":          h.ConfigPath,
		// Self host id (= identifies which machine in a shared DB / aggregated dashboard).
		// SelfHostID: resolved value (= config value → os.Hostname → "default", in priority order).
		// ConfiguredHostID: raw value from config.yml. Empty means the hostname fallback was used.
		"SelfHostID":       h.HostID,
		"ConfiguredHostID": h.cfg().Server.HostID,
		// OSHostname: the raw os.Hostname() — shown next to the "use the OS
		// hostname" radio so the operator sees what that option resolves to,
		// even while a custom id is configured.
		"OSHostname": func() string {
			n, _ := os.Hostname()
			if n == "" {
				return "default"
			}
			return n
		}(),
		// listen mode (= TCP / unix socket). Distinguished by the "unix:" prefix on bind.
		"ListenMode":     listenModeOf(h.cfg().Server),
		"ListenBind":     h.cfg().Server.Bind,
		"ListenPort":     h.cfg().Server.Port,
		"ListenSockPath": defStr(socketPathOf(h.cfg().Server), settings.DefaultListenSocket),
		"ListenSockMode": defStr(h.cfg().Server.SocketMode, "0660"),
		// Keep empty when unset (do NOT default to "nginx"): an empty value lets
		// the daemon auto-detect the web server's group at listen time, so
		// forcing "nginx" into the field would pin it and break apache hosts.
		"ListenSockGroup":       h.cfg().Server.SocketGroup,
		"EventsRetentionDays":   h.cfg().EventsRetentionDays,
		"EventsBatchSize":       h.cfg().EventsBatchSize,
		"EventsBatchIntervalMs": h.cfg().EventsBatchIntervalMs,
		"EventsDropped":         events.GlobalFlusherDropped(),
		"NginxLogEnabled":       h.cfg().NginxLog.Enabled,
		"Retention":             retentionView,
		"Tab":                   tab,
		"TabHelpKey":            tabHelpKey(tab),
		"Saved":                 r.URL.Query().Get("saved") != "",
		// SavedReload: whether the just-saved section ends up in the
		// rendered http.inc.  Drives the post-save banner copy: true =
		// "needs nginx -s reload on native mode"; false = "applies
		// immediately on every mode" (= admin-only sections).
		// SavedReload is driven purely by the conf diff the save handler
		// computed (= reload=1 appended iff the rendered nginx conf changed).
		// No per-section static list -- the deterministic renderer means any
		// conf-affecting field, in any section, flips this automatically.
		"SavedReload": r.URL.Query().Get("reload") == "1",
		// SavedRestart: a listen-side change (Server.*) was saved; it takes effect
		// only on `systemctl restart unmask` (serve reads these at start, not on
		// reload).  Independent of SavedReload -- a TCP<->socket switch needs both.
		"SavedRestart": r.URL.Query().Get("restart") == "1",
		"Error":        readFlash(w, r, h.cfg().Server.BasePath, "err"),
		"Cur":          cur,
		"Global":       h.snapshotSettings().Global,
		// Shipped current-Chrome-major baseline shown as the placeholder for the
		// stale-browser tier's optional override field.
		"StaleBrowserBaseline": settings.DefaultCurrentChromeMajor,
		"IPGeoMMDBPath":        ipgeoCur.MMDBPath,
		"IPGeoMMDBASNPath":     ipgeoCur.MMDBASNPath,
		"IPGeoLoaded":          h.IPGeo != nil && h.IPGeo.Loaded(),
		"IPGeoASNLoaded":       h.IPGeo != nil && h.IPGeo.ASNLoaded(),
		// Custom-path candidates exclude files under /var/lib/unmask/ipgeo/
		// (= that directory belongs to the dbip radio; surfacing the same
		// file under "custom" would confuse the operator).
		"IPGeoCommonGeo": scanIPGeoPaths(ipgeoCommonGeoPaths, h.cfg().IPGeo.MMDBPath, "/var/lib/unmask/ipgeo/", loc),
		"IPGeoCommonASN": scanIPGeoPaths(ipgeoCommonASNPaths, h.cfg().IPGeo.MMDBASNPath, "/var/lib/unmask/ipgeo/", loc),
		// IPGeoMode / IPGeoASNMode: which radio is currently active.
		//   "dbip"   -> saved path matches DefaultMMDBPath / DefaultASNPath
		//   "custom" -> a non-default path
		//   "none"   -> empty (ASN only; country always has a value)
		"IPGeoMode":       ipgeoMode(h.cfg().IPGeo.MMDBPath, ipgeo.DefaultMMDBPath, false),
		"IPGeoASNMode":    ipgeoMode(h.cfg().IPGeo.MMDBASNPath, ipgeo.DefaultASNPath, true),
		"IPGeoDefault":    ipgeo.DefaultMMDBPath,
		"IPGeoASNDefault": ipgeo.DefaultASNPath,
		// Roaming: how many networks one _bv pass cookie stays valid on, and the
		// active new-IP rebind mode (strict / asn / any) for the radio group.
		// ASNDBLoaded drives the "asn mode but no ASN db -> behaves like any" note.
		"RoamingCap":  h.cfg().Rebind.MaxEntriesResolved(),
		"RoamingMode": h.cfg().Rebind.RebindMode(),
		"ASNDBLoaded": h.IPGeo != nil && h.IPGeo.ASNLoaded(),
		// Active-row metadata for the in-line vendor / build / size badges.
		"IPGeoActiveInfo": func() IPGeoPathInfo {
			info, _ := buildIPGeoPathInfo(h.cfg().IPGeo.MMDBPath, loc)
			return info
		}(),
		"IPGeoASNActiveInfo": func() IPGeoPathInfo {
			info, _ := buildIPGeoPathInfo(h.cfg().IPGeo.MMDBASNPath, loc)
			return info
		}(),
		"LBPresets":                  buildLBPresetView(cur),
		"LBExtras":                   buildLBExtraView(cur),
		"SearchBotsRules":            pairRules(cur.SearchBots.Extra, cur.SearchBots.ExtraTitle, cur.SearchBots.ExtraDisabled, cur.SearchBots.ExtraUpdatedAt),
		"UpstreamRescue":             upstreamRescue,
		"UpstreamDisabled":           upstreamDisabledSet,
		"UpstreamRescueTotal":        upstreamTotal,
		"UpstreamRescueEnabled":      upstreamEnabled,
		"UpstreamGroupMode":          upstreamGroupMode,
		"UpstreamGroupAction":        upstreamGroupAction,
		"UpstreamRangeBacked":        upstreamRangeBacked,
		"UpstreamRangeActive":        upstreamRangeActive,
		"UpstreamCatHasRV":           upstreamCatHasRV,
		"JA4Groups":                  ja4Groups,
		"JA4Rules":                   ja4ExtraRules,
		"JA4Verdicts":                cur.JA4Verdicts,
		"JA4PresetAction":            cur.JA4Verdicts.PresetAction,
		"JA4ExtraAction":             padToLen(cur.JA4Verdicts.ExtraAction, len(cur.JA4Verdicts.Extra)),
		"ChallengeAll":               cur.ChallengeTargets.All,
		"ChallengeGroups":            tgtGroups,
		"ChallengeRules":             pairRules(cur.ChallengeTargets.Extra, cur.ChallengeTargets.ExtraTitle, cur.ChallengeTargets.ExtraDisabled, cur.ChallengeTargets.ExtraUpdatedAt),
		"ChallengeTargets":           cur.ChallengeTargets,
		"ChallengePresetAction":      cur.ChallengeTargets.PresetAction,
		"HoneypotGroups":             honeypotGroups,
		"HoneypotRules":              honeypotURLRows(cur.Honeypot.URLs),
		"HoneypotDefaultBanDuration": cur.Honeypot.BanDurationSec,
		"Honeypot":                   cur.Honeypot,
		"HoneypotPresetAction":       cur.Honeypot.PresetAction,
		"BypassIPsRules":             pairBypassRules(cur.BypassIPs, cur.BypassIPsTitle, cur.BypassIPsDisabled, cur.BypassIPsUpdatedAt),
		"StatsExcludeRules":          pairStatsExcludeRules(cur.StatsExcludeIPs, cur.StatsExcludeIPsTitle),
		"BypassPresetGroups":         bypassPresetGroups,
		"IPRangeSync":                h.IPRangeSyncStatus(),
		"ProtectedRules":             protectedPathRows(cur.ProtectedPaths.Paths),
		"BypassPathGroups":           bypassPathGroups,
		"PrivateNetworkCIDRs":        nginxconf.PrivateNetworkCIDRs,
		"RedirectExemptGroups":       redirectExemptGroups,
		"RedirectExemptRules":        redirectExemptRules,
		// AdvancedEnabled: master reveal-gate for the Web Bot Auth + Privacy Pass
		// tabs.  Off => their nav links + top-page shortcuts are hidden and the
		// features are inert (see settings.Nginx.WebBotAuthActive/PrivacyPassActive).
		"AdvancedEnabled":    cur.AdvancedEnabled,
		"WebBotAuth":         cur.WebBotAuth,
		"WebBotAuthPresets":  wbaPresets,
		"WebBotAuthCustom":   wbaCustom,
		"PrivacyPass":        cur.PrivacyPass,
		"PrivacyPassPresets": ppPresets,
		// AdminIPsAllowAll: the IP allowlist contains a /0 entry, making it a
		// no-op (= same as empty).  The network tab shows a warning state line
		// so "restricted-looking but actually wide open" is visible at a glance.
		"AdminIPsAllowAll":      adminIPsAllowAll(cur.AdminAllowedIPs),
		"ProtectedPresetGroups": protectedPresetGroups,
		"AdminCaptchaGate":      adminCaptchaGate,
		"ProtectedPaths":        cur.ProtectedPaths,
		"ProtectedPresetAction": cur.ProtectedPaths.PresetAction,
		"BypassPathsRules":      bypassPathRows(cur.BypassPaths.Paths),
		// Dropdown options come from sites already observed in unmask_event
		// (= auto-complete).  Under "defined" mode, ghost sites are stripped so
		// the picker only suggests names the operator has already declared --
		// matches the ghost-sites filter applied in the dashboard / hunt picker.
		// On failure, continue with an empty list (= datalist works even when
		// empty, the field still accepts free input).
		"Sites": h.observedSitesFilteredForPicker(r, sitesConfig),
		// Sites tab: acceptance config (mode + defined list) + ghost report.
		"SitesConfig":     sitesConfig,
		"SiteModeDefined": sitesConfig.ResolvedMode() == settings.SiteModeDefined,
		"SiteGhosts":      siteGhosts,
		// Host inventory: every unmask instance that has written to the shared
		// DB.  HostDisabled marks the ids that are disabled (= hidden from the
		// picker + excluded from aggregation, toggled per row).
		"HostInventory": hostInventory,
		"HostDisabled":  hostDisabled,
		// SitesTimedOut: the ghostSites / HostInventory aggregates hit the
		// deadline, so an empty list is "couldn't read", not "nothing there".
		"SitesTimedOut": sitesTimedOut,
		// CAPTCHA provider settings (= used by the captcha tab).
		// Pulled from the Default record; the captcha tab edits the global
		// default only.  Per-site captcha provider override is part of the
		// per-site card UI on the challenge tab.
		"Captcha": h.snapshotSettings().Challenge.Default.CaptchaProvider,
		// Settings used by the challenge tab.  The wrapper is still passed
		// (= some helpers need .Challenge.Sites for the site pulldown) but
		// .ChallengeValues now follows the scope picker: scope="" / "default"
		// → cur.Challenge.Default; scope=<host> with an existing entry →
		// cur.Challenge.Sites[host]; scope=<host> with no entry → Default
		// (= seeds the new entry on first save).
		"Challenge":       snap.Challenge,
		"ChallengeValues": scopeChallenge,
		// Settings used by the rate-limit tab (= default zone + named zones list).
		"RateLimit": h.snapshotSettings().RateLimit,
		// Settings used by the geo tab (= Nginx.Geo config).  Pass the whole
		// Nginx struct so the geo template can reference .Nginx.Geo.* directly.
		"Nginx": h.snapshotSettings().Nginx,
		// Country master for the geo tab.  Sorted slice powers the datalist
		// + JS validator; the map gives per-row name lookup without scanning
		// the slice each row.
		"GeoCountriesAll": ipgeo.CountriesSorted(),
		"GeoCountryMap":   ipgeo.Countries,
		// Challenge-page theme (= used by the theme tab; empty/invalid → "auto").
		// Follows the scope picker: scope=<host> reads the per-site Theme
		// (= cur.Challenge.Sites[host].Theme) so the theme card preview shows
		// the per-site selection.
		"ChallengeTheme": func() string {
			t := scopeChallenge.Theme
			if !challengeThemes[t] {
				return "auto" // out-of-the-box default
			}
			return t
		}(),
		// Theme list with a guaranteed display order (= map iteration is unordered).
		// "auto" first since it is the out-of-the-box default (= follow the OS),
		// then the light/dark pair, then the named skins by mood (= calm → lively).
		"ThemeOptions": []string{"auto", "light", "dark", "terminal", "paper", "cat"},
		// Per-theme color override (= recolor a theme to the site palette).  The
		// saved overrides drive the "customize" checkbox + input values; the
		// built-in palette pre-fills inputs the operator hasn't overridden so they
		// edit from the theme's own look.  Both keyed by theme name.
		"ChallengeCustomColors":    scopeChallenge.CustomColors,
		"ChallengeThemeBaseColors": challengeThemeBaseColors,
		// Branding settings used by the theme tab.  The wrapper is still
		// passed (= site pulldown enumerates .Branding.Sites) but
		// .BrandingValues follows the scope picker: scope="" / "default" →
		// cur.Branding.Default; scope=<host> with an existing entry →
		// cur.Branding.Sites[host]; scope=<host> with no entry → Default
		// (= seeds the new entry on first save).  Visitor-facing copy
		// presets are resolved client-side (challenge.js).
		"Branding":       snap.Branding,
		"BrandingValues": scopeBranding,
		// Whether the scope-resolved Branding has a logo on disk.  Used to
		// show the "current logo" thumbnail + the "remove logo" toggle.
		// Path is not shown to the operator (= internal detail).
		"BrandingHasLogo": func() bool {
			if strings.TrimSpace(scopeBranding.LogoPath) == "" {
				return false
			}
			st, err := os.Stat(scopeBranding.LogoPath)
			return err == nil && !st.IsDir()
		}(),
		// Pre-computed admin-side logo URL with a cache-bust query so the
		// preview thumbnail refreshes immediately after upload (= the
		// /branding/logo.<ext> serve carries 5-min Cache-Control).  Reads
		// the scope-resolved LogoPath so the operator sees the per-site
		// logo when scope=<host> is selected.
		"BrandingLogoURL": func() string {
			p := strings.TrimSpace(scopeBranding.LogoPath)
			if p == "" {
				return ""
			}
			ext := strings.ToLower(filepath.Ext(p))
			if !brandingAllowedExt[ext] {
				return ""
			}
			base := strings.TrimRight(h.cfg().Server.BasePath, "/")
			url := base + "/branding/logo"
			if st, err := os.Stat(p); err == nil {
				url += "?v=" + strconv.FormatInt(st.ModTime().Unix(), 10)
			}
			return url
		}(),
		// Scope picker state for the theme + challenge tabs.  Scope is the
		// host name when a per-site override is being edited, empty when the
		// Default record is being edited.  ScopeHosts is the sorted union of
		// hosts that already have an override (= used to populate the <select>
		// dropdown).  ScopeIsSite signals "this is an override edit" so the
		// template can show the [× Reset to default] button + the per-scope
		// banner.
		"Scope":       scope,
		"ScopeIsSite": scopeIsSite,
		"ScopeHosts":  scopeHosts,
		// Per-host override state surfaced to the scope <select> options so
		// each entry can show whether it carries an own record or inherits
		// the Default verbatim.  Keys are host strings from ScopeHosts; the
		// bool is true when an active (non-Disabled) entry exists for that
		// host in the matching section.
		"BrandingOverrideHosts": func() map[string]bool {
			out := make(map[string]bool, len(scopeHosts))
			for _, h := range scopeHosts {
				v, ok := snap.Branding.Sites[h]
				out[h] = ok && !v.Disabled
			}
			return out
		}(),
		"ChallengeOverrideHosts": func() map[string]bool {
			out := make(map[string]bool, len(scopeHosts))
			for _, h := range scopeHosts {
				v, ok := snap.Challenge.Sites[h]
				out[h] = ok && !v.Disabled
			}
			return out
		}(),
		// Per-site override state.  HasEntry = "an entry exists" (= form is
		// pre-filled with the saved values); HasOverride = "an entry exists
		// AND is not Disabled" (= the toggle should ship checked + form
		// values are actually applied).  The split means the operator can
		// un-check + save without destroying the stored record, then re-
		// check later and find their previous edits intact.
		"BrandingHasOverride": func() bool {
			if !scopeIsSite {
				return false
			}
			v, ok := snap.Branding.Sites[scope]
			return ok && !v.Disabled
		}(),
		"BrandingHasEntry": func() bool {
			if !scopeIsSite {
				return false
			}
			_, ok := snap.Branding.Sites[scope]
			return ok
		}(),
		"ChallengeHasOverride": func() bool {
			if !scopeIsSite {
				return false
			}
			v, ok := snap.Challenge.Sites[scope]
			return ok && !v.Disabled
		}(),
		"ChallengeHasEntry": func() bool {
			if !scopeIsSite {
				return false
			}
			_, ok := snap.Challenge.Sites[scope]
			return ok
		}(),
		"BrandingPresets": []string{settings.BrandingPresetFriendly, settings.BrandingPresetNeutral, settings.BrandingPresetMinimal},
		// Notification webhook settings (= used by the notifications tab).
		"Notifications": h.snapshotSettings().Notifications,
		// SMTP settings (= used by the smtp tab). Mask the password (= empty
		// submit preserves the saved value).
		"SMTP": maskedSMTP(h.snapshotSettings().SMTP),
		// community-bans tab. Mask the token (= not shown in UI; the admin issues
		// the submit token via auto-register).
		"CommunityBans": maskedCommunityBans(h.snapshotSettings().CommunityBans),
	}
}

// maskedCommunityBans: display copy. Hide the token contents (= the template only
// needs to distinguish "configured" / "not configured").
func maskedCommunityBans(s settings.CommunityBans) settings.CommunityBans {
	if s.Token != "" {
		s.Token = "***"
	}
	return s
}

// maskedSMTP: SMTP-settings copy for display. Replace non-empty password with
// "***" (= don't surface cleartext; matches the apply-side design where an
// empty submit preserves the saved value).
func maskedSMTP(s settings.SMTP) settings.SMTP {
	if s.Password != "" {
		s.Password = ""
	}
	return s
}

// observedSites: returns DISTINCT site from unmask_event. Returns nil on error.
func (h *Handler) observedSites(r *http.Request) []string {
	if h.DB == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	xs, err := events.DistinctSites(ctx, h.DB)
	if err != nil {
		log.Printf("observedSites: %v", err)
		return nil
	}
	return xs
}

// observedSitesFilteredForPicker drops ghost sites (= observed but not in
// settings.Sites.Defined) when the acceptance mode is "defined".  Auto mode
// returns the full observed list unchanged.  Defined entries that have not
// yet been observed are appended so the operator can pick a freshly defined
// site even before traffic arrives.  Result is alphabetically sorted for
// stable rendering.
func (h *Handler) observedSitesFilteredForPicker(r *http.Request, sc settings.SiteAcceptanceConfig) []string {
	observed := h.observedSites(r)
	if sc.ResolvedMode() != settings.SiteModeDefined {
		return observed
	}
	defined := map[string]bool{}
	for _, s := range sc.Defined {
		s = strings.TrimSpace(s)
		if s != "" {
			defined[s] = true
		}
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(observed)+len(defined))
	for _, s := range observed {
		if defined[s] && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	// Defined-but-unobserved sites: include so the picker can suggest them
	// before any traffic lands.  Empty Defined list -> empty result, which
	// is the right answer (no sites are "known").
	for s := range defined {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// extraRule: (pattern, title, enabled, updated_at) struct passed to the template.
type extraRule struct {
	Pattern   string
	Title     string
	Enabled   bool
	UpdatedAt int64 // unix sec
}

// bypassRule: row-UI struct for the network-tab bypass_ips.
// statsExcludeRule / pairStatsExcludeRules: zip the stats-exclude list and its
// optional titles for the row UI -- the bypass editor's shape minus
// enable/timestamp, which stats exclusion does not carry.
type statsExcludeRule struct {
	IP    string
	Title string
}

func pairStatsExcludeRules(ips, titles []string) []statsExcludeRule {
	out := make([]statsExcludeRule, len(ips))
	for i, ip := range ips {
		var t string
		if i < len(titles) {
			t = titles[i]
		}
		out[i] = statsExcludeRule{IP: ip, Title: t}
	}
	return out
}

type bypassRule struct {
	IP        string
	Title     string
	Enabled   bool
	UpdatedAt int64
}

// pairBypassRules: zip 4 parallel slices into the row-UI struct slice.
func pairBypassRules(ips, titles []string, disabled []bool, updatedAt []int64) []bypassRule {
	out := make([]bypassRule, len(ips))
	for i, ip := range ips {
		var t string
		if i < len(titles) {
			t = titles[i]
		}
		isDisabled := false
		if i < len(disabled) {
			isDisabled = disabled[i]
		}
		var ts int64
		if i < len(updatedAt) {
			ts = updatedAt[i]
		}
		out[i] = bypassRule{IP: ip, Title: t, Enabled: !isDisabled, UpdatedAt: ts}
	}
	return out
}

// ja4ExtraRule: row-UI struct for the JA4 verdict tab (= extraRule + Verdict + Action columns).
type ja4ExtraRule struct {
	ID        int
	Pattern   string
	Verdict   string
	Action    string // "bot" | "suspect" | "ok"
	Title     string
	Enabled   bool
	UpdatedAt int64
}

// pairJA4Rules: zip the 4 parallel slices of JA4Verdicts into the row-UI struct slice.
func pairJA4Rules(
	extras []settings.JA4VerdictExtraRule, titles []string, disabled []bool, updatedAt []int64,
) []ja4ExtraRule {
	out := make([]ja4ExtraRule, len(extras))
	for i, e := range extras {
		var t string
		if i < len(titles) {
			t = titles[i]
		}
		isDisabled := false
		if i < len(disabled) {
			isDisabled = disabled[i]
		}
		var ts int64
		if i < len(updatedAt) {
			ts = updatedAt[i]
		}
		action := e.Action
		if !nginxconf.IsValidJA4Action(action) {
			action = nginxconf.JA4ActionOK
		}
		out[i] = ja4ExtraRule{
			ID:      e.ID,
			Pattern: e.Pattern, Verdict: e.Verdict, Action: action,
			Title: t, Enabled: !isDisabled, UpdatedAt: ts,
		}
	}
	return out
}

// pairRules: zip parallel slices (= patterns + titles + disabled + updatedAt)
// into the template-bound struct slice. The shorter side is padded with defaults.
func pairRules(patterns, titles []string, disabled []bool, updatedAt []int64) []extraRule {
	out := make([]extraRule, len(patterns))
	for i, p := range patterns {
		var t string
		if i < len(titles) {
			t = titles[i]
		}
		isDisabled := false
		if i < len(disabled) {
			isDisabled = disabled[i]
		}
		var ts int64
		if i < len(updatedAt) {
			ts = updatedAt[i]
		}
		out[i] = extraRule{Pattern: p, Title: t, Enabled: !isDisabled, UpdatedAt: ts}
	}
	return out
}

// AdminSettingsSave: POST {base}/admin/settings/save?section=...
//
// Parse the form for the given section, then fresh-disk-read → modify →
// atomic save → render.
func (h *Handler) AdminSettingsSave(w http.ResponseWriter, r *http.Request) {
	if h.ConfigPath == "" {
		http.Error(w, "config path unknown — cannot persist (admin doesn't know where config.yml lives)", http.StatusBadRequest)
		return
	}
	section := r.URL.Query().Get("section")
	// Branding upload uses multipart/form-data because of the logo file.
	// "appearance" carries the same multipart form (= branding + theme in
	// one POST -- the operator sees a single save button on the theme tab).
	// Every other section is plain x-www-form-urlencoded.
	if section == "branding" || section == "appearance" {
		// Cap the upload at ~4 MiB so a runaway POST cannot eat the admin's
		// memory; reasonable for logo files (the typical SVG is <50 KiB).
		if err := r.ParseMultipartForm(4 << 20); err != nil {
			http.Error(w, "bad form (multipart): "+err.Error(), http.StatusBadRequest)
			return
		}
	} else if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	switch section {
	case "global", "network", "ua-filter", "ja4-verdicts", "honeypot", "bypass-ips", "bypass-paths", "web-bot-auth", "privacy-pass", "protected", "captcha", "challenge", "rate_limit", "deny_design", "theme", "branding", "appearance", "notifications", "smtp", "retention", "community-bans", "sites", "about":
		// ok
	default:
		http.Error(w, "unknown section", http.StatusBadRequest)
		return
	}
	base := h.cfg().Server.BasePath
	// nginxReloadNeeded: set true after the form apply when the rendered nginx
	// conf actually changed (= RenderSignature before != after).  This is the
	// authoritative, per-save signal -- no per-section / per-field flags to
	// maintain; any setting that reaches the rendered conf is covered, and
	// admin-only settings never flip it.
	nginxReloadNeeded := false
	// unmaskRestartNeeded: set true when a listen-side setting changed (Server.*),
	// which the daemon only reads at serve start -- a reload won't pick it up, so
	// the operator must `systemctl restart unmask`.  The banner announces it.
	unmaskRestartNeeded := false
	// communityPullNeeded: set true when the community-bans subscribe just went
	// off -> on, so we kick an immediate feed pull after save (= populate the
	// browse list now instead of waiting for the next hourly tick).
	communityPullNeeded := false
	redirBack := func(msg string) {
		dst := base + "/admin/settings/?tab=" + tabForSection(section)
		if msg == "" {
			// Pass the section name through to the saved banner; reload=1 tells
			// the banner the conf changed and native mode needs nginx -s reload.
			dst += "&saved=1&section=" + url.QueryEscape(section)
			if nginxReloadNeeded {
				dst += "&reload=1"
			}
			if unmaskRestartNeeded {
				dst += "&restart=1"
			}
		} else {
			// Carry the error text in a flash cookie rather than the URL
			// (= avoids long, URL-encoded messages cluttering the address bar).
			setFlash(w, r, base, "err", msg)
		}
		http.Redirect(w, r, dst, http.StatusFound)
	}

	// fresh load (= stays consistent even if another process touches the file)
	cur, err := settings.Load(h.ConfigPath)
	if err != nil {
		redirBack("load: " + err.Error())
		return
	}
	// Snapshot the pre-mutation yaml for the audit log.  Captured here, not
	// after Save, so a partial / failing apply does not leave a misleading
	// diff in the audit.  MarshalYAML failures fall through to an empty
	// snapshot (= the audit row is still written, just without rollback data).
	beforeYAML, _ := settings.MarshalYAML(cur)

	// Snapshot the rendered nginx conf before the form apply.  The renderer is
	// deterministic (= all map outputs sorted), so an unchanged conf yields a
	// byte-identical signature -- letting us reload-prompt ONLY when the save
	// actually altered the conf, automatically across every section / field.
	// A signature error falls back to a conservative "assume reload needed".
	beforeSig, beforeSigErr := nginxconf.RenderSignature(cur, "", h.Version)

	lang := i18n.Resolve(r)
	// Snapshot listen-side config before the apply so we can detect a change that
	// needs a unmask restart (Server is all scalar fields, so a value compare of
	// the whole struct catches bind / port / socket_mode / socket_group / base_path).
	beforeServer := cur.Server
	switch section {
	case "global":
		cur.Global.Passthrough = r.FormValue("global_passthrough") == "1"
		validBucket := func(v string) string {
			v = strings.TrimSpace(v)
			if v == "" || v == "pass" {
				return "pass"
			}
			if settings.IsValidRateChallengeMode(v) {
				return v
			}
			return "pass"
		}
		cur.Global.KnownBrowserAction = validBucket(r.FormValue("global_known_browser_action"))
		cur.Global.UnknownUAAction = validBucket(r.FormValue("global_unknown_ua_action"))
	case "network":
		if err := applyNetworkForm(&cur.Nginx, r, lang, adminClientIP(r, h.snapshotSettings()), r.Host); err != nil {
			redirBack(err.Error())
			return
		}
		if err := applyServerListenForm(&cur.Server, r, lang); err != nil {
			redirBack(err.Error())
			return
		}
		if err := applyIPGeoForm(&cur.IPGeo, r, lang); err != nil {
			redirBack(err.Error())
			return
		}
		applyTrustedLBForm(&cur.Nginx, r)
		// HTTP->HTTPS redirect toggle (emitted at the top of server.inc).
		cur.Nginx.HTTPSRedirect = r.FormValue("https_redirect") == "1"
		if err := applyRedirectExemptForm(&cur.Nginx, r, lang); err != nil {
			redirBack(err.Error())
			return
		}
	case "ua-filter":
		applyUAFilterForm(&cur.Nginx, r)
		// Stale-browser tier (lives on the UA-filter tab: it is a UA-string rule
		// — old Chrome version → challenge — a sibling to the challenge-target
		// blacklist).  The fields persist in Global; the tab is only a UI home.
		// A blank/invalid current-major stores 0, which resolves to the shipped
		// DefaultCurrentChromeMajor at render/serve time (CurrentChromeMajorResolved)
		// — so the toggle alone works out of the box; the field is an optional
		// override.  Action restricted to real screens; anything else falls back
		// to the captcha_only default via StaleBrowserResolvedAction.
		cur.Global.StaleBrowserChallenge = r.FormValue("stale_browser_challenge") == "1"
		parseIntInRange := func(v string, lo, hi int) int {
			n, err := strconv.Atoi(strings.TrimSpace(v))
			if err != nil || n < lo || n > hi {
				return 0
			}
			return n
		}
		cur.Global.CurrentChromeMajor = parseIntInRange(r.FormValue("current_chrome_major"), 1, 999)
		cur.Global.StaleBrowserLag = parseIntInRange(r.FormValue("stale_browser_lag"), 1, 99)
		if a := strings.TrimSpace(r.FormValue("stale_browser_action")); settings.IsValidRateChallengeMode(a) && a != "pass" {
			cur.Global.StaleBrowserAction = a
		} else {
			cur.Global.StaleBrowserAction = ""
		}
		// Black-list default action (= independent of rate-limit chain).
		if v := strings.TrimSpace(r.FormValue("ua_black_action")); v != "" {
			if settings.IsValidRateChallengeMode(v) {
				cur.Nginx.ChallengeTargets.DefaultAction = v
			}
		}
	case "ja4-verdicts":
		if err := applyJA4VerdictsForm(&cur.Nginx, r, lang); err != nil {
			redirBack(err.Error())
			return
		}
	case "honeypot":
		if err := applyHoneypotForm(&cur.Nginx, r, lang); err != nil {
			redirBack(err.Error())
			return
		}
	case "bypass-ips":
		if err := applyBypassIPsForm(&cur.Nginx, r, lang); err != nil {
			redirBack(err.Error())
			return
		}
	case "protected":
		if err := applyProtectedForm(&cur.Nginx, r, lang); err != nil {
			redirBack(err.Error())
			return
		}
	case "bypass-paths":
		if err := applyBypassPathsForm(&cur.Nginx, r, lang); err != nil {
			redirBack(err.Error())
			return
		}
	case "captcha":
		// CAPTCHA provider edits target the Default record; per-site CAPTCHA
		// overrides ride the per-site card endpoints (see add/edit/delete
		// routes below).
		if err := applyCaptchaForm(&cur.Challenge.Default.CaptchaProvider, r); err != nil {
			redirBack(err.Error())
			return
		}
	case "challenge":
		// Challenge tab save: applyChallengeFormV2 updates Default + Sites
		// from the same form payload (= one click writes both blocks).
		if err := applyChallengeFormV2(&cur.Challenge, r); err != nil {
			redirBack(err.Error())
			return
		}
		// Roaming: how many networks one _bv pass cookie stays valid on, and the
		// new-IP rebind policy (strict / asn / any).  Both live on cur.Rebind.
		if v, err := strconv.Atoi(strings.TrimSpace(r.FormValue("roaming_cap"))); err == nil {
			if v < 1 {
				v = 1
			} else if v > 16 {
				v = 16
			}
			cur.Rebind.MaxEntries = v
		}
		if m := strings.TrimSpace(r.FormValue("rebind_mode")); m != "" {
			cur.Rebind.SetRebindMode(m)
		}
	case "rate_limit":
		if err := applyRateLimitForm(&cur.RateLimit, r); err != nil {
			redirBack(err.Error())
			return
		}
	case "geo":
		if err := applyGeoForm(&cur.Nginx.Geo, r); err != nil {
			redirBack(err.Error())
			return
		}
	case "theme":
		// Challenge-page theme.  Targets the Default record; per-site theme
		// override lives on the per-site card on the challenge tab.  Keep
		// the allowlist in sync with handlers.go challengeThemes ("light"
		// / "cat" / ...); invalid values snap to "auto".
		t := strings.TrimSpace(r.FormValue("theme"))
		if !challengeThemes[t] {
			t = "auto"
		}
		cur.Challenge.Default.Theme = t
		cur.Challenge.Default.CustomColors = parseChallengeCustomColors(r)
	case "branding":
		// Branding tab save: applyBrandingFormV2 updates Default + Sites
		// from the same form payload.  See settings.Branding for the data
		// shape and handlers.go ServeBrandingLogo for the logo serve path.
		if err := applyBrandingFormV2(&cur.Branding, h.ConfigPath, r); err != nil {
			redirBack(err.Error())
			return
		}
	case "appearance":
		// Combined save for the theme tab: branding identity + copy preset
		// + theme card + "show credit" badge.  Multiple forms with multiple
		// save buttons on the same page confused operators; appearance
		// dispatches them all from one button press.  All operate on the
		// Default record.
		if err := applyBrandingFormV2(&cur.Branding, h.ConfigPath, r); err != nil {
			redirBack(err.Error())
			return
		}
		t := strings.TrimSpace(r.FormValue("theme"))
		if !challengeThemes[t] {
			t = "auto"
		}
		cur.Challenge.Default.Theme = t
		cur.Challenge.Default.CustomColors = parseChallengeCustomColors(r)
		// show_credit was previously on the challenge tab; now lives next
		// to the theme cards so the operator sees the live preview toggle
		// alongside it.  Plain checkbox -> bool.
		cur.Challenge.Default.ShowCredit = r.FormValue("show_credit") == "1"
	case "notifications":
		applyNotificationsForm(&cur.Notifications, r)
	case "smtp":
		applySMTPForm(&cur.SMTP, r)
	case "web-bot-auth":
		applyWebBotAuthForm(&cur.Nginx.WebBotAuth, r)
	case "privacy-pass":
		applyPrivacyPassForm(&cur.Nginx.PrivacyPass, r)
	case "community-bans":
		// Snapshot the pre-apply subscribe state.  When the operator flips
		// subscribe from off to fetch / fetch_apply they expect the "共有 BAN"
		// browse list to populate right away, so an off -> on transition kicks
		// an immediate pull below instead of waiting up to an hour for the
		// next periodic tick.
		wasSubscribing := cur.CommunityBans.SubscribeActive()
		applyCommunityBansForm(&cur.CommunityBans, r)
		communityPullNeeded = !wasSubscribing && cur.CommunityBans.SubscribeActive()
		// The shared-BAN fallback action is not edited from the UI: the
		// "auto-BAN action" select writes a concrete action onto every
		// auto-applied row, so a separate fallback rarely matters.  The
		// yaml field (Nginx.Bans.CommunityBansDefaultAction) is still
		// honored at runtime for operators who set it manually.
	case "sites":
		// The Sites / Hosts tab is one form: site acceptance + this host's id.
		applySitesForm(&cur.Sites, r)
		// host id: "hostname" mode clears it so the OS hostname fallback
		// applies; "custom" stores the charset-guarded value.  Takes effect on
		// the next admin restart (h.HostID is resolved at startup).
		if r.FormValue("host_id_mode") == "custom" {
			hid := strings.TrimSpace(r.FormValue("host_id"))
			if hid != "" && !hostIDRE.MatchString(hid) {
				redirBack("invalid host id (allowed: letters, digits, dot, underscore, hyphen)")
				return
			}
			cur.Server.HostID = hid
		} else {
			cur.Server.HostID = ""
		}
	case "about":
		// version_check checkbox: present (= ticked) means enabled; an absent
		// field (unticked) disables the update check entirely.
		cur.VersionCheckDisabled = r.FormValue("version_check") == ""
		// Advanced master reveal-gate, co-located with the version-check toggle
		// (both install-level opt-ins).  Off hides the Web Bot Auth + Privacy
		// Pass tabs and makes both inert (WebBotAuthActive/PrivacyPassActive AND
		// on this), without disturbing their per-feature config.  Submitted in
		// the same form as version_check, so it's always present here.
		cur.Nginx.AdvancedEnabled = r.FormValue("advanced_enabled") == "1"
	case "retention":
		// events_retention_days: 0 = retain forever; sanity-capped at 3650 (= 10 years).
		// No need to restart the goroutine on change (= EventsRetentionDays is
		// read via h.cfg(), so the published swap takes effect from the next tick).
		if v, err := strconv.Atoi(strings.TrimSpace(r.FormValue("events_retention_days"))); err == nil {
			if v < 0 {
				v = 0
			} else if v > 3650 {
				v = 3650
			}
			cur.EventsRetentionDays = v
		}
		// events_batch_size: clamp to 1..1000.
		if v, err := strconv.Atoi(strings.TrimSpace(r.FormValue("events_batch_size"))); err == nil {
			if v < 1 {
				v = 1
			} else if v > 1000 {
				v = 1000
			}
			cur.EventsBatchSize = v
		}
		// events_batch_interval_ms: clamp to 50..60000 (= 1 min).
		if v, err := strconv.Atoi(strings.TrimSpace(r.FormValue("events_batch_interval_ms"))); err == nil {
			if v < 50 {
				v = 50
			} else if v > 60000 {
				v = 60000
			}
			cur.EventsBatchIntervalMs = v
		}
		// Hot-reload the flusher (= runs with the new values from the next cycle).
		events.GlobalFlusherSetConfig(cur.EventsBatchSize, cur.EventsBatchIntervalMs)
		// nginx_log_enabled toggle. To apply, the next render-nginx + nginx
		// reload + admin service restart (= socket bind close/reopen) is
		// required. We don't toggle this on the fly (= the recvLoop goroutine's
		// running state is not changed by design).
		cur.NginxLog.Enabled = r.FormValue("nginx_log_enabled") == "1"
	}

	// Record the admin version at the moment the user saves the settings page.
	// On the next render, presets with AddedIn newer than this are treated as
	// new (= forced OFF + NEW badge).  Dev / source builds carry a git hash as
	// Version; stamping that would poison the gate (PresetIsNew reads it as
	// unparseable), so keep the previous SeenVersion on such builds.
	if v := "v" + h.Version; nginxconf.VersionParseable(v) {
		cur.Nginx.SeenVersion = v
	}

	// Conf diff: reload-prompt only when the rendered conf actually changed.
	// Errors on either side conservatively assume a reload is needed.
	if beforeSigErr != nil {
		nginxReloadNeeded = true
	} else if afterSig, sigErr := nginxconf.RenderSignature(cur, "", h.Version); sigErr != nil {
		nginxReloadNeeded = true
	} else {
		nginxReloadNeeded = afterSig != beforeSig
	}
	// Listen-side settings are read only at serve start, so a change there needs
	// `systemctl restart unmask`, independent of the nginx-conf reload signal.
	unmaskRestartNeeded = cur.Server != beforeServer

	if err := settings.Save(cur, h.ConfigPath); err != nil {
		redirBack("save: " + err.Error())
		return
	}
	if err := nginxconf.Render(cur, "", h.Version); err != nil {
		// A render failure is critical (= the file is saved but nginx keeps the
		// old conf). Surface the error in the banner while noting that the
		// save itself did complete.
		redirBack("save ok / render failed: " + err.Error())
		return
	}

	// in-memory swap (= the next GET sees the new values)
	settingsMu.Lock()
	h.settingsPtr.Store(&cur)
	settingsMu.Unlock()

	// ipgeo hot-swap (= picks up mmdb path changes immediately, no restart)
	if h.IPGeo != nil {
		h.IPGeo.Reload(cur.IPGeo.MMDBPath, cur.IPGeo.MMDBASNPath)
	}

	// classify hot-swap: rebuild the upstream per-pattern disable filter so
	// the next IsBot call reflects the saved settings.
	if section == "ua-filter" {
		classify.SetUpstreamDisabled(cur.Nginx.SearchBots.UpstreamDisabled)
	}

	// notifier hot-swap (= picks up URL / format / threshold changes immediately)
	if h.Notifier != nil {
		h.Notifier.SetConfig(notifier.Config{
			Disabled:            cur.Notifications.Disabled,
			URL:                 cur.Notifications.URL,
			Format:              cur.Notifications.Format,
			Sites:               cur.Notifications.SiteLabel,
			BanEvents:           cur.Notifications.BanEvents,
			ChallengeBurst:      cur.Notifications.ChallengeBurst,
			BurstThresholdPer5m: cur.Notifications.BurstThresholdPer5m,
		})
	}

	// mailer hot-swap (= picks up host/auth changes immediately)
	if h.Mailer != nil {
		h.Mailer.SetConfig(mail.Config{
			Host:               cur.SMTP.Host,
			Port:               cur.SMTP.Port,
			Username:           cur.SMTP.Username,
			Password:           cur.SMTP.Password,
			FromAddress:        cur.SMTP.FromAddress,
			FromName:           cur.SMTP.FromName,
			StartTLS:           cur.SMTP.StartTLS,
			InsecureSkipVerify: cur.SMTP.InsecureSkipVerify,
		})
	}

	// Avoid "no token" right after enabling community-bans and immediately BANning:
	// when terms accepted + submit_enabled / subscribe active and no
	// token exists yet, trigger an asynchronous register right after save.
	// This is redundant with the synchronous register at submit time, but
	// ensures the "save → BAN" flow from the settings page does not drop a row.
	if section == "community-bans" && h.CommunityBans != nil &&
		(cur.CommunityBans.SubmitActive() || cur.CommunityBans.SubscribeActive()) &&
		strings.TrimSpace(cur.CommunityBans.Token) == "" {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			if err := h.CommunityBans.Register(ctx); err != nil {
				log.Printf("communitybans: post-save register: %v", err)
			}
		}()
	}

	// Subscribe just went off -> on: pull the feed now so the "共有 BAN" browse
	// list shows entries immediately rather than after the next hourly tick.
	// Runs async (= a slow / unreachable hub must not stall the save redirect);
	// Pull takes the client mutex, so it serialises with the periodic pull.  The
	// browse doc this populates needs no nginx reload; fetch_apply map
	// enforcement still does (maps are include-loaded), which is the operator's
	// step as usual.
	if communityPullNeeded && h.CommunityBans != nil {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if _, err := h.CommunityBans.Pull(ctx); err != nil {
				log.Printf("communitybans: pull after subscribe enable: %v", err)
			}
		}()
	}

	// audit log: who / what / before-after diff.  detail is a JSON blob with
	// both yaml snapshots so the audit UI can show a unified diff and offer
	// 1-click rollback to the captured `before`.  Marshal failure (= huge
	// yaml etc.) downgrades silently to an empty detail; the audit row is
	// still written.
	if pay := SessionFromContext(r); pay != nil && h.UserRepo != nil {
		username := ""
		if u, err := h.UserRepo.GetByID(r.Context(), pay.UserID); err == nil {
			username = u.Username
		}
		afterYAML, _ := settings.MarshalYAML(cur)
		auditWriteSettingsSave(r.Context(), h, pay.UserID, username, section, beforeYAML, afterYAML)
	}

	redirBack("")
}

// tabForSection maps a save form's ?section= value to the destination tab
// for the post-save redirect.  Most sections share the name; the branding /
// appearance forms live inside the theme tab, so they redirect there.
func tabForSection(s string) string {
	if s == "branding" || s == "appearance" {
		return "theme"
	}
	if s == "deny_design" {
		return "deny-design"
	}
	return s
}

func (h *Handler) snapshotSettings() settings.Settings {
	// Load is atomic and the deref copies the struct, so no settingsMu needed
	// here — the lock now serializes writers only.
	return *h.cfg()
}

// SnapshotSettings: exported version of snapshotSettings. Entry point for safe
// access from non-handler packages (= communitybans's SettingsGetter callback etc.).
func (h *Handler) SnapshotSettings() settings.Settings { return h.snapshotSettings() }

// UpdateSettings: atomically modify + persist + in-memory swap a settings.Settings.
//  1. Re-load the latest from disk (= consistent with other processes / concurrent saves)
//  2. Apply the mutator
//  3. Atomic save to file
//  4. Publish the new snapshot (atomic Store under settingsMu)
//
// Returns ErrNoConfigPath and does nothing if ConfigPath is empty.
//
// Use: communitybans package's SettingsUpdate callback (= server-driven write-back
// of token / last_pulled_at / entries). Distinct from the web UI write path,
// but shares the same disk file + same in-memory state.
func (h *Handler) UpdateSettings(mutate func(*settings.Settings)) error {
	if h.ConfigPath == "" {
		return ErrNoConfigPath
	}
	if mutate == nil {
		return nil
	}
	settingsMu.Lock()
	defer settingsMu.Unlock()
	cur, err := settings.Load(h.ConfigPath)
	if err != nil {
		return err
	}
	mutate(&cur)
	if err := settings.Save(cur, h.ConfigPath); err != nil {
		return err
	}
	h.settingsPtr.Store(&cur)
	return nil
}

// ErrNoConfigPath: sentinel returned by UpdateSettings when Handler.ConfigPath is empty.
var ErrNoConfigPath = errors.New("handler: ConfigPath is empty (= cannot persist settings)")

// ---------------------------------------------------------------------------
// per-form apply
// ---------------------------------------------------------------------------

var ipOrCIDRRE = regexp.MustCompile(`^[0-9a-fA-F:.\/]+$`)

// listenModeOf: returns the listen mode ("tcp" | "socket") from settings.Server.Bind.
func listenModeOf(s settings.Server) string {
	if strings.HasPrefix(s.Bind, "unix:") {
		return "socket"
	}
	return "tcp"
}

// socketPathOf: returns the path portion if bind is in unix: form; empty for TCP.
func socketPathOf(s settings.Server) string {
	if strings.HasPrefix(s.Bind, "unix:") {
		return strings.TrimPrefix(s.Bind, "unix:")
	}
	return ""
}

// defStr: returns fallback for an empty string. Used to format template defaults.
func defStr(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

// applyServerListenForm: receives the listen-mode form (= TCP / unix socket).
//
//	listen_mode  : "tcp" | "socket" radio.
//	tcp_bind     : bind IP for TCP (= "127.0.0.1" / "0.0.0.0" / a specific IP).
//	tcp_port     : port for TCP (= 1..65535).
//	socket_path  : absolute path for unix socket (= "/run/unmask/http.sock" etc.).
//	socket_mode  : octal file-mode string (= "0660" etc.). Empty = keep current.
//	socket_group : group owner name. Empty = keep current.
//
// The change is saved to config.yml but does not take effect on reload
// (= listen-side change requires systemctl restart unmask). The banner
// announces this.
func applyServerListenForm(s *settings.Server, r *http.Request, lang i18n.Lang) error {
	mode := strings.TrimSpace(r.FormValue("listen_mode"))
	switch mode {
	case "tcp":
		bind := strings.TrimSpace(r.FormValue("tcp_bind"))
		if bind == "" {
			bind = "127.0.0.1"
		}
		// Only IP / "0.0.0.0" / "::" / hostname allowed. Reject dangerous chars.
		if !ipOrCIDRRE.MatchString(bind) && bind != "::" {
			return fmt.Errorf("%s", i18n.Tf(lang, "err.listen_bind_invalid", bind))
		}
		port, err := strconv.Atoi(strings.TrimSpace(r.FormValue("tcp_port")))
		if err != nil || port < 1 || port > 65535 {
			return fmt.Errorf("%s", i18n.Tf(lang, "err.listen_port_invalid", r.FormValue("tcp_port")))
		}
		s.Bind = bind
		s.Port = port
	case "socket":
		path := strings.TrimSpace(r.FormValue("socket_path"))
		if path == "" || !strings.HasPrefix(path, "/") {
			return fmt.Errorf("%s", i18n.Tf(lang, "err.listen_socket_path", path))
		}
		// path injection guard: the bind value lands unquoted in
		// nginx upstream's `server {{ .UpstreamServer }};` (= http.conf.tmpl
		// :714).  A stray `;` / ` ` / `}` / `#` would close the directive or
		// the block and let an admin form save inject arbitrary http-scope
		// directives.  Reject anything outside a clean POSIX path.
		if strings.ContainsAny(path, "\"\\\x00\r\n\t ;{}#") {
			return fmt.Errorf("%s", i18n.Tf(lang, "err.listen_socket_path", path))
		}
		s.Bind = "unix:" + path
		// Port is meaningless here but we keep the existing value (= hint kept for switching back to TCP).
		mode := strings.TrimSpace(r.FormValue("socket_mode"))
		if mode != "" {
			// Octal-format check.
			if _, err := strconv.ParseUint(mode, 8, 32); err != nil {
				return fmt.Errorf("%s", i18n.Tf(lang, "err.listen_socket_mode", mode))
			}
			s.SocketMode = mode
		}
		grp := strings.TrimSpace(r.FormValue("socket_group"))
		// Empty group is OK (= save empty to keep default "nginx"). For non-empty,
		// only reject control chars (= existence check is deferred to LookupGroup
		// at startup; rejecting unknown groups at save time would block the
		// "groupadd later" workflow).
		if strings.ContainsAny(grp, "\"\\\x00\r\n /") {
			return fmt.Errorf("%s", i18n.Tf(lang, "err.listen_socket_group", grp))
		}
		s.SocketGroup = grp
	default:
		// Don't touch this for sections that have no listen form (= mode is empty).
		return nil
	}
	return nil
}

// adminIPsAllowAll reports whether the admin IP allowlist contains a /0
// entry (0.0.0.0/0, ::/0, ...), which admits every address and makes the
// list equivalent to empty.  Used by the settings network tab to surface a
// "looks restricted, is actually wide open" state.
func adminIPsAllowAll(list []string) bool {
	for _, e := range list {
		if strings.HasSuffix(strings.TrimSpace(e), "/0") {
			return true
		}
	}
	return false
}

func applyNetworkForm(n *settings.Nginx, r *http.Request, lang i18n.Lang, curIP, curHost string) error {
	// admin_allowed_ips / admin_allowed_hosts / metrics_allow_from all accept
	// empty (= empty means allow all), so a forgotten list never locks you out.
	// A NON-empty list that excludes the operator's own IP / Host is rejected
	// here to prevent a save-time self-lockout (curIP/curHost are this request's,
	// resolved the same way the /admin/* gate resolves them).
	allow := formList(r.Form["admin_allowed_ips"])
	for _, a := range allow {
		if !ipOrCIDRRE.MatchString(a) {
			return fmt.Errorf("%s", i18n.Tf(lang, "err.admin_allow_invalid", a))
		}
	}
	if len(allow) > 0 && !ipAllowed(curIP, allow) {
		return fmt.Errorf("%s", i18n.Tf(lang, "err.admin_lockout_ip", curIP))
	}
	n.AdminAllowedIPs = allow

	// Host allowlist (= which domains may reach /admin/* when one nginx serves
	// many vhosts).  Matched in-app, never written to nginx config, so no
	// injection guard is needed beyond the self-lockout check.
	hosts := formList(r.Form["admin_allowed_hosts"])
	if len(hosts) > 0 && !hostAllowed(curHost, hosts) {
		return fmt.Errorf("%s", i18n.Tf(lang, "err.admin_lockout_host", curHost))
	}
	n.AdminAllowedHosts = hosts

	mallow := formList(r.Form["metrics_allow_from"])
	for _, a := range mallow {
		if !ipOrCIDRRE.MatchString(a) {
			return fmt.Errorf("%s", i18n.Tf(lang, "err.metrics_allow_invalid", a))
		}
	}
	n.MetricsAllowFrom = mallow
	return nil
}

// Common mmdb locations. Searched in priority order by the UI.
var ipgeoCommonGeoPaths = []string{
	"/usr/share/GeoIP/GeoLite2-City.mmdb",
	"/usr/share/GeoIP/GeoLite2-Country.mmdb",
	"/var/lib/GeoIP/GeoLite2-City.mmdb",
	"/var/lib/GeoIP/GeoLite2-Country.mmdb",
	"/etc/unmask/ipgeo/GeoLite2-City.mmdb",
	"/etc/unmask/ipgeo/GeoLite2-Country.mmdb",
}
var ipgeoCommonASNPaths = []string{
	"/usr/share/GeoIP/GeoLite2-ASN.mmdb",
	"/var/lib/GeoIP/GeoLite2-ASN.mmdb",
	"/etc/unmask/ipgeo/GeoLite2-ASN.mmdb",
}

// IPGeoPathInfo: existence status + vendor detection for one known mmdb path.
// Vendor / DatabaseType come from ipgeo.InspectMMDB so the UI can show
// "MaxMind GeoLite2-Country" vs "DB-IP Country Lite" badges on each row.
type IPGeoPathInfo struct {
	Path         string
	Exists       bool
	MTime        string // RFC-like ("2006-01-02 15:04 UTC") -- noscript fallback
	MTimeTS      int64  // unix sec UTC; template emits <time class="js-datetime" data-ts="..."> and JS formats it in browser TZ
	Size         string // human-readable ("4.0 MB")
	Vendor       string // "MaxMind" / "DB-IP" / "IP2Location" / "Unknown" / "" (= unreadable)
	DatabaseType string // raw mmdb DatabaseType (e.g. "DBIP-Country-Lite")
	BuildTime    string // YYYY-MM-DD UTC from mmdb metadata (= snapshot date, not file mtime)
}

// ipgeoMode: which network-tab radio applies given the configured path.
//
// allowNone=false (= country DB; never optional):
//   - empty / DefaultMMDBPath -> "dbip"
//   - anything else           -> "custom"
//
// allowNone=true (= ASN DB; the operator may turn it off entirely):
//   - empty                   -> "none"
//   - DefaultASNPath          -> "dbip"
//   - anything else           -> "custom"
func ipgeoMode(path, defaultPath string, allowNone bool) string {
	if path == "" {
		if allowNone {
			return "none"
		}
		return "dbip"
	}
	if path == defaultPath {
		return "dbip"
	}
	return "custom"
}

// scanIPGeoPaths: stats the candidate list and returns **only existing files**.
// Drop non-existent paths since the UI has nothing useful to show.
//
// excludePrefix: file paths starting with this string are skipped, even if
// they exist.  Used to keep the dbip-managed directory
// (= /var/lib/unmask/ipgeo/) out of the "custom path" candidates — that
// directory belongs to the radio's DB-IP mode, surfacing it under custom
// would confuse the operator.
//
// If currentPath is non-empty, not in the common candidates, not under the
// excluded prefix, and the file exists, append it at the tail (= ensures a
// file placed in an unexpected directory still shows up).  If currentPath
// does not exist, do not append.
func scanIPGeoPaths(paths []string, currentPath, excludePrefix string, loc *time.Location) []IPGeoPathInfo {
	out := make([]IPGeoPathInfo, 0, len(paths)+1)
	seen := map[string]bool{}
	excluded := func(p string) bool {
		return excludePrefix != "" && strings.HasPrefix(p, excludePrefix)
	}
	for _, p := range paths {
		if excluded(p) {
			continue
		}
		if info, ok := buildIPGeoPathInfo(p, loc); ok {
			out = append(out, info)
			seen[p] = true
		}
	}
	if currentPath != "" && !seen[currentPath] && !excluded(currentPath) {
		if info, ok := buildIPGeoPathInfo(currentPath, loc); ok {
			out = append(out, info)
		}
	}
	return out
}

// buildIPGeoPathInfo: stat + mmdb metadata into a single IPGeoPathInfo.
// Returns (zero, false) when the file is missing.  Metadata-parse failures
// (= a non-mmdb file at the path) still return the row with empty Vendor
// / DatabaseType so the UI can flag "unreadable".
func buildIPGeoPathInfo(p string, loc *time.Location) (IPGeoPathInfo, bool) {
	if loc == nil {
		loc = time.UTC
	}
	st, err := osStat(p)
	if err != nil {
		return IPGeoPathInfo{}, false
	}
	row := IPGeoPathInfo{
		Path:    p,
		Exists:  true,
		MTime:   st.ModTime().In(loc).Format("2006-01-02 15:04 MST"),
		MTimeTS: st.ModTime().Unix(),
		Size:    humanSize(st.Size()),
	}
	if info, err := ipgeo.InspectMMDB(p); err == nil {
		row.Vendor = info.Vendor
		row.DatabaseType = info.DatabaseType
		if !info.BuildTime.IsZero() {
			row.BuildTime = info.BuildTime.Format("2006-01-02")
		}
	}
	return row, true
}

// LBPresetView: display struct for a built-in LB preset passed to the settings template.
type LBPresetView struct {
	ID        string
	Label     string
	CIDRCount int
	CIDRs     []string // actual IP / CIDR list (= shown when details is expanded)
	Source    string   // distribution URL
	Header    string
	Enabled   bool
}

// LBExtraView: display struct for custom (= user-added) LBs. CIDRs are joined
// as CSV and shown in a single input.
type LBExtraView struct {
	ID     string
	CIDRs  string
	Header string
}

// buildLBPresetView: merge built-in presets (= nginxconf.LBIPRanges) with
// TrustedLBPresets from settings into the checkbox-display view.
func buildLBPresetView(n settings.Nginx) []LBPresetView {
	enabled := map[string]bool{}
	for _, id := range n.TrustedLBPresets {
		enabled[id] = true
	}
	out := make([]LBPresetView, 0, len(nginxconf.LBIPRanges))
	for _, p := range nginxconf.LBIPRanges {
		if len(p.CIDRs) == 0 {
			continue
		}
		out = append(out, LBPresetView{
			ID:        p.ID,
			Label:     p.Label,
			CIDRCount: len(p.CIDRs),
			CIDRs:     p.CIDRs,
			Source:    p.Source,
			Header:    nginxconf.HeaderFromNginxVar(p.Header),
			Enabled:   enabled[p.ID],
		})
	}
	return out
}

// buildLBExtraView: display for the custom row UI.
func buildLBExtraView(n settings.Nginx) []LBExtraView {
	out := make([]LBExtraView, 0, len(n.TrustedLBExtra))
	for _, e := range n.TrustedLBExtra {
		out = append(out, LBExtraView{
			ID:     e.ID,
			CIDRs:  strings.Join(e.CIDRs, ", "),
			Header: nginxconf.HeaderFromNginxVar(e.Header),
		})
	}
	return out
}

// lbExtraIDRE constrains a custom trusted-LB id to an nginx-safe identifier.
// The id is emitted into the rendered config (geo var name + quoted map key),
// so a '"' or whitespace would break out; only [A-Za-z0-9_-] is allowed.
var lbExtraIDRE = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// applyTrustedLBForm: receives the trusted-LB section of the network tab.
//   - trusted_lb_preset[]   : preset IDs enabled via checkbox
//   - lb_extra_id[] / lb_extra_cidrs[] / lb_extra_header[] : 3 parallel arrays from the row UI
func applyTrustedLBForm(n *settings.Nginx, r *http.Request) {
	// The trusted-LB list below is the single source of truth for both native
	// mode (http.inc geo) and forward-auth (forward-auth-lbtrust.conf gate +
	// the resolveForwardedJA4 peer check), so there is no separate "trust
	// forwarded JA4" toggle to apply here.
	n.TrustedLBPresets = nil
	for _, id := range r.Form["trusted_lb_preset"] {
		id = strings.TrimSpace(id)
		if id != "" {
			n.TrustedLBPresets = append(n.TrustedLBPresets, id)
		}
	}
	ids := r.Form["lb_extra_id"]
	cidrs := r.Form["lb_extra_cidrs"]
	hdrs := r.Form["lb_extra_header"]
	maxLen := len(ids)
	for _, l := range []int{len(cidrs), len(hdrs)} {
		if l > maxLen {
			maxLen = l
		}
	}
	extras := make([]settings.TrustedLBExtra, 0, maxLen)
	for i := 0; i < maxLen; i++ {
		var id, c, h string
		if i < len(ids) {
			id = strings.TrimSpace(ids[i])
		}
		if i < len(cidrs) {
			c = strings.TrimSpace(cidrs[i])
		}
		if i < len(hdrs) {
			h = strings.TrimSpace(hdrs[i])
		}
		if id == "" || c == "" {
			continue
		}
		// Reject ids that aren't nginx-safe identifiers (= injection guard:
		// the id lands in a geo var name and a quoted map key).
		if !lbExtraIDRE.MatchString(id) {
			continue
		}
		// Split CIDRs by CSV or whitespace separators.
		var cidrList []string
		for _, s := range strings.FieldsFunc(c, func(r rune) bool {
			return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == ';'
		}) {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			// Validate before it reaches the unquoted geo{} block: a stray
			// '}' / '"' would otherwise close the block or inject directives.
			if _, _, err := net.ParseCIDR(s); err != nil && net.ParseIP(s) == nil {
				continue
			}
			cidrList = append(cidrList, s)
		}
		if len(cidrList) == 0 {
			continue
		}
		extras = append(extras, settings.TrustedLBExtra{
			ID:     id,
			CIDRs:  cidrList,
			Header: nginxconf.NginxVarFromHeader(h),
		})
	}
	n.TrustedLBExtra = extras
}

// applyIPGeoForm: persist mmdb paths.
//
// The UI exposes the country-DB path as a radio:
//   - mode=dbip   -> path is forced to ipgeo.DefaultMMDBPath; the custom
//     input is ignored.  The file might not exist yet (= user
//     clicks the dl button afterwards), so we skip the
//     Open-test in this mode.
//   - mode=custom -> path is whatever the user typed.  Open-test it so
//     invalid paths fail loudly at save time rather than
//     silently producing an empty country chart later.
//
// ASN DB stays a free input (= no radio); typical operator either has no
// ASN file or already knows where it lives.
func applyIPGeoForm(g *settings.IPGeo, r *http.Request, lang i18n.Lang) error {
	mode := strings.TrimSpace(r.FormValue("ipgeo_mode"))
	if mode == "" {
		mode = "dbip"
	}
	var geoPath string
	switch mode {
	case "dbip":
		geoPath = ipgeo.DefaultMMDBPath
		// Skip Open-test: the user may save before clicking dl.
	case "custom":
		geoPath = strings.TrimSpace(r.FormValue("ipgeo_mmdb_path"))
		if geoPath != "" {
			db, err := maxminddb.Open(geoPath)
			if err != nil {
				return fmt.Errorf("%s", i18n.Tf(lang, "err.geoip_invalid", geoPath, err.Error()))
			}
			_ = db.Close()
		}
	default:
		return fmt.Errorf("ipgeo_mode must be 'dbip' or 'custom' (got %q)", mode)
	}

	asnMode := strings.TrimSpace(r.FormValue("ipgeo_asn_mode"))
	if asnMode == "" {
		asnMode = "dbip"
	}
	var asnPath string
	switch asnMode {
	case "dbip":
		asnPath = ipgeo.DefaultASNPath
	case "custom":
		asnPath = strings.TrimSpace(r.FormValue("ipgeo_mmdb_asn_path"))
		if asnPath != "" {
			db, err := maxminddb.Open(asnPath)
			if err != nil {
				return fmt.Errorf("%s", i18n.Tf(lang, "err.geoip_invalid", asnPath, err.Error()))
			}
			_ = db.Close()
		}
	case "none":
		asnPath = ""
	default:
		return fmt.Errorf("ipgeo_asn_mode must be 'dbip', 'custom', or 'none' (got %q)", asnMode)
	}

	g.MMDBPath = geoPath
	g.MMDBASNPath = asnPath
	return nil
}

// applyUAFilterForm: save allowlist (= search bot UA) and blocklist
// (= challenge target UA) together from one form. Field names:
// white_presets / white_extra / black_presets / black_extra / black_all.
// Internally writes into the legacy SearchBots / ChallengeTargets structs
// (= preserves the YAML schema so no migration is needed).
func applyUAFilterForm(n *settings.Nginx, r *http.Request) {
	// ── allowlist (= operator-added extra UA patterns) ───
	// The built-in whitelist presets were removed; only the operator's own
	// extra rules persist here.  Upstream auto-rescue (below) is the managed
	// search/AI bypass path.
	n.SearchBots.Extra, n.SearchBots.ExtraTitle, n.SearchBots.ExtraDisabled, n.SearchBots.ExtraUpdatedAt = pairExtras(
		r.Form["white_extra"], r.Form["white_extra_title"], r.Form["white_extra_enabled"], r.Form["white_extra_updated_at"])

	// upstream auto-rescue per-pattern disable list (= modal popup form).
	// Dedup + strip empty so the YAML stays tidy.
	seen := map[string]bool{}
	upDisabled := []string{}
	for _, p := range r.Form["upstream_disabled"] {
		p = strings.TrimSpace(p)
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		upDisabled = append(upDisabled, p)
	}
	n.SearchBots.UpstreamDisabled = upDisabled

	// upstream group mode: each category is white / black / none.
	// Only store entries that differ from the built-in default (= keeps
	// the YAML tidy and lets future default changes propagate to silent
	// installs).
	overrides := map[string]string{}
	for cat, vals := range r.Form {
		if !strings.HasPrefix(cat, "upstream_group_mode__") {
			continue
		}
		key := strings.TrimPrefix(cat, "upstream_group_mode__")
		if key == "" || len(vals) == 0 {
			continue
		}
		v := strings.TrimSpace(vals[0])
		switch v {
		case classify.GroupModeWhite, classify.GroupModeBlack, classify.GroupModeNone:
		default:
			continue
		}
		if v == classify.DefaultGroupMode(key) {
			continue
		}
		overrides[key] = v
	}
	if len(overrides) == 0 {
		n.SearchBots.UpstreamGroupMode = nil
	} else {
		n.SearchBots.UpstreamGroupMode = overrides
	}

	// per-group challenge action override (= only meaningful for groups
	// resolved to black, so we keep entries even if the group is currently
	// white — the user may flip the mode later and expect the override to
	// be remembered).
	actOverrides := map[string]string{}
	for cat, vals := range r.Form {
		if !strings.HasPrefix(cat, "upstream_group_action__") {
			continue
		}
		key := strings.TrimPrefix(cat, "upstream_group_action__")
		if key == "" || len(vals) == 0 {
			continue
		}
		v := strings.TrimSpace(vals[0])
		if v == "" || v == "inherit" {
			continue
		}
		if !settings.IsValidRateChallengeMode(v) {
			continue
		}
		actOverrides[key] = v
	}
	if len(actOverrides) == 0 {
		n.SearchBots.UpstreamGroupAction = nil
	} else {
		n.SearchBots.UpstreamGroupAction = actOverrides
	}

	// ── blocklist (= legacy challenge-targets) ──────────
	n.ChallengeTargets.All = r.FormValue("black_all") != ""
	blackEnabled := map[string]bool{}
	for _, id := range r.Form["black_presets"] {
		blackEnabled[id] = true
	}
	blackDisabled := []string{}
	for _, g := range nginxconf.ChallengeTargetGroups {
		if !blackEnabled[g.ID] {
			blackDisabled = append(blackDisabled, g.ID)
		}
	}
	n.ChallengeTargets.DisabledPresets = blackDisabled
	// per-preset action override (= keys preset ID, value action string).
	presetActOverrides := map[string]string{}
	for k, vals := range r.Form {
		if !strings.HasPrefix(k, "black_preset_action__") {
			continue
		}
		id := strings.TrimPrefix(k, "black_preset_action__")
		if id == "" || len(vals) == 0 {
			continue
		}
		v := strings.TrimSpace(vals[0])
		if v == "" || v == "inherit" {
			continue
		}
		if !settings.IsValidRateChallengeMode(v) {
			continue
		}
		presetActOverrides[id] = v
	}
	if len(presetActOverrides) == 0 {
		n.ChallengeTargets.PresetAction = nil
	} else {
		n.ChallengeTargets.PresetAction = presetActOverrides
	}
	n.ChallengeTargets.Extra, n.ChallengeTargets.ExtraTitle, n.ChallengeTargets.ExtraDisabled, n.ChallengeTargets.ExtraUpdatedAt = pairExtras(
		r.Form["black_extra"], r.Form["black_extra_title"], r.Form["black_extra_enabled"], r.Form["black_extra_updated_at"])
}

// applyBypassIPsForm: receive the bypass-ips tab form. Zip the row-UI 4
// parallel arrays (ip + title + enabled + updated_at) into the BypassIPs*
// 4 slices for save.
func applyBypassIPsForm(n *settings.Nginx, r *http.Request, lang i18n.Lang) error {
	ips := r.Form["bypass_ip"]
	titles := r.Form["bypass_title"]
	enabled := r.Form["bypass_enabled"]
	upds := r.Form["bypass_updated_at"]
	maxLen := len(ips)
	for _, l := range []int{len(titles), len(enabled), len(upds)} {
		if l > maxLen {
			maxLen = l
		}
	}
	outIP := make([]string, 0, maxLen)
	outTitle := make([]string, 0, maxLen)
	outDisabled := make([]bool, 0, maxLen)
	outUpdated := make([]int64, 0, maxLen)
	now := time.Now().Unix()
	for i := 0; i < maxLen; i++ {
		var ip, t string
		isEnabled := true
		var ts int64
		if i < len(ips) {
			ip = strings.TrimSpace(ips[i])
		}
		if i < len(titles) {
			t = strings.TrimSpace(titles[i])
			t = strings.NewReplacer("\n", " ", "\r", " ", "\"", "'", "\\", "/").Replace(t)
		}
		if i < len(enabled) {
			isEnabled = enabled[i] == "1"
		}
		if i < len(upds) {
			ts, _ = strconv.ParseInt(strings.TrimSpace(upds[i]), 10, 64)
		}
		if ip == "" {
			continue
		}
		if !ipOrCIDRRE.MatchString(ip) {
			return fmt.Errorf("%s", i18n.Tf(lang, "err.bypass_invalid", ip))
		}
		if ts <= 0 {
			ts = now
		}
		outIP = append(outIP, ip)
		outTitle = append(outTitle, t)
		outDisabled = append(outDisabled, !isEnabled)
		outUpdated = append(outUpdated, ts)
	}
	n.BypassIPs = outIP
	n.BypassIPsTitle = outTitle
	n.BypassIPsDisabled = outDisabled
	n.BypassIPsUpdatedAt = outUpdated

	// Collect enabled preset groups.  The template sends checkbox values for
	// enabled groups as `bypass_preset_enabled[]=ID` (= same pattern as
	// bypass_paths / protected_paths).  Iterate over the canonical group order
	// rather than the raw form values so the saved list is stable + dedup'd
	// and unknown IDs from a forged form are silently dropped.
	enabledForm := map[string]bool{}
	for _, id := range r.Form["bypass_preset_enabled"] {
		enabledForm[strings.TrimSpace(id)] = true
	}
	enabledOut := []string{}
	for _, g := range nginxconf.BypassIPGroups {
		if enabledForm[g.ID] {
			enabledOut = append(enabledOut, g.ID)
		}
	}
	n.BypassIPEnabledPresets = enabledOut

	// stats_exclude_ips (+ _title): row UI, parallel arrays zipped by index --
	// IPs dropped entirely from statistics.  Rows are paired BEFORE blanks and
	// duplicates are skipped so a dropped row can never shift the titles
	// against the IPs; duplicates keep the first row's title (= formList's
	// first-wins dedup, which this replaces).
	stxIPs := r.Form["stats_exclude_ips"]
	stxTitles := r.Form["stats_exclude_ips_title"]
	stxSeen := map[string]bool{}
	outStx := make([]string, 0, len(stxIPs))
	outStxTitle := make([]string, 0, len(stxIPs))
	for i, raw := range stxIPs {
		ip := strings.TrimSpace(raw)
		if ip == "" || stxSeen[ip] {
			continue
		}
		if !ipOrCIDRRE.MatchString(ip) {
			return fmt.Errorf("%s", i18n.Tf(lang, "err.bypass_invalid", ip))
		}
		var t string
		if i < len(stxTitles) {
			t = strings.TrimSpace(stxTitles[i])
			t = strings.NewReplacer("\n", " ", "\r", " ", "\"", "'", "\\", "/").Replace(t)
		}
		stxSeen[ip] = true
		outStx = append(outStx, ip)
		outStxTitle = append(outStxTitle, t)
	}
	n.StatsExcludeIPs = outStx
	n.StatsExcludeIPsTitle = outStxTitle
	n.StatsExcludePrivateNetworks = r.FormValue("stats_exclude_private_networks") == "1"
	return nil
}

// applyHoneypotForm: receive the honeypot tab form (v2 = flat URLs slice).
//
//	honeypot_default_ban_duration_sec: TTL (seconds) for BANs from honeypot hits.
//	    Lives on Default; per-site overrides go through AdminHoneypotSiteSave.
//	honeypot_preset_enabled[]: list of preset-group IDs to enable (= checkbox).
//	honeypot_url_path / _title / _enabled / _updated_at / _site / _action:
//	    parallel arrays for the row UI -- zipped here into HoneypotURL slice.
func applyHoneypotForm(n *settings.Nginx, r *http.Request, lang i18n.Lang) error {
	// Default ban duration: numeric + range check.
	if raw := strings.TrimSpace(r.FormValue("honeypot_default_ban_duration_sec")); raw != "" {
		v, err := strconv.Atoi(raw)
		if err != nil || v < 0 || v > 2592000 {
			return fmt.Errorf("ban_duration_sec: invalid value %q (= 0..2592000)", raw)
		}
		n.Honeypot.BanDurationSec = v
	}

	// Collect disabled preset groups.
	enabledIDs := map[string]bool{}
	for _, id := range r.Form["honeypot_preset_enabled"] {
		enabledIDs[strings.TrimSpace(id)] = true
	}
	disabledOut := []string{}
	for _, g := range nginxconf.HoneypotPresetGroups {
		if !enabledIDs[g.ID] {
			disabledOut = append(disabledOut, g.ID)
		}
	}
	n.Honeypot.DisabledPresets = disabledOut

	// Row UI parallel arrays → zip into HoneypotURL slice.
	pats := r.Form["honeypot_url_path"]
	titles := r.Form["honeypot_url_title"]
	enabled := r.Form["honeypot_url_enabled"]
	upds := r.Form["honeypot_url_updated_at"]
	sites := r.Form["honeypot_url_site"]
	actions := r.Form["honeypot_url_action"]
	maxLen := len(pats)
	for _, l := range []int{len(titles), len(enabled), len(upds), len(sites), len(actions)} {
		if l > maxLen {
			maxLen = l
		}
	}
	urls := make([]settings.HoneypotURL, 0, maxLen)
	now := time.Now().Unix()
	for i := 0; i < maxLen; i++ {
		var p, t, site, action string
		isEnabled := true
		var ts int64
		if i < len(pats) {
			p = strings.TrimSpace(pats[i])
		}
		if i < len(titles) {
			t = strings.TrimSpace(titles[i])
			t = strings.NewReplacer("\n", " ", "\r", " ", "\"", "'", "\\", "/").Replace(t)
		}
		if i < len(enabled) {
			isEnabled = enabled[i] == "1"
		}
		if i < len(upds) {
			ts, _ = strconv.ParseInt(strings.TrimSpace(upds[i]), 10, 64)
		}
		if i < len(sites) {
			site = strings.TrimSpace(sites[i])
		}
		if i < len(actions) {
			v := strings.TrimSpace(actions[i])
			if v != "" && v != "inherit" && settings.IsValidRateChallengeMode(v) {
				action = v
			}
		}
		if p == "" {
			continue
		}
		if _, err := regexp.Compile(p); err != nil {
			return fmt.Errorf("%s", i18n.Tf(lang, "err.honeypot_regex", p, err))
		}
		if ts <= 0 {
			ts = now
		}
		urls = append(urls, settings.HoneypotURL{
			Path:      p,
			Title:     t,
			Action:    action,
			Disabled:  !isEnabled,
			UpdatedAt: ts,
			Site:      site,
		})
	}
	n.Honeypot.URLs = urls

	// honeypot default action (= chain for trips).
	if v := strings.TrimSpace(r.FormValue("honeypot_default_action")); v != "" {
		if settings.IsValidRateChallengeMode(v) {
			n.Honeypot.DefaultAction = v
		}
	}
	// Bans.ManualDefaultAction / CommunityBansDefaultAction are edited on the
	// bans page itself (= /admin/bans/, op=save-defaults).  Keeping them off
	// the honeypot save path means a honeypot save doesn't reset bans-page
	// inputs the operator may have just touched.
	// per-preset action override.
	presetActions := map[string]string{}
	for k, vals := range r.Form {
		if !strings.HasPrefix(k, "honeypot_preset_action__") {
			continue
		}
		id := strings.TrimPrefix(k, "honeypot_preset_action__")
		if id == "" || len(vals) == 0 {
			continue
		}
		v := strings.TrimSpace(vals[0])
		if v == "" || v == "inherit" || !settings.IsValidRateChallengeMode(v) {
			continue
		}
		presetActions[id] = v
	}
	if len(presetActions) == 0 {
		n.Honeypot.PresetAction = nil
	} else {
		n.Honeypot.PresetAction = presetActions
	}
	return nil
}

// pairExtras: zip the 4 parallel arrays from the row UI into
// (cleaned_patterns, titles, disabled, updatedAt).
//   - drop rows where pattern is empty
//   - drop rows where pattern contains control chars / quotes
//   - drop rows where pattern fails to compile as regex
//   - title is trimmed; control chars are replaced with spaces
//   - enabled = "1" → enabled; otherwise disabled
//   - updatedAt is unix sec. "0" / empty / invalid is filled with now
//     (= new row or when JS overwrites with 0 on "dirty" detection)
func pairExtras(patterns, titles, enabled, updatedAt []string) ([]string, []string, []bool, []int64) {
	maxLen := len(patterns)
	if len(titles) > maxLen {
		maxLen = len(titles)
	}
	if len(enabled) > maxLen {
		maxLen = len(enabled)
	}
	if len(updatedAt) > maxLen {
		maxLen = len(updatedAt)
	}
	outP := make([]string, 0, maxLen)
	outT := make([]string, 0, maxLen)
	outD := make([]bool, 0, maxLen)
	outU := make([]int64, 0, maxLen)
	now := time.Now().Unix()
	for i := 0; i < maxLen; i++ {
		var p, t string
		isEnabled := true
		var ts int64
		if i < len(patterns) {
			p = strings.TrimSpace(patterns[i])
		}
		if i < len(titles) {
			t = strings.TrimSpace(titles[i])
			t = strings.NewReplacer("\n", " ", "\r", " ", "\"", "'", "\\", "/").Replace(t)
		}
		if i < len(enabled) {
			isEnabled = enabled[i] == "1"
		}
		if i < len(updatedAt) {
			ts, _ = strconv.ParseInt(strings.TrimSpace(updatedAt[i]), 10, 64)
		}
		if p == "" {
			continue
		}
		if strings.ContainsAny(p, "\"\\\x00\r\n") {
			continue
		}
		if _, err := regexp.Compile(p); err != nil {
			continue
		}
		if ts <= 0 {
			ts = now
		}
		outP = append(outP, p)
		outT = append(outT, t)
		outD = append(outD, !isEnabled)
		outU = append(outU, ts)
	}
	return outP, outT, outD, outU
}

func applyJA4VerdictsForm(n *settings.Nginx, r *http.Request, lang i18n.Lang) error {
	enabled := map[string]bool{}
	for _, id := range r.Form["enabled_presets"] {
		enabled[id] = true
	}
	disabled := []string{}
	for _, g := range nginxconf.JA4VerdictGroups {
		if !enabled[g.ID] {
			disabled = append(disabled, g.ID)
		}
	}
	n.JA4Verdicts.DisabledPresets = disabled

	// 6 parallel arrays from the row UI (pattern + verdict + action + title + enabled + updated_at).
	// Zip rows at the same index into one entry.
	pats := r.Form["ja4_extra_pat"]
	verds := r.Form["ja4_extra_verd"]
	acts := r.Form["ja4_extra_action"]
	titles := r.Form["ja4_extra_title"]
	enabledArr := r.Form["ja4_extra_enabled"]
	upds := r.Form["ja4_extra_updated_at"]
	ids := r.Form["ja4_extra_id"] // hidden input for ID-based linking; existing entries keep their ID.
	maxLen := len(pats)
	for _, l := range []int{len(verds), len(acts), len(titles), len(enabledArr), len(upds), len(ids)} {
		if l > maxLen {
			maxLen = l
		}
	}
	extras := make([]settings.JA4VerdictExtraRule, 0, maxLen)
	outTitles := make([]string, 0, maxLen)
	outDisabled := make([]bool, 0, maxLen)
	outUpdated := make([]int64, 0, maxLen)
	now := time.Now().Unix()
	for i := 0; i < maxLen; i++ {
		var p, v, a, t string
		isEnabled := true
		var ts int64
		if i < len(pats) {
			p = strings.TrimSpace(pats[i])
		}
		if i < len(verds) {
			v = strings.TrimSpace(verds[i])
		}
		if i < len(acts) {
			a = strings.TrimSpace(acts[i])
		}
		if i < len(titles) {
			t = strings.TrimSpace(titles[i])
			t = strings.NewReplacer("\n", " ", "\r", " ", "\"", "'", "\\", "/").Replace(t)
		}
		if i < len(enabledArr) {
			isEnabled = enabledArr[i] == "1"
		}
		if i < len(upds) {
			ts, _ = strconv.ParseInt(strings.TrimSpace(upds[i]), 10, 64)
		}
		// Drop empty rows (pattern or verdict alone is invalid input)
		if p == "" && v == "" {
			continue
		}
		if p == "" {
			return fmt.Errorf("%s", i18n.Tf(lang, "err.verdict_2tokens", v))
		}
		if v == "" {
			return fmt.Errorf("%s", i18n.Tf(lang, "err.verdict_2tokens", p))
		}
		if strings.ContainsAny(p, "\"\\\x00\r\n") {
			continue
		}
		// The verdict is emitted into a quoted nginx map value, so it needs the
		// same character reject as the pattern or a '"' would break the quote.
		if strings.ContainsAny(v, "\"\\\x00\r\n") {
			continue
		}
		if _, err := regexp.Compile(p); err != nil {
			return fmt.Errorf("%s", i18n.Tf(lang, "err.verdict_regex", p, err))
		}
		if !nginxconf.IsValidJA4Action(a) {
			return fmt.Errorf("%s", i18n.Tf(lang, "err.verdict_action", v, a))
		}
		if ts <= 0 {
			ts = now
		}
		var id int
		if i < len(ids) {
			id, _ = strconv.Atoi(strings.TrimSpace(ids[i]))
		}
		extras = append(extras, settings.JA4VerdictExtraRule{ID: id, Pattern: p, Verdict: v, Action: a})
		outTitles = append(outTitles, t)
		outDisabled = append(outDisabled, !isEnabled)
		outUpdated = append(outUpdated, ts)
	}
	n.JA4Verdicts.Extra = extras
	n.JA4Verdicts.ExtraTitle = outTitles
	n.JA4Verdicts.ExtraDisabled = outDisabled
	n.JA4Verdicts.ExtraUpdatedAt = outUpdated

	// JA4 default action (= challenge chain when ja4 hits action=bot).
	if v := strings.TrimSpace(r.FormValue("ja4_default_action")); v != "" {
		if settings.IsValidRateChallengeMode(v) {
			n.JA4Verdicts.DefaultAction = v
		}
	}
	// JA4 per-preset action override.
	presetActions := map[string]string{}
	for k, vals := range r.Form {
		if !strings.HasPrefix(k, "ja4_preset_action__") {
			continue
		}
		id := strings.TrimPrefix(k, "ja4_preset_action__")
		if id == "" || len(vals) == 0 {
			continue
		}
		v := strings.TrimSpace(vals[0])
		if v == "" || v == "inherit" {
			continue
		}
		if !settings.IsValidRateChallengeMode(v) {
			continue
		}
		presetActions[id] = v
	}
	if len(presetActions) == 0 {
		n.JA4Verdicts.PresetAction = nil
	} else {
		n.JA4Verdicts.PresetAction = presetActions
	}
	// JA4 per-extra action override (parallel slice aligned with Extra).
	chains := r.Form["ja4_extra_action_chain"]
	outChains := make([]string, len(extras))
	for i := range outChains {
		if i < len(chains) {
			v := strings.TrimSpace(chains[i])
			if v == "" || v == "inherit" || !settings.IsValidRateChallengeMode(v) {
				outChains[i] = ""
			} else {
				outChains[i] = v
			}
		}
	}
	// Compact: drop a trailing run of empties so the YAML stays small.
	for len(outChains) > 0 && outChains[len(outChains)-1] == "" {
		outChains = outChains[:len(outChains)-1]
	}
	if len(outChains) == 0 {
		n.JA4Verdicts.ExtraAction = nil
	} else {
		n.JA4Verdicts.ExtraAction = outChains
	}

	// Assign IDs to new entries (= ID=0). Preserve IDs of existing entries.
	tmp := settings.Settings{Nginx: *n}
	settings.BackfillExtraVerdictIDs(&tmp)
	n.JA4Verdicts.Extra = tmp.Nginx.JA4Verdicts.Extra
	return nil
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// formList sanitizes the per-row values of a structured list field (= the
// value-rule-list UI that replaced the newline textareas): trim, drop empty,
// dedup, and reject control chars / quotes (an nginx-config-injection guard).
// Order is preserved.
func formList(vals []string) []string {
	out := make([]string, 0, len(vals))
	seen := map[string]bool{}
	for _, v := range vals {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			continue
		}
		if strings.ContainsAny(v, "\"\\\x00\r\n") {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

func toSet(xs []string) map[string]bool {
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}

// applyProtectedForm: receive the protected-paths tab form. Zip 4 parallel
// arrays (= path / title / disabled / updated_at) and save them. The old
// `mode` column (= captcha/pow/strict) was retired in favor of the
// per-axis chain action (= pow_only / pow_then_captcha / captcha_only /
// deny) wired through protected_default_action + protected_extra_action;
// applyProtectedForm receives the protected-paths tab form (v2 = flat
// ProtectedPath slice).  Form fields: protected_path / _title / _enabled /
// _updated_at / _mode / _site / _action -- zipped into ProtectedPath.
func applyProtectedForm(n *settings.Nginx, r *http.Request, lang i18n.Lang) error {
	pats := r.Form["protected_path"]
	titles := r.Form["protected_title"]
	enabledArr := r.Form["protected_enabled"]
	upds := r.Form["protected_updated_at"]
	modes := r.Form["protected_mode"]
	sites := r.Form["protected_site"]
	actions := r.Form["protected_action"]
	maxLen := len(pats)
	for _, l := range []int{len(titles), len(enabledArr), len(upds), len(modes), len(sites), len(actions)} {
		if l > maxLen {
			maxLen = l
		}
	}
	rows := make([]settings.ProtectedPath, 0, maxLen)
	now := time.Now().Unix()
	for i := 0; i < maxLen; i++ {
		var p, t, mode, site, action string
		isEnabled := true
		var ts int64
		if i < len(pats) {
			p = strings.TrimSpace(pats[i])
		}
		if i < len(titles) {
			t = strings.TrimSpace(titles[i])
			t = strings.NewReplacer("\n", " ", "\r", " ", "\"", "'", "\\", "/").Replace(t)
		}
		if i < len(enabledArr) {
			isEnabled = enabledArr[i] == "1"
		}
		if i < len(upds) {
			ts, _ = strconv.ParseInt(strings.TrimSpace(upds[i]), 10, 64)
		}
		if i < len(modes) {
			mode = strings.TrimSpace(modes[i])
		}
		if !nginxconf.IsValidProtectedMode(mode) {
			mode = nginxconf.ProtectedModeCaptcha
		}
		if i < len(sites) {
			site = strings.TrimSpace(sites[i])
		}
		if i < len(actions) {
			v := strings.TrimSpace(actions[i])
			if v != "" && v != "inherit" && settings.IsValidRateChallengeMode(v) {
				action = v
			}
		}
		if p == "" {
			continue
		}
		if _, err := regexp.Compile(p); err != nil {
			return fmt.Errorf("%s", i18n.Tf(lang, "err.protected_regex", p, err))
		}
		if ts <= 0 {
			ts = now
		}
		rows = append(rows, settings.ProtectedPath{
			Path:      p,
			Title:     t,
			Mode:      mode,
			Action:    action,
			Disabled:  !isEnabled,
			UpdatedAt: ts,
			Site:      site,
		})
	}
	n.ProtectedPaths.Paths = rows

	// Receive presets: "protected_preset_enabled" carries the list of checked
	// IDs and is written directly to EnabledPresets.  Unknown IDs (= form
	// tampering) are dropped silently.
	known := map[string]bool{}
	for _, g := range nginxconf.ProtectedPathPresetGroups {
		known[g.ID] = true
	}
	enabled := []string{}
	for _, id := range r.Form["protected_preset_enabled"] {
		id = strings.TrimSpace(id)
		if known[id] {
			enabled = append(enabled, id)
		}
	}
	n.ProtectedPaths.EnabledPresets = enabled

	// Protected default action.
	if v := strings.TrimSpace(r.FormValue("protected_default_action")); v != "" {
		if settings.IsValidRateChallengeMode(v) {
			n.ProtectedPaths.DefaultAction = v
		}
	}
	// per-preset action override.
	presetActions := map[string]string{}
	for k, vals := range r.Form {
		if !strings.HasPrefix(k, "protected_preset_action__") {
			continue
		}
		id := strings.TrimPrefix(k, "protected_preset_action__")
		if id == "" || len(vals) == 0 {
			continue
		}
		v := strings.TrimSpace(vals[0])
		if v == "" || v == "inherit" || !settings.IsValidRateChallengeMode(v) {
			continue
		}
		presetActions[id] = v
	}
	if len(presetActions) == 0 {
		n.ProtectedPaths.PresetAction = nil
	} else {
		n.ProtectedPaths.PresetAction = presetActions
	}
	return nil
}

// protectedExtraRule: row-UI struct for the protected-paths tab.
type protectedExtraRule struct {
	Pattern   string
	Title     string
	Mode      string
	Action    string
	Site      string
	Enabled   bool
	UpdatedAt int64
}

// padToLen pads (or truncates) `s` to exactly `n` entries, filling missing
// slots with the empty string.  Used to keep per-row override slices aligned
// with the canonical row count for template rendering — the save handlers
// trim trailing-empty overrides to keep yaml compact, which would otherwise
// cause `index <slice> $i` to panic when the override is shorter than the
// canonical list.
func padToLen(s []string, n int) []string {
	if len(s) == n {
		return s
	}
	out := make([]string, n)
	for i := 0; i < n && i < len(s); i++ {
		out[i] = s[i]
	}
	return out
}

// protectedPathRows: surface ProtectedPath rows in the template's row-UI
// shape.  Mode defaults to "captcha" so a freshly-added row renders with a
// pre-selected dropdown.
func protectedPathRows(rows []settings.ProtectedPath) []protectedExtraRule {
	out := make([]protectedExtraRule, len(rows))
	for i, r := range rows {
		mode := r.Mode
		if !nginxconf.IsValidProtectedMode(mode) {
			mode = nginxconf.ProtectedModeCaptcha
		}
		out[i] = protectedExtraRule{
			Pattern:   r.Path,
			Title:     r.Title,
			Mode:      mode,
			Action:    r.Action,
			Site:      r.Site,
			Enabled:   !r.Disabled,
			UpdatedAt: r.UpdatedAt,
		}
	}
	return out
}

// bypassPathRows: surface BypassPath rows in the row-UI shape used by the
// settings template (= booleans the template can branch on directly).
func bypassPathRows(rows []settings.BypassPath) []bypassPathRule {
	out := make([]bypassPathRule, len(rows))
	for i, r := range rows {
		out[i] = bypassPathRule{
			Pattern:   r.Path,
			Title:     r.Title,
			Site:      r.Site,
			Enabled:   !r.Disabled,
			UpdatedAt: r.UpdatedAt,
		}
	}
	return out
}

// honeypotURLRow: row-UI struct surfaced to the settings template.  Mirrors
// settings.HoneypotURL but flips Disabled into Enabled so the templates can
// keep using `if .Enabled`.
type honeypotURLRow struct {
	Pattern   string
	Title     string
	Action    string
	Site      string
	Enabled   bool
	UpdatedAt int64
}

// honeypotURLRows: turn the persisted HoneypotURL slice into the row-UI
// shape for rendering.
func honeypotURLRows(rows []settings.HoneypotURL) []honeypotURLRow {
	out := make([]honeypotURLRow, len(rows))
	for i, r := range rows {
		out[i] = honeypotURLRow{
			Pattern:   r.Path,
			Title:     r.Title,
			Action:    r.Action,
			Site:      r.Site,
			Enabled:   !r.Disabled,
			UpdatedAt: r.UpdatedAt,
		}
	}
	return out
}

// applyBypassPathsForm: receive the bypass-paths tab form (v2 = flat
// BypassPath slice).  Form fields: bp_path / _title / _enabled /
// _updated_at / _site -- zipped into BypassPath.
func applyBypassPathsForm(n *settings.Nginx, r *http.Request, lang i18n.Lang) error {
	// Preset checkboxes: store only DEVIATIONS from each preset's DefaultOn —
	// checked-but-default-OFF lands in EnabledPresets, unchecked-but-default-ON
	// in DisabledPresets, a match with the default stores nothing.  That way a
	// preset added in a later version follows its own code-declared default on
	// this install too.  A NEW preset (added after this operator's last save)
	// is absent from the form (its checkbox renders disabled), so its recorded
	// deviations — normally none — are carried over untouched rather than
	// misread as "explicitly turned off".  Unknown IDs (= form tampering) drop
	// silently since only known groups are consulted.
	checked := map[string]bool{}
	for _, id := range r.Form["bypass_path_preset_enabled"] {
		checked[strings.TrimSpace(id)] = true
	}
	prevEnabled := toSet(n.BypassPaths.EnabledPresets)
	prevDisabled := toSet(n.BypassPaths.DisabledPresets)
	enabled, disabled := []string{}, []string{}
	for _, g := range nginxconf.BypassPathPresetGroups {
		if nginxconf.PresetIsNew(n.SeenVersion, g.AddedIn) {
			if prevEnabled[g.ID] {
				enabled = append(enabled, g.ID)
			}
			if prevDisabled[g.ID] {
				disabled = append(disabled, g.ID)
			}
			continue
		}
		switch on := checked[g.ID]; {
		case on && !g.DefaultOn:
			enabled = append(enabled, g.ID)
		case !on && g.DefaultOn:
			disabled = append(disabled, g.ID)
		}
	}
	n.BypassPaths.EnabledPresets = enabled
	n.BypassPaths.DisabledPresets = disabled

	pats := r.Form["bp_path"]
	titles := r.Form["bp_title"]
	rowEnabled := r.Form["bp_enabled"]
	upds := r.Form["bp_updated_at"]
	sites := r.Form["bp_site"]
	maxLen := len(pats)
	for _, l := range []int{len(titles), len(rowEnabled), len(upds), len(sites)} {
		if l > maxLen {
			maxLen = l
		}
	}
	rows := make([]settings.BypassPath, 0, maxLen)
	now := time.Now().Unix()
	for i := 0; i < maxLen; i++ {
		var p, t, site string
		isEnabled := true
		var ts int64
		if i < len(pats) {
			p = strings.TrimSpace(pats[i])
		}
		if i < len(titles) {
			t = strings.TrimSpace(titles[i])
			t = strings.NewReplacer("\n", " ", "\r", " ", "\"", "'", "\\", "/").Replace(t)
		}
		if i < len(rowEnabled) {
			isEnabled = rowEnabled[i] == "1"
		}
		if i < len(upds) {
			ts, _ = strconv.ParseInt(strings.TrimSpace(upds[i]), 10, 64)
		}
		if i < len(sites) {
			site = strings.TrimSpace(sites[i])
		}
		if p == "" {
			continue
		}
		if _, err := regexp.Compile(p); err != nil {
			return fmt.Errorf("%s", i18n.Tf(lang, "err.bypass_path_regex", p, err))
		}
		if ts <= 0 {
			ts = now
		}
		rows = append(rows, settings.BypassPath{
			Path:      p,
			Title:     t,
			Disabled:  !isEnabled,
			UpdatedAt: ts,
			Site:      site,
		})
	}
	n.BypassPaths.Paths = rows
	return nil
}

// applyRedirectExemptForm parses the HTTPS-redirect exemption UI: preset
// checkboxes (redirect_exempt_preset_enabled) + custom rows (re_type / re_pattern
// / re_title / re_enabled).  Same deviation model as bypass paths, minus the
// SeenVersion gate (exemptions have no AddedIn — a missing exemption is the
// unsafe state, so a default-on preset always applies).
func applyRedirectExemptForm(n *settings.Nginx, r *http.Request, lang i18n.Lang) error {
	checked := map[string]bool{}
	for _, id := range r.Form["redirect_exempt_preset_enabled"] {
		checked[strings.TrimSpace(id)] = true
	}
	enabled, disabled := []string{}, []string{}
	for _, g := range nginxconf.RedirectExemptPresetGroups {
		switch on := checked[g.ID]; {
		case on && !g.DefaultOn:
			enabled = append(enabled, g.ID)
		case !on && g.DefaultOn:
			disabled = append(disabled, g.ID)
		}
	}
	n.HTTPSRedirectExempt.EnabledPresets = enabled
	n.HTTPSRedirectExempt.DisabledPresets = disabled

	types := r.Form["re_type"]
	pats := r.Form["re_pattern"]
	titles := r.Form["re_title"]
	rowEnabled := r.Form["re_enabled"]
	upds := r.Form["re_updated_at"]
	maxLen := len(pats)
	for _, l := range []int{len(types), len(titles), len(rowEnabled), len(upds)} {
		if l > maxLen {
			maxLen = l
		}
	}
	rows := make([]settings.HTTPSRedirectExemptRule, 0, maxLen)
	now := time.Now().Unix()
	for i := 0; i < maxLen; i++ {
		var typ, p, t string
		isEnabled := true
		var ts int64
		if i < len(types) {
			typ = strings.TrimSpace(types[i])
		}
		if typ != nginxconf.RedirectExemptMatchUA {
			typ = nginxconf.RedirectExemptMatchPath
		}
		if i < len(pats) {
			p = strings.TrimSpace(pats[i])
		}
		if i < len(titles) {
			t = strings.NewReplacer("\n", " ", "\r", " ", "\"", "'", "\\", "/").Replace(strings.TrimSpace(titles[i]))
		}
		if i < len(rowEnabled) {
			isEnabled = rowEnabled[i] == "1"
		}
		if i < len(upds) {
			ts, _ = strconv.ParseInt(strings.TrimSpace(upds[i]), 10, 64)
		}
		if p == "" {
			continue
		}
		if _, err := regexp.Compile(p); err != nil {
			return fmt.Errorf("%s", i18n.Tf(lang, "err.redirect_exempt_regex", p, err))
		}
		if ts <= 0 {
			ts = now
		}
		rows = append(rows, settings.HTTPSRedirectExemptRule{
			Type:      typ,
			Pattern:   p,
			Title:     t,
			Disabled:  !isEnabled,
			UpdatedAt: ts,
		})
	}
	n.HTTPSRedirectExempt.Rules = rows
	return nil
}

// bypassPathRule: row-UI struct surfaced to the template renderer.  Mirrors
// the underlying settings.BypassPath but uses booleans the template can
// branch on directly.
type bypassPathRule struct {
	Pattern   string
	Title     string
	Site      string
	Enabled   bool
	UpdatedAt int64
}

// applyCaptchaForm: receive the captcha tab form. Reads the provider radio +
// per-provider site_key / secret_key + recaptcha min_score. An empty secret_key
// submit preserves the current value (= matches the "***" placeholder UX
// where the value is not edited).
// parseChallengeCustomColors reads the per-theme color override inputs from the
// theme-tab form.  Each recolorable theme contributes a "customize" checkbox
// (custom_on_<theme>) plus a bg + text color (custom_bg_<theme> /
// custom_text_<theme>); an entry is kept only when the box is ticked AND both
// colors validate as hex, so a half-set or unchecked theme leaves no override
// (= the built-in palette).  "auto" has no inputs (it composes default + dark).
// Returns nil when nothing is overridden so the config stays clean.
func parseChallengeCustomColors(r *http.Request) map[string]settings.ChallengeThemeColors {
	out := map[string]settings.ChallengeThemeColors{}
	for _, name := range []string{"light", "dark", "terminal", "paper", "cat"} {
		if r.FormValue("custom_on_"+name) != "1" {
			continue
		}
		bg := strings.TrimSpace(r.FormValue("custom_bg_" + name))
		text := strings.TrimSpace(r.FormValue("custom_text_" + name))
		if settings.IsValidHexColor(bg) && settings.IsValidHexColor(text) {
			out[name] = settings.ChallengeThemeColors{Bg: bg, Text: text}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func applyCaptchaForm(c *settings.Captcha, r *http.Request) error {
	provider := strings.TrimSpace(r.FormValue("provider"))
	switch provider {
	case "", "builtin", "turnstile", "hcaptcha", "recaptcha":
		// ok
	default:
		return fmt.Errorf("invalid provider: %s", provider)
	}
	if provider == "" {
		provider = "builtin"
	}
	c.Provider = provider

	// site_key is a public value exposed in HTML. Empty submit overwrites (= allow "delete").
	c.TurnstileSiteKey = strings.TrimSpace(r.FormValue("turnstile_site_key"))
	c.HCaptchaSiteKey = strings.TrimSpace(r.FormValue("hcaptcha_site_key"))
	c.RecaptchaSiteKey = strings.TrimSpace(r.FormValue("recaptcha_site_key"))

	// secret_key: empty submit preserves the value (= express "do not change"
	// via the form). Explicit clear would need a dedicated button
	// (= omitted now; add if/when needed).
	if v := strings.TrimSpace(r.FormValue("turnstile_secret_key")); v != "" {
		c.TurnstileSecretKey = v
	}
	if v := strings.TrimSpace(r.FormValue("hcaptcha_secret_key")); v != "" {
		c.HCaptchaSecretKey = v
	}
	if v := strings.TrimSpace(r.FormValue("recaptcha_secret_key")); v != "" {
		c.RecaptchaSecretKey = v
	}

	// reCAPTCHA v3 min_score (0.0..1.0). Empty / invalid falls back to 0.5.
	if v := strings.TrimSpace(r.FormValue("recaptcha_min_score")); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil && f >= 0 && f <= 1 {
			c.RecaptchaMinScore = f
		}
	}
	if c.RecaptchaMinScore <= 0 {
		c.RecaptchaMinScore = 0.5
	}

	// Builtin behavioral CAPTCHA threshold (0.0..1.0). Only consulted when
	// Provider == "builtin"; harmless to store otherwise.  Empty submit
	// preserves the current value; explicit invalid input falls back to 0.5.
	if v := strings.TrimSpace(r.FormValue("builtin_score_threshold")); v != "" {
		f, err := strconv.ParseFloat(v, 64)
		if err != nil || f < 0 || f > 1 {
			return fmt.Errorf("builtin_score_threshold must be a float in 0.0-1.0 (got %q)", v)
		}
		c.BuiltinScoreThreshold = f
	}
	if c.BuiltinScoreThreshold <= 0 {
		c.BuiltinScoreThreshold = 0.5
	}
	return nil
}

// applyChallengeForm: receive the challenge tab form. Configures the _bv
// cookie TTL issued after PoW/CAPTCHA passes + behavioral CAPTCHA score
// threshold + DB events insertion rate-limit.
//
//	pow_cookie_valid_seconds      : 60..31_536_000 (= 1 minute .. 1 year). server-side check window for
//	                                _bv issued via the PoW path.  HMAC payload now carries an
//	                                exact unix-second issuance timestamp, so any value in this
//	                                range is honored at second precision.
//	captcha_cookie_valid_seconds  : same range for the CAPTCHA path.
//	debug_rate_limit_per_5min     : 1-10000 (= rate limit for inserting challenge debug
//	                                           payloads from the same IP into unmask_event.
//	                                           default 20).
//
// The behavioral CAPTCHA pass threshold has moved to the captcha tab
// (= applyCaptchaForm / builtin_score_threshold) since it only applies to
// the builtin provider -- third-party providers use their own siteverify.
//
// Operates on a *settings.ChallengeValues record (= one Default or one site
// entry).  applyChallengeFormV2 wraps this so a single form submit updates
// the Default record and adds / edits the per-site cards in one pass.
func applyChallengeForm(c *settings.ChallengeValues, r *http.Request) error {
	if v := strings.TrimSpace(r.FormValue("pow_cookie_valid_seconds")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 60 || n > 31_536_000 {
			return fmt.Errorf("pow_cookie_valid_seconds must be an integer in 60-31536000 (= 1 minute .. 1 year, got %q)", v)
		}
		c.PowCookieValidSeconds = n
	}
	if v := strings.TrimSpace(r.FormValue("captcha_cookie_valid_seconds")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 60 || n > 31_536_000 {
			return fmt.Errorf("captcha_cookie_valid_seconds must be an integer in 60-31536000 (= 1 minute .. 1 year, got %q)", v)
		}
		c.CaptchaCookieValidSeconds = n
	}
	if v := strings.TrimSpace(r.FormValue("pow_difficulty")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 8 || n > 24 {
			return fmt.Errorf("pow_difficulty must be an integer in 8-24 (got %q)", v)
		}
		c.PowDifficulty = n
	}
	if v := strings.TrimSpace(r.FormValue("debug_rate_limit_per_5min")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 10000 {
			return fmt.Errorf("debug_rate_limit_per_5min must be an integer in 1-10000 (got %q)", v)
		}
		c.DebugRateLimitPer5Min = n
	}
	// public_test_pages: HTML checkboxes don't send anything when unchecked,
	// so we use the adjacent hidden marker `public_test_pages_present` to
	// detect "came from form" and persist true/false accordingly.
	// If the marker is missing, we do not touch the value.
	if r.FormValue("public_test_pages_present") != "" {
		c.PublicTestPages = r.FormValue("public_test_pages") == "1"
		// Optional Basic Auth password.  Only honored when PublicTestPages
		// is on, but persist the value regardless so toggling the checkbox
		// back on doesn't silently lose what the operator typed.
		c.PublicTestPagesPassword = strings.TrimSpace(r.FormValue("public_test_pages_password"))
	}
	// show_credit: also belongs to the challenge tab; handle it here.
	c.ShowCredit = r.FormValue("show_credit") == "1"
	return nil
}

// applyRateLimitForm: receive the rate-limit tab form. Only the default zone
// is editable here (= named zones are edited directly in yaml; UI for them
// is planned for v0.2).
func applyRateLimitForm(c *settings.RateLimitConfig, r *http.Request) error {
	if v := strings.TrimSpace(r.FormValue("rate_limit_key")); v != "" {
		if !settings.IsValidRateLimitKey(v) {
			return fmt.Errorf("rate_limit_key must be one of ip / ja4 / ip+ja4 (got %q)", v)
		}
		c.Key = v
	}
	if v := strings.TrimSpace(r.FormValue("default_requests_per_min")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 100000 {
			return fmt.Errorf("requests_per_min must be an integer in 1-100000 (got %q)", v)
		}
		c.Default.RequestsPerMin = n
	}
	if v := strings.TrimSpace(r.FormValue("default_burst")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 || n > 100000 {
			return fmt.Errorf("burst must be an integer in 0-100000 (got %q)", v)
		}
		c.Default.Burst = n
	}
	if v := strings.TrimSpace(r.FormValue("default_window_sec")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 3600 {
			return fmt.Errorf("window_sec must be an integer in 1-3600 (got %q)", v)
		}
		c.Default.WindowSec = n
	}
	if v := strings.TrimSpace(r.FormValue("default_challenge_mode")); v != "" {
		if !settings.IsValidRateChallengeMode(v) {
			return fmt.Errorf("challenge_mode must be one of captcha_only / pow_only / pow_then_captcha (got %q)", v)
		}
		c.Default.ChallengeMode = v
	}
	// Default.Name is fixed (= "unmask_rate"). Not editable in the UI.
	if c.Default.Name == "" {
		c.Default.Name = "unmask_rate"
	}

	// zones[]: zone_<i>_name / zone_<i>_paths (newline-sep) / zone_<i>_rpm /
	// Read zone_<i>_burst / zone_<i>_window / zone_<i>_chmode in order.
	// After delete, JS keeps indices contiguous, so loop 0..N-1. Skip empty name.
	const maxZones = 100
	zones := make([]settings.RateZone, 0, maxZones)
	zoneNamesSeen := map[string]bool{}
	for i := 0; i < maxZones; i++ {
		prefix := fmt.Sprintf("zone_%d_", i)
		name := strings.TrimSpace(r.FormValue(prefix + "name"))
		if name == "" {
			// JS guarantees contiguous indices (= no gaps arrive).
			// Scan up to the max anyway, but break on a run of absences for efficiency.
			if r.FormValue(prefix+"rpm") == "" && r.FormValue(prefix+"paths") == "" {
				break
			}
			continue
		}
		if zoneNamesSeen[name] {
			return fmt.Errorf("zone name %q is duplicated", name)
		}
		zoneNamesSeen[name] = true
		if name == c.Default.Name {
			return fmt.Errorf("zone name %q collides with the default zone", name)
		}
		// validation: alnum + "_" only.
		if !rateZoneNameRE.MatchString(name) {
			return fmt.Errorf("zone name %q: alnum and '_' only (= nginx limit_req_zone name syntax)", name)
		}
		rpm, err := strconv.Atoi(strings.TrimSpace(r.FormValue(prefix + "rpm")))
		if err != nil || rpm < 1 || rpm > 100000 {
			return fmt.Errorf("zone %s: requests_per_min must be in 1-100000 (got %q)", name, r.FormValue(prefix+"rpm"))
		}
		burst, err := strconv.Atoi(strings.TrimSpace(r.FormValue(prefix + "burst")))
		if err != nil || burst < 0 || burst > 100000 {
			return fmt.Errorf("zone %s: burst must be in 0-100000 (got %q)", name, r.FormValue(prefix+"burst"))
		}
		window, err := strconv.Atoi(strings.TrimSpace(r.FormValue(prefix + "window")))
		if err != nil || window < 1 || window > 3600 {
			window = 60 // default fallback
		}
		chmode := strings.TrimSpace(r.FormValue(prefix + "chmode"))
		if chmode != "" && !settings.IsValidRateChallengeMode(chmode) {
			return fmt.Errorf("zone %s: challenge_mode invalid (got %q)", name, chmode)
		}
		// paths: textarea newline-separated → list. Skip empty / duplicate lines.
		paths := []string{}
		seen := map[string]bool{}
		for _, line := range strings.Split(r.FormValue(prefix+"paths"), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || seen[line] {
				continue
			}
			// The path lands unquoted in `location ^~ <path> {`, so a space / {
			// / } / ; would break out into an arbitrary location or directive.
			if strings.ContainsAny(line, " \t{}#;\"\\\r\x00") {
				return fmt.Errorf("zone %s: path %q contains invalid characters", name, line)
			}
			seen[line] = true
			paths = append(paths, line)
		}
		// site: optional per-row Host filter (= multi-site v2 step b).
		// Empty value -> zone applies to every vhost.  No normalisation is
		// required here -- the resolver compares against the same form-of-host
		// that was written through the picker / datalist, and the site list
		// supplied to .Sites already comes from the canonical observed pool.
		site := strings.TrimSpace(r.FormValue(prefix + "site"))
		zones = append(zones, settings.RateZone{
			Name:           name,
			RequestsPerMin: rpm,
			Burst:          burst,
			WindowSec:      window,
			PathPatterns:   paths,
			ChallengeMode:  chmode,
			Site:           site,
		})
	}
	c.Zones = zones
	return nil
}

// Deny-page design parsers (theme / wording tone / per-theme colors), used by
// applyBrandingForm since the deny design now rides on the per-site appearance
// record (BrandingValues).  rate (deny_*) and ban (ban_*) are parsed separately.

// parseDenyThemeField: "" / "auto" -> empty (follows the visitor OS); light/dark.
func parseDenyThemeField(r *http.Request, field string, dst *string) error {
	if v := strings.TrimSpace(r.FormValue(field)); v == "" || v == settings.DenyThemeAuto {
		*dst = ""
	} else if settings.IsValidDenyTheme(v) {
		*dst = v
	} else {
		return fmt.Errorf("%s must be one of auto / light / dark (got %q)", field, v)
	}
	return nil
}

// parseDenyPresetField: "" / "inherit" -> empty (follow the branding preset).
func parseDenyPresetField(r *http.Request, field string, dst *string) error {
	if v := strings.TrimSpace(r.FormValue(field)); v == "" || v == "inherit" {
		*dst = ""
	} else if settings.IsValidBrandingPreset(v) {
		*dst = v
	} else {
		return fmt.Errorf("%s must be inherit / friendly / neutral / minimal (got %q)", field, v)
	}
	return nil
}

// parseDenyColorsField: per-theme bg/text overrides under <prefix>_custom_*.  An
// entry is kept only when its toggle is on AND both colors validate as hex;
// otherwise the built-in deny palette stands.  nil when nothing is set.
func parseDenyColorsField(r *http.Request, prefix string) map[string]settings.ChallengeThemeColors {
	dcols := map[string]settings.ChallengeThemeColors{}
	for _, name := range []string{"light", "dark"} {
		if r.FormValue(prefix+"_custom_on_"+name) != "1" {
			continue
		}
		bg := strings.TrimSpace(r.FormValue(prefix + "_custom_bg_" + name))
		text := strings.TrimSpace(r.FormValue(prefix + "_custom_text_" + name))
		if settings.IsValidHexColor(bg) && settings.IsValidHexColor(text) {
			dcols[name] = settings.ChallengeThemeColors{Bg: bg, Text: text}
		}
	}
	if len(dcols) == 0 {
		return nil
	}
	return dcols
}

// rateZoneNameRE: nginx `limit_req_zone` name syntax (= alnum + underscore, 1..32 chars).
var rateZoneNameRE = regexp.MustCompile(`^[a-zA-Z0-9_]{1,32}$`)

// applyGeoForm: per-country rule axis (= settings.Nginx.Geo).
//
// Form fields:
//
//	geo_default_action : "" / "skip" / "pow_only" / "captcha_only" /
//	                       "pow_then_captcha" / "deny"  (= unmatched countries)
//	geo_country[]      : parallel array of ISO codes
//	geo_action[]       : parallel action per row (empty = inherit default)
//	geo_enabled_<i>    : per-row "1" when ticked (= rule active)
//	geo_updated_at[]   : preserved timestamp per row
//
// Rows are zipped by position.  Trailing empty Country slots are dropped.
// Duplicate Country codes return an error so the LookupRule linear scan
// doesn't silently pick the wrong row.
func applyGeoForm(c *settings.GeoConfig, r *http.Request) error {
	if v := strings.TrimSpace(r.FormValue("geo_default_action")); v != "" {
		if !settings.IsValidGeoAction(v) {
			return fmt.Errorf("geo_default_action invalid (got %q)", v)
		}
		c.DefaultAction = v
	} else {
		c.DefaultAction = ""
	}

	countries := r.Form["geo_country"]
	actions := r.Form["geo_action"]
	enabledArr := r.Form["geo_enabled"]
	updatedAt := r.Form["geo_updated_at"]

	rules := make([]settings.GeoRule, 0, len(countries))
	seen := map[string]bool{}
	now := time.Now().Unix()
	for i, raw := range countries {
		code := strings.ToUpper(strings.TrimSpace(raw))
		if code == "" {
			continue
		}
		if len(code) != 2 {
			return fmt.Errorf("country code %q: must be ISO 3166-1 alpha-2 (2 letters)", code)
		}
		if !ipgeo.IsValidCountry(code) {
			return fmt.Errorf("unknown country code %q", code)
		}
		if seen[code] {
			return fmt.Errorf("duplicate country code %q", code)
		}
		seen[code] = true

		var action string
		if i < len(actions) {
			action = strings.TrimSpace(actions[i])
		}
		if action != "" && !settings.IsValidGeoAction(action) {
			return fmt.Errorf("country %s: action invalid (got %q)", code, action)
		}

		enVal := r.FormValue(fmt.Sprintf("geo_enabled_%d", i))
		if enVal == "" && i < len(enabledArr) {
			enVal = enabledArr[i]
		}
		enOn := enVal == "1"

		var ts int64
		if i < len(updatedAt) {
			if n, err := strconv.ParseInt(strings.TrimSpace(updatedAt[i]), 10, 64); err == nil {
				ts = n
			}
		}
		if ts == 0 {
			ts = now
		}

		rules = append(rules, settings.GeoRule{
			Country:   code,
			Action:    action,
			Enabled:   enOn,
			UpdatedAt: ts,
		})
	}
	c.Rules = rules
	return nil
}

// applyNotificationsForm: receive the webhook notifications tab form.
func applyNotificationsForm(c *settings.Notifications, r *http.Request) {
	c.Disabled = r.FormValue("disabled") == "1"
	c.URL = strings.TrimSpace(r.FormValue("url"))
	format := strings.TrimSpace(r.FormValue("format"))
	switch format {
	case "slack", "discord", "generic":
		c.Format = format
	default:
		c.Format = "slack"
	}
	c.SiteLabel = strings.TrimSpace(r.FormValue("site_label"))
	c.BanEvents = r.FormValue("ban_events") == "1"
	c.ChallengeBurst = r.FormValue("challenge_burst") == "1"
	if v, err := strconv.Atoi(strings.TrimSpace(r.FormValue("burst_threshold_per_5m"))); err == nil && v >= 0 {
		c.BurstThresholdPer5m = v
	}
}

// AdminNotifyTest: POST {base}/admin/api/notify/test — send a test event.
//
// Settings need not be persisted to disk (= we want to try in-flight values
// immediately). Pass url / format from the form directly to a one-shot
// notifier and POST once.
func (h *Handler) AdminNotifyTest(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": 0, "error": "bad_form"})
		return
	}
	url := strings.TrimSpace(r.FormValue("url"))
	if url == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": 0, "error": "url_empty"})
		return
	}
	format := strings.TrimSpace(r.FormValue("format"))
	switch format {
	case "slack", "discord", "generic":
	default:
		format = "slack"
	}
	tmp := notifier.New(notifier.Config{
		URL:       url,
		Format:    format,
		Sites:     strings.TrimSpace(r.FormValue("site_label")),
		BanEvents: true,
	})
	if err := tmp.TestSend(r.Context()); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"ok": 0, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": 1})
}

// applyCommunityBansForm: receive the community-bans tab form.
//   - report_enabled  : "share to hub when BANning" (= also records terms accept)
//   - subscribe_mode  : "off" / "fetch" / "fetch_apply"
//
// The hub URLs live in defaults() (communitybans-package constants) and are not
// edited from the UI; the unmask.sh hub is the only target until the feature
// graduates beyond preview.
func applyCommunityBansForm(c *settings.CommunityBans, r *http.Request) {
	// report_enabled is the unified clickwrap: one checkbox both enables
	// submission AND records terms acceptance (= ticking it is the
	// affirmative action).
	report := r.FormValue("report_enabled") == "1"
	c.SubmitEnabled = report
	if report {
		// Ticking the box is the acceptance.  Stamp time + version on first
		// accept or on a version bump (= re-accept after terms change).
		if c.TermsAcceptedAt == 0 || c.TermsAcceptedVersion < settings.CurrentCommunityBansTermsVersion {
			c.TermsAcceptedAt = time.Now().Unix()
		}
		c.TermsAcceptedVersion = settings.CurrentCommunityBansTermsVersion
	}
	// Unchecking report stops submission but keeps the acceptance record
	// (= re-enabling later does not require re-reading the terms unless the
	// version bumped in the meantime).
	switch strings.TrimSpace(r.FormValue("subscribe_mode")) {
	case settings.SubscribeOff, settings.SubscribeFetch, settings.SubscribeFetchApply:
		c.SubscribeMode = r.FormValue("subscribe_mode")
	default:
		c.SubscribeMode = settings.SubscribeOff
	}
	// PublishCountry: install-wide opt-out (default ON, set by the Default()
	// constructor so the feed shows a global picture).  When ON, future
	// register / submit / vote / comment requests pass publish_country=true
	// so the hub records the install's country code alongside the entry.
	// Flipping to OFF stops emitting the flag on new requests; old rows
	// keep whatever they recorded until they age out.
	c.PublishCountry = r.FormValue("publish_country") == "1"
	// HN override: trim + lowercase + clamp.  Strict validation lives on the
	// hub side -- here we just normalize so the saved value matches what the
	// hub will accept (= avoids "looks accepted in admin, rejected on hub").
	c.HNOverride = normalizeHNOverride(r.FormValue("hn_override"))
	// terms acceptance is handled at the top via the unified report_enabled
	// checkbox (= ticking it IS the acceptance).
}

// applySMTPForm: receive the SMTP tab form. Empty password submit preserves
// current value (= matches the "***" placeholder UX where the value is
// untouched). Port: 0 / invalid → 587.
// normalizeHNOverride: client-side parity with the hub's validHN().  Empty
// string clears the override.  Invalid input (= disallowed chars / length)
// is also coerced to empty so the bad value never reaches the wire; the
// hub silently re-validates on every register / submit.
func normalizeHNOverride(in string) string {
	s := strings.ToLower(strings.TrimSpace(in))
	if s == "" {
		return ""
	}
	if len(s) < 3 || len(s) > 32 {
		return ""
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		ok := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_'
		if !ok {
			return ""
		}
	}
	// First / last must be alphanum so the result reads like the derived form.
	isAlnum := func(c byte) bool {
		return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
	}
	if !isAlnum(s[0]) || !isAlnum(s[len(s)-1]) {
		return ""
	}
	return s
}

func applySMTPForm(c *settings.SMTP, r *http.Request) {
	c.Host = strings.TrimSpace(r.FormValue("host"))
	if v, err := strconv.Atoi(strings.TrimSpace(r.FormValue("port"))); err == nil && v >= 0 && v <= 65535 {
		c.Port = v
	}
	if c.Port == 0 {
		c.Port = 587
	}
	c.Username = strings.TrimSpace(r.FormValue("username"))
	if v := strings.TrimSpace(r.FormValue("password")); v != "" {
		c.Password = v
	}
	c.FromAddress = strings.TrimSpace(r.FormValue("from_address"))
	c.FromName = strings.TrimSpace(r.FormValue("from_name"))
	c.StartTLS = r.FormValue("starttls") == "1"
	c.InsecureSkipVerify = r.FormValue("insecure_skip_verify") == "1"
}

// AdminSMTPTest: POST {base}/admin/api/smtp/test — send a test mail.
//
// To try in-flight values immediately, read from the form and send via a
// one-shot mailer. If password is empty, use the current Mailer's password
// (= avoids forcing "save → test" in the UI).
func (h *Handler) AdminSMTPTest(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": 0, "error": "bad_form"})
		return
	}
	to := strings.TrimSpace(r.FormValue("to"))
	if to == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": 0, "error": "to_empty"})
		return
	}
	host := strings.TrimSpace(r.FormValue("host"))
	if host == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": 0, "error": "host_empty"})
		return
	}
	port := 587
	if v, err := strconv.Atoi(strings.TrimSpace(r.FormValue("port"))); err == nil && v > 0 {
		port = v
	}
	username := strings.TrimSpace(r.FormValue("username"))
	password := strings.TrimSpace(r.FormValue("password"))
	if password == "" {
		// Empty → use the current settings password (= can test without "save → test").
		password = h.snapshotSettings().SMTP.Password
	}
	tmp := mail.New(mail.Config{
		Host:               host,
		Port:               port,
		Username:           username,
		Password:           password,
		FromAddress:        strings.TrimSpace(r.FormValue("from_address")),
		FromName:           strings.TrimSpace(r.FormValue("from_name")),
		StartTLS:           r.FormValue("starttls") == "1",
		InsecureSkipVerify: r.FormValue("insecure_skip_verify") == "1",
	})
	if err := tmp.TestSend(to); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"ok": 0, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": 1})
}

// tabHelpKey returns the i18n key whose value is the popover content for
// the given settings tab.  Empty result means "no help text → omit the
// ?-button entirely."  Stays as a single lookup table so the template
// does not have to know the per-tab convention (= some keys are "intro",
// some "desc", some "tab_help").
func tabHelpKey(tab string) string {
	switch tab {
	case "network":
		return "settings.network.intro"
	case "smtp":
		return "settings.smtp.intro"
	case "notifications":
		return "settings.notify.desc"
	case "retention":
		return "settings.retention.intro"
	case "bypass-ips":
		return "settings.bypass_ips.intro"
	case "bypass-paths":
		return "settings.bypass_paths.intro"
	case "web-bot-auth":
		return "settings.web_bot_auth.help"
	case "privacy-pass":
		return "settings.privacy_pass.help"
	case "global":
		return "settings.global.tab_help"
	case "ua-filter":
		return "settings.ua.intro"
	case "ja4-verdicts":
		return "settings.ja4.desc"
	case "honeypot":
		return "settings.honeypot.desc"
	case "protected":
		return "settings.protected.desc"
	case "rate-limit":
		return "settings.rate_limit.intro"
	case "geo":
		return "settings.geo.intro"
	case "captcha":
		return "settings.captcha.desc"
	case "challenge":
		return "settings.challenge.intro"
	case "theme":
		return "settings.theme.intro"
	case "community-bans":
		return "settings.community_bans.intro"
	case "sites":
		return "settings.sites.intro"
	}
	return ""
}

// retentionStatsView: current size of the data the retention tab controls, so
// the operator can see what they're about to prune.  Zero values are fine when
// the tab is not being rendered (= the template just hides the empty row).
type retentionStatsView struct {
	EventsRows           int    // unmask_event row estimate (MAX(id)-MIN(id)+1; = int so the template's `comma` filter accepts it)
	EventsRowsApprox     bool   // EventsRows is the fast id-range estimate (rendered with "≈"), not an exact COUNT(*)
	EventsOldestTS       int64  // unix seconds of the oldest unmask_event row, or 0 if none
	EventsOldest         string // server-side UTC fallback string ("YYYY-MM-DD HH:MM UTC"), or ""
	CookieMinuteRows     int    // unmask_cookie_minute row count
	CookieMinuteOldestTS int64  // unix seconds of the oldest bucket, or 0 if none
	CookieMinuteOldest   string // UTC fallback string, or ""
	DBSize               int64  // DB size in bytes (sqlite file / mariadb data+index), or 0 if unknown
	DBSizeStr            string // pre-formatted DBSize (e.g. "12.3 MB"), or ""
	DBDriver             string // "sqlite" / "mariadb" (current DB backend)
	DBDetail             string // sqlite path, or mariadb host:port/db (no password)
	// Whole days from the oldest row to now, for a "N days ago" hint shown next
	// to the absolute timestamp.  0 when there is no row.
	EventsOldestDaysAgo       int
	CookieMinuteOldestDaysAgo int
	// TimedOut is set when one of the COUNT(*)/MIN() queries hit the context
	// deadline (or was cancelled) -- typically a large DB whose full-scan COUNT
	// outran the budget.  The template surfaces a warning instead of silently
	// rendering the zeroed-out counts as if the DB were genuinely empty.
	TimedOut bool
	// Per-metric success flags: true = the value was read, false = its query
	// errored/timed out and the value is unknown (rendered "??" rather than a
	// misleading 0, so the operator sees WHICH metric could not be computed).
	EventsRowsOK         bool
	EventsOldestOK       bool
	CookieMinuteRowsOK   bool
	CookieMinuteOldestOK bool
}

// retentionStats: cheap point-in-time stats for the retention tab.  Best-
// effort: query errors are logged and produce zero fields rather than fail
// the whole page.
func (h *Handler) retentionStats(ctx context.Context, loc *time.Location) retentionStatsView {
	if loc == nil {
		loc = time.UTC
	}
	v := retentionStatsView{}
	if h == nil || h.DB == nil {
		return v
	}
	// note logs a query error and, when it is a context deadline/cancel, flags
	// the view as incomplete so the template can warn instead of rendering the
	// zeroed-out counts as if the DB were genuinely empty.
	// note logs a query error, flags the view as timed-out on a deadline/cancel,
	// and returns whether the query succeeded so each metric can record its own
	// known/unknown state.
	note := func(label string, err error) bool {
		if err == nil {
			return true
		}
		log.Printf("retentionStats %s: %v", label, err)
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			v.TimedOut = true
		}
		return false
	}
	// Row count via the id range, NOT COUNT(*).  An exact COUNT(*) scans the
	// whole covering index (6.6M entries / ~6GB on tool1-us) and, cold or under
	// the aggregation goroutine's write load, outran even the 10s budget — the
	// timeout this tab kept hitting.  unmask_event is append-only and pruned
	// oldest-first, so its id range [MIN(id), MAX(id)] is dense: MAX-MIN+1 is a
	// near-exact estimate (measured 127 rows off out of 6.6M = 0.002% on
	// tool1-us).  MIN(id) and MAX(id) MUST be two separate queries: SQLite only
	// applies its min/max-is-one-index-seek optimization to a lone aggregate, so
	// `SELECT MIN(id), MAX(id)` in one statement falls back to a full index SCAN
	// (measured 0.7s) — two statements each SEARCH one endpoint in ~4ms O(1).  It
	// never scans, so it never times out; EventsRowsApprox marks it "≈".
	var minID, maxID int64
	okMin := note("events min id", h.DB.QueryRowContext(ctx,
		`SELECT COALESCE(MIN(id), 0) FROM unmask_event`).Scan(&minID))
	okMax := note("events max id", h.DB.QueryRowContext(ctx,
		`SELECT COALESCE(MAX(id), 0) FROM unmask_event`).Scan(&maxID))
	v.EventsRowsOK = okMin && okMax
	if v.EventsRowsOK {
		v.EventsRowsApprox = true
		if maxID > 0 {
			v.EventsRows = int(maxID - minID + 1)
		}
	}
	// Oldest unmask_event row as unix seconds.  The column is TEXT; convert
	// driver-side so we don't have to parse multiple datetime formats in Go.
	eventsOldestSQL := `SELECT COALESCE(CAST(strftime('%s', MIN(date_created)) AS INTEGER), 0) FROM unmask_event`
	if h.cfg().DB.Driver == "mariadb" {
		eventsOldestSQL = `SELECT COALESCE(UNIX_TIMESTAMP(MIN(date_created)), 0) FROM unmask_event`
	}
	v.EventsOldestOK = note("events oldest", h.DB.QueryRowContext(ctx, eventsOldestSQL).Scan(&v.EventsOldestTS))
	if v.EventsOldestTS > 0 {
		v.EventsOldest = time.Unix(v.EventsOldestTS, 0).In(loc).Format("2006-01-02 15:04 MST")
		v.EventsOldestDaysAgo = int(time.Since(time.Unix(v.EventsOldestTS, 0)).Hours() / 24)
	}
	v.CookieMinuteRowsOK = note("cookie_minute count", h.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM unmask_cookie_minute`).Scan(&v.CookieMinuteRows))
	var oldestMin int64
	v.CookieMinuteOldestOK = note("cookie_minute oldest", h.DB.QueryRowContext(ctx,
		`SELECT COALESCE(MIN(bucket_min), 0) FROM unmask_cookie_minute`).Scan(&oldestMin))
	if oldestMin > 0 {
		v.CookieMinuteOldestTS = oldestMin * 60
		v.CookieMinuteOldest = time.Unix(v.CookieMinuteOldestTS, 0).In(loc).Format("2006-01-02 15:04 MST")
		v.CookieMinuteOldestDaysAgo = int(time.Since(time.Unix(v.CookieMinuteOldestTS, 0)).Hours() / 24)
	}
	dbc := h.cfg().DB
	v.DBDriver = dbc.Driver
	if v.DBDriver == "" {
		v.DBDriver = "sqlite"
	}
	switch v.DBDriver {
	case "mariadb":
		m := dbc.MariaDB
		v.DBDetail = fmt.Sprintf("%s:%d/%s", m.Host, m.Port, m.Database)
		// data_length + index_length across this schema's tables.  COALESCE so an
		// empty schema reads 0 (not NULL).  No password is exposed.
		var sz int64
		note("mariadb size", h.DB.QueryRowContext(ctx,
			`SELECT COALESCE(SUM(data_length+index_length),0) FROM information_schema.tables WHERE table_schema = DATABASE()`).Scan(&sz))
		if sz > 0 {
			v.DBSize = sz
			v.DBSizeStr = humanBytes(sz)
		}
	default: // sqlite
		v.DBDetail = dbc.SQLitePath
		if dbc.SQLitePath != "" {
			if st, err := os.Stat(dbc.SQLitePath); err == nil {
				v.DBSize = st.Size()
				v.DBSizeStr = humanBytes(v.DBSize)
			}
		}
	}
	return v
}

// humanBytes: render a byte count as a one-decimal SI-style string
// (e.g. 12345 -> "12.1 KB").  Returns "" for n<=0.
func humanBytes(n int64) string {
	if n <= 0 {
		return ""
	}
	const k = 1024.0
	switch {
	case n < int64(k):
		return fmt.Sprintf("%d B", n)
	case n < int64(k*k):
		return fmt.Sprintf("%.1f KB", float64(n)/k)
	case n < int64(k*k*k):
		return fmt.Sprintf("%.1f MB", float64(n)/(k*k))
	default:
		return fmt.Sprintf("%.2f GB", float64(n)/(k*k*k))
	}
}

// --- branding form helpers ----------------------------------------------

// allowed logo file extensions, mapped from MIME-ish suffixes accepted on
// upload.  Kept tight so a misnamed file (.exe disguised as .png) just gets
// rejected — Content-Type sniffing on the upload side is non-trivial in
// pure Go, so we lean on the extension here and rely on the visitor-side
// serve handler to set the Content-Type per the on-disk extension.
var brandingAllowedExt = map[string]bool{
	".png": true, ".jpg": true, ".jpeg": true,
	".svg": true, ".webp": true, ".gif": true,
}

// pickLogoExt returns the lowercase extension (with the dot) when it sits
// in brandingAllowedExt, plus ok=true.  Unknown extensions return ok=false.
func pickLogoExt(filename string) (string, bool) {
	ext := strings.ToLower(filepath.Ext(filename))
	if brandingAllowedExt[ext] {
		return ext, true
	}
	return "", false
}

// sanitizeSVG strips the most common JS-execution vectors out of an SVG
// payload before it lands in the static serve.  This is a regex-based
// best-effort filter (not a full XML parser): the threat model is
// "operator uploads a malicious SVG that runs JS in visitors' browsers",
// which is a defence-in-depth concern -- the operator is already admin,
// but the challenge page is rendered for unauthenticated visitors.
//
// Strips:
//   - <script>...</script> blocks
//   - <foreignObject>, <iframe>, <object>, <embed> elements
//   - on*= event-handler attributes (= onload / onclick / ...)
//   - href / xlink:href values starting with "javascript:" or "data:text/html"
func sanitizeSVG(data []byte) []byte {
	src := string(data)
	src = svgDropScript.ReplaceAllString(src, "")
	src = svgDropForeign.ReplaceAllString(src, "")
	src = svgDropIframe.ReplaceAllString(src, "")
	src = svgDropObject.ReplaceAllString(src, "")
	src = svgDropEmbed.ReplaceAllString(src, "")
	src = svgStripOnAttr.ReplaceAllString(src, "")
	src = svgStripJSHref.ReplaceAllString(src, "")
	return []byte(src)
}

var (
	svgDropScript  = regexp.MustCompile(`(?is)<script\b[^>]*>.*?</script\s*>|<script\b[^>]*/?>`)
	svgDropForeign = regexp.MustCompile(`(?is)<foreignObject\b[^>]*>.*?</foreignObject\s*>|<foreignObject\b[^>]*/?>`)
	svgDropIframe  = regexp.MustCompile(`(?is)<iframe\b[^>]*>.*?</iframe\s*>|<iframe\b[^>]*/?>`)
	svgDropObject  = regexp.MustCompile(`(?is)<object\b[^>]*>.*?</object\s*>|<object\b[^>]*/?>`)
	svgDropEmbed   = regexp.MustCompile(`(?is)<embed\b[^>]*/?>`)
	svgStripOnAttr = regexp.MustCompile(`(?i)\son[a-z]+\s*=\s*("[^"]*"|'[^']*'|[^\s>]*)`)
	svgStripJSHref = regexp.MustCompile(`(?i)\s(?:xlink:)?href\s*=\s*("(?:javascript|data:text/html)[^"]*"|'(?:javascript|data:text/html)[^']*'|(?:javascript|data:text/html)[^\s>]*)`)
)

// applyBrandingForm mutates cur in place with the values from the branding
// form (= section=branding).  configPath is the path to the active
// config.yml so the logo can be persisted next to it (= <dir>/branding/logo.<ext>).
//
// Operates on a *settings.BrandingValues record (= one Default or one site
// entry).  applyBrandingFormV2 wraps this for the default + sites save path.
//
// The logo file accepts a single upload.  Missing file = leave existing
// logo untouched (= operator only changed text fields).  branding_logo_clear=1
// removes the on-disk file + clears LogoPath.
func applyBrandingForm(cur *settings.BrandingValues, configPath string, r *http.Request) error {
	cur.SiteName = strings.TrimSpace(r.FormValue("branding_site_name"))
	cur.FooterText = strings.TrimSpace(r.FormValue("branding_footer_text"))
	if p := strings.TrimSpace(r.FormValue("branding_copy_preset")); settings.IsValidBrandingPreset(p) {
		cur.CopyPreset = p
	} else {
		cur.CopyPreset = settings.BrandingPresetFriendly
	}
	// Deny page design (rate-limit "retry" + ban "blocked") is part of this
	// appearance record, so it is parsed here and follows the same Default /
	// per-site resolution as the logo.  Done before the logo early-returns so it
	// always runs.  Empty / invalid theme -> auto; empty preset -> inherit.
	if err := parseDenyThemeField(r, "deny_theme", &cur.DenyRateTheme); err != nil {
		return err
	}
	if err := parseDenyPresetField(r, "deny_copy_preset", &cur.DenyRateCopyPreset); err != nil {
		return err
	}
	cur.DenyRateColors = parseDenyColorsField(r, "deny")
	if err := parseDenyThemeField(r, "ban_deny_theme", &cur.DenyBanTheme); err != nil {
		return err
	}
	if err := parseDenyPresetField(r, "ban_copy_preset", &cur.DenyBanCopyPreset); err != nil {
		return err
	}
	cur.DenyBanColors = parseDenyColorsField(r, "ban")
	// Length caps so a runaway paste doesn't bloat the config file or
	// overflow the challenge layout.
	if n := len([]rune(cur.SiteName)); n > 80 {
		cur.SiteName = string([]rune(cur.SiteName)[:80])
	}
	if n := len([]rune(cur.FooterText)); n > 160 {
		cur.FooterText = string([]rune(cur.FooterText)[:160])
	}
	// Logo handling: explicit clear takes priority over file upload.
	if r.FormValue("branding_logo_clear") == "1" {
		if cur.LogoPath != "" {
			_ = os.Remove(cur.LogoPath)
		}
		cur.LogoPath = ""
		return nil
	}
	f, fh, err := r.FormFile("branding_logo_file")
	if err == http.ErrMissingFile || f == nil {
		// No upload this time — keep the existing on-disk file.
		return nil
	}
	if err != nil {
		return fmt.Errorf("logo: read upload: %w", err)
	}
	defer func() { _ = f.Close() }()
	ext, ok := pickLogoExt(fh.Filename)
	if !ok {
		return fmt.Errorf("logo: unsupported extension (allowed: png, jpg, jpeg, svg, webp, gif)")
	}
	data, err := io.ReadAll(io.LimitReader(f, 4<<20))
	if err != nil {
		return fmt.Errorf("logo: read failed: %w", err)
	}
	if ext == ".svg" {
		data = sanitizeSVG(data)
	}
	dir := filepath.Join(filepath.Dir(configPath), "branding")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("logo: mkdir failed: %w", err)
	}
	// Drop any prior logo whose extension differs from the new upload so
	// stale files do not accumulate on disk.
	if cur.LogoPath != "" && strings.ToLower(filepath.Ext(cur.LogoPath)) != ext {
		_ = os.Remove(cur.LogoPath)
	}
	path := filepath.Join(dir, "logo"+ext)
	// Write to a temp file in the same dir and rename into place so a concurrent
	// reader (the /branding/logo serve) never sees a half-written file, matching
	// the atomic tmp+rename pattern used for every other on-disk write.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return fmt.Errorf("logo: write failed: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("logo: rename failed: %w", err)
	}
	cur.LogoPath = path
	return nil
}

// applyBrandingFormV2: top-level entry point for the branding tab save.
// In v2 there is a single form per tab that edits the Default record only;
// per-site cards have their own add / edit / delete endpoints (see the
// HandleBrandingSite* methods below).  Until the cards land, this is a thin
// adapter onto applyBrandingForm targeting cur.Default.
func applyBrandingFormV2(cur *settings.Branding, configPath string, r *http.Request) error {
	return applyBrandingForm(&cur.Default, configPath, r)
}

// applyChallengeFormV2: top-level entry point for the challenge tab save.
// Mirrors applyBrandingFormV2: the Default record is edited via the same
// form fields, per-site entries via dedicated card endpoints.
func applyChallengeFormV2(cur *settings.ChallengeConfig, r *http.Request) error {
	return applyChallengeForm(&cur.Default, r)
}

// AdminBrandingSiteSave: POST {base}/admin/settings/branding/site/save
//
// Persists one Sites[<host>] entry for the branding wrapper.  The form
// carries the site identifier in `site` plus the same field names as the
// default form (branding_site_name / branding_footer_text /
// branding_copy_preset / branding_logo_file / branding_logo_clear).  Empty
// fields are persisted as-is (= the v2 contract is "complete record",
// nothing inherits from Default).  Already-existing sites are overwritten;
// the same handler covers add + edit.  Redirects back to the theme tab,
// where the per-site card section lives.
func (h *Handler) AdminBrandingSiteSave(w http.ResponseWriter, r *http.Request) {
	h.adminScalarSiteSave(w, r, "theme", func(cur *settings.Settings, site string) error {
		// "Override on" checkbox.  Off → flip the existing entry's Disabled
		// flag so Resolve falls back to Default but the carefully-edited
		// values stay around for next time.  No entry yet + off = no-op (=
		// nothing to remember).  This avoids the destructive "save erases
		// the override" path the operator hit when toggling the checkbox.
		overrideOn := r.FormValue("use_site_override") == "1"
		if !overrideOn {
			if cur.Branding.Sites != nil {
				if v, ok := cur.Branding.Sites[site]; ok {
					v.Disabled = true
					cur.Branding.Sites[site] = v
				}
			}
			if cur.Challenge.Sites != nil {
				if v, ok := cur.Challenge.Sites[site]; ok {
					v.Disabled = true
					cur.Challenge.Sites[site] = v
				}
			}
			return nil
		}
		if cur.Branding.Sites == nil {
			cur.Branding.Sites = map[string]settings.BrandingValues{}
		}
		// Seed from the existing entry so that an edit that does not touch
		// the logo file preserves it (= applyBrandingForm leaves LogoPath
		// alone when there is no upload).  When a site is being created for
		// the first time via the scope picker, the form arrives with the
		// Default values pre-filled, so the new entry inherits Default's
		// fields with whatever the operator changed.
		bv := cur.Branding.Sites[site]
		if err := applyBrandingForm(&bv, h.ConfigPath, r); err != nil {
			return err
		}
		bv.Disabled = false
		cur.Branding.Sites[site] = bv
		// The theme tab form (= scope=<host>) also carries `theme` +
		// `show_credit`, which belong on cur.Challenge.Sites[site] -- mirror
		// the section=appearance behavior that writes both to Default in one
		// click.  Without this branch the operator would have to switch to
		// the challenge tab + same scope to commit those two fields.
		if cur.Challenge.Sites == nil {
			cur.Challenge.Sites = map[string]settings.ChallengeValues{}
		}
		cv := cur.Challenge.Sites[site]
		// Seed cookie windows + pow difficulty from Default if the site has
		// no existing override -- the theme tab does not expose challenge
		// numeric knobs, so without this seed the new override would carry
		// zero values that the challenge engine then snaps to defaults.
		if _, ok := cur.Challenge.Sites[site]; !ok {
			cv = cur.Challenge.Default
			// Theme + ShowCredit are about to be overwritten from the form,
			// but everything else (= captcha + cookie windows + difficulty
			// + debug rate + public test pages) should mirror Default until
			// the operator visits the challenge tab.
		}
		t := strings.TrimSpace(r.FormValue("theme"))
		if !challengeThemes[t] {
			t = "default"
		}
		cv.Theme = t
		cv.ShowCredit = r.FormValue("show_credit") == "1"
		cv.Disabled = false
		cur.Challenge.Sites[site] = cv
		return nil
	})
}

// AdminBrandingSiteDelete: POST {base}/admin/settings/branding/site/delete
// Drops cur.Branding.Sites[<site>] entirely, returning the site to Default
// verbatim on the next request.
func (h *Handler) AdminBrandingSiteDelete(w http.ResponseWriter, r *http.Request) {
	h.adminScalarSiteSave(w, r, "theme", func(cur *settings.Settings, site string) error {
		delete(cur.Branding.Sites, site)
		return nil
	})
}

// AdminChallengeSiteSave: POST {base}/admin/settings/challenge/site/save
//
// Persists cur.Challenge.Sites[<site>].  Targeted by the challenge tab when
// the scope picker selects a host (= scope=<host>).  When the per-site entry
// did not exist before, it is seeded from cur.Challenge.Default so fields the
// challenge tab does not edit (= theme + show_credit, which live on the theme
// tab) are not zeroed out.
func (h *Handler) AdminChallengeSiteSave(w http.ResponseWriter, r *http.Request) {
	h.adminScalarSiteSave(w, r, "challenge", func(cur *settings.Settings, site string) error {
		// "Override on" checkbox.  Off → flip Disabled on the existing entry
		// (= values stay for next time, Resolve falls back to Default).
		// First-time off with no entry yet is a no-op.
		overrideOn := r.FormValue("use_site_override") == "1"
		if !overrideOn {
			if cur.Challenge.Sites != nil {
				if v, ok := cur.Challenge.Sites[site]; ok {
					v.Disabled = true
					cur.Challenge.Sites[site] = v
				}
			}
			return nil
		}
		if cur.Challenge.Sites == nil {
			cur.Challenge.Sites = map[string]settings.ChallengeValues{}
		}
		cv, existed := cur.Challenge.Sites[site]
		if !existed {
			// First save for this site: seed from Default so theme +
			// show_credit (= owned by the theme tab) survive.  The
			// challenge tab will overwrite the fields it owns below.
			cv = cur.Challenge.Default
		}
		if err := applyChallengeForm(&cv, r); err != nil {
			return err
		}
		// captcha provider + theme share the form field names with the
		// captcha / theme tabs.  Reuse the existing parsers so the per-site
		// card form behaves the same as the default form.
		if err := applyCaptchaForm(&cv.CaptchaProvider, r); err != nil {
			return err
		}
		if t := strings.TrimSpace(r.FormValue("theme")); t != "" {
			if !challengeThemes[t] {
				t = "default"
			}
			cv.Theme = t
		}
		cv.Disabled = false
		cur.Challenge.Sites[site] = cv
		return nil
	})
}

// AdminChallengeSiteDelete: POST {base}/admin/settings/challenge/site/delete
func (h *Handler) AdminChallengeSiteDelete(w http.ResponseWriter, r *http.Request) {
	h.adminScalarSiteSave(w, r, "challenge", func(cur *settings.Settings, site string) error {
		delete(cur.Challenge.Sites, site)
		return nil
	})
}

// adminScalarSiteSave is the shared body for all four per-site card endpoints.
// It loads the latest settings from disk, runs mutate, saves atomically, and
// swaps the in-memory snapshot under settingsMu.  Errors are surfaced via the
// same flash cookie + redirect contract as AdminSettingsSave.
func (h *Handler) adminScalarSiteSave(w http.ResponseWriter, r *http.Request, tab string, mutate func(*settings.Settings, string) error) {
	if h.ConfigPath == "" {
		http.Error(w, "config path unknown", http.StatusBadRequest)
		return
	}
	// branding endpoints can carry multipart (= the save form has a logo
	// upload); challenge + delete are plain.  Decide by the actual content
	// type instead of the URL path so a delete via x-www-form-urlencoded
	// against the /branding/ subtree still parses cleanly.
	ctype := r.Header.Get("Content-Type")
	if strings.HasPrefix(ctype, "multipart/") {
		if err := r.ParseMultipartForm(4 << 20); err != nil {
			http.Error(w, "bad form (multipart): "+err.Error(), http.StatusBadRequest)
			return
		}
	} else if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	base := h.cfg().Server.BasePath
	// Carry scope back to the redirect so the operator lands on the same
	// per-site form they just saved (= same picker option still selected).
	// The deletes redirect to the Default form (= scope="") which is correct
	// because the entry the operator just dropped no longer has a form.
	site := normalizeSite(strings.TrimSpace(r.FormValue("site")))
	redirBack := func(msg string, scopeHost string) {
		dst := base + "/admin/settings/?tab=" + tab
		if scopeHost != "" {
			dst += "&scope=" + url.QueryEscape(scopeHost)
		}
		if msg == "" {
			// Per-site branding / challenge / theme are admin-only (= never
			// touch the rendered conf), so no &reload=1 is appended and the
			// banner shows "applies immediately".  If a per-site setting ever
			// reaches the conf, add the same RenderSignature diff used by the
			// main save handler here.
			dst += "&saved=1&section=" + url.QueryEscape(tab)
		} else {
			setFlash(w, r, base, "err", msg)
		}
		http.Redirect(w, r, dst, http.StatusFound)
	}
	if site == "" {
		redirBack("site is required", "")
		return
	}
	settingsMu.Lock()
	defer settingsMu.Unlock()
	cur, err := settings.Load(h.ConfigPath)
	if err != nil {
		redirBack("load: "+err.Error(), site)
		return
	}
	if err := mutate(&cur, site); err != nil {
		redirBack(err.Error(), site)
		return
	}
	if err := settings.Save(cur, h.ConfigPath); err != nil {
		redirBack("save: "+err.Error(), site)
		return
	}
	h.settingsPtr.Store(&cur)
	// Stay on the just-saved scope even when the save dropped the entry
	// (= operator unchecked "override on" + saved).  The redirect target is
	// still ?scope=<host>, where the picker keeps the host selected and the
	// banner shows "editing uic.io" + override toggle off.  Operators that
	// truly want to leave the per-site view do so via the side menu (which
	// drops scope intentionally) or by typing default into the scope picker.
	redirBack("", site)
}

// applyRateLimitValuesForm was used by the v2 per-site rate-limit card
// (AdminRateLimitSiteSave) and removed in step b along with the per-site
// scalar wrapper.  See applyRateLimitForm for the install-wide Default
// path; per-site rate variations now live in RateZone rows with Site.

// AdminRateLimitSiteSave: POST {base}/admin/settings/rate_limit/site/save
// Rate-limit per-site scalar overrides were dropped along with honeypot's:
// every per-site rate variation can be expressed by adding a RateZone with
// a Site column instead, which leaves a single place in the UI to look at
// per-host rate behaviour.  Install-wide Default still applies when no
// zone matches.

// Honeypot per-site scalar overrides were dropped: the BAN list is keyed on
// IP+JA4 and not on the visited host, so a per-host BanDurationSec did not
// have a coherent meaning.  BanDurationSec lives directly on HoneypotConfig
// and applies install-wide; per-site URL filtering still works via the
// HoneypotURL.Site column.

// IPRangeSyncInfo: state shape consumed by the settings template's hub-sync
// status card.  Zero-value LastSyncedAt = no successful pull yet.
type IPRangeSyncInfo struct {
	Enabled      bool
	HubURL       string
	LastSyncedAt int64 // unix seconds, 0 if never
	LastError    string
}

// IPRangeSyncStatus returns the current state of the subscribe goroutine for
// the bypass-ips tab's hub-sync card.  Nil-safe (= disabled state).
func (h *Handler) IPRangeSyncStatus() IPRangeSyncInfo {
	if h.IPRangeSync == nil {
		return IPRangeSyncInfo{}
	}
	info := IPRangeSyncInfo{
		Enabled:   true,
		HubURL:    h.IPRangeSync.HubURLString(),
		LastError: h.IPRangeSync.LastError(),
	}
	if t := h.IPRangeSync.LastSyncedAt(); !t.IsZero() {
		info.LastSyncedAt = t.Unix()
	}
	return info
}

// applyWebBotAuthForm: receive the web-bot-auth tab form.
//
//   - enabled         : verify signed-agent requests at all
//   - preset_operator : checked preset checkboxes (one repeated field per host)
//   - operator        : custom add-rows (one repeated field per host)
//   - cache_ttl_sec   : per-operator directory cache lifetime
//
// AllowedOperators = checked presets + custom rows, deduped (case-insensitive).
// Public key directories are fetched lazily by the Verifier; this form only
// configures gating.
func applyWebBotAuthForm(c *settings.WebBotAuthConfig, r *http.Request) {
	c.Enabled = r.FormValue("enabled") == "1" // also triggers form parsing

	c.AllowedOperators = nil
	seen := map[string]bool{}
	add := func(s string) {
		s = strings.TrimSpace(s)
		k := strings.ToLower(s)
		if s != "" && !seen[k] {
			seen[k] = true
			c.AllowedOperators = append(c.AllowedOperators, s)
		}
	}
	for _, op := range r.Form["preset_operator"] {
		add(op)
	}
	for _, op := range r.Form["operator"] {
		add(op)
	}

	if n, err := strconv.Atoi(strings.TrimSpace(r.FormValue("cache_ttl_sec"))); err == nil && n > 0 {
		c.CacheTTLSec = n
	}
}

// applyPrivacyPassForm: receive the privacy-pass tab form.
//
//   - enabled        : verify "Authorization: PrivateToken" (PAT) headers at all
//   - pp_issuer_name : issuer host add-rows (the challenge issuer_name + label)
//   - pp_issuer_key  : the matching token-key (DER SubjectPublicKeyInfo,
//     id-RSASSA-PSS, base64), parallel-indexed with pp_issuer_name
//
// Rows with an empty name or key are dropped; the verifier further skips any key
// it can't parse.
func applyPrivacyPassForm(c *settings.PrivacyPassConfig, r *http.Request) {
	c.Enabled = r.FormValue("enabled") == "1" // also triggers form parsing

	c.EnabledIssuerPresets = nil
	for _, id := range r.Form["pp_preset"] {
		if id = strings.TrimSpace(id); id != "" {
			c.EnabledIssuerPresets = append(c.EnabledIssuerPresets, id)
		}
	}

	c.Issuers = nil
	names := r.Form["pp_issuer_name"]
	keys := r.Form["pp_issuer_key"]
	for i := range names {
		name := strings.TrimSpace(names[i])
		key := ""
		if i < len(keys) {
			key = strings.TrimSpace(keys[i])
		}
		if name != "" && key != "" {
			c.Issuers = append(c.Issuers, settings.PrivacyPassIssuer{Name: name, Key: key})
		}
	}
}

// AdminIPRangeSync: POST {base}/admin/api/iprange/sync — force one pull
// from the hub right now.  Returns ok=1 + last_synced_at on success, or
// ok=0 + error message.  Settings UI calls this from the "Sync now" button.
func (h *Handler) AdminIPRangeSync(w http.ResponseWriter, r *http.Request) {
	if h.IPRangeSync == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": 0, "error": "sync_disabled"})
		return
	}
	if err := h.IPRangeSync.PullOnce(r.Context()); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"ok": 0, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":             1,
		"last_synced_at": h.IPRangeSync.LastSyncedAt().Unix(),
	})
}
