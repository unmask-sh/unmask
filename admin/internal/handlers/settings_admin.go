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
	"os/user"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/oschwald/maxminddb-golang"
	"github.com/unmask-sh/unmask/admin/internal/classify"
	"github.com/unmask-sh/unmask/admin/internal/crawlerverify"
	"github.com/unmask-sh/unmask/admin/internal/dashboard"
	"github.com/unmask-sh/unmask/admin/internal/db"
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
	case "top", "network", "global", "ua-filter", "ja4-verdicts", "honeypot", "bypass-ips", "bypass-paths", "web-bot-auth", "privacy-pass", "protected", "captcha", "challenge", "rate-limit", "deny-design", "geo", "asn", "theme", "notifications", "smtp", "retention", "performance", "community-bans", "sites", "about":
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
	//
	// The per-pattern checkbox shows INTENT -- "is this crawler on the rescue
	// list at all" -- not the effective rescue path.  Those are two questions,
	// and answering both with one control is what made this list hard to read:
	// a range-backed row appeared unchecked, which on any other row means
	// "blocked", while here it meant "passes, verified by IP".  How a rescued
	// crawler is verified is now the standing policy's business (the switch
	// above the rows), and the per-pattern badge states the resulting path.
	upstreamRescue := classify.UpstreamRescueList()
	upstreamDisabledSet := toSet(cur.SearchBots.UpstreamDisabled)
	upstreamUAOffView := map[string]bool{}
	for p := range upstreamDisabledSet {
		upstreamUAOffView[p] = true
	}
	// With the policy off, the UA path is per-pattern again, so the checkbox
	// goes back to showing that resolution.
	if !cur.SearchBots.RangeVerificationRequired() {
		for p, off := range nginxconf.EffectiveUpstreamUAOff(cur) {
			if off {
				upstreamUAOffView[p] = true
			}
		}
	}
	upstreamTotal := 0
	upstreamEnabled := 0
	for _, entries := range upstreamRescue {
		for _, e := range entries {
			upstreamTotal++
			if !upstreamUAOffView[e.Pattern] {
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
	// published vendor IP range at all (backed), and for those, whether the
	// vendor's addresses are loaded right now (= the badge is green).
	// catHasRV drives the per-category legend line.  UpstreamUAOff feeds the
	// checkbox state so the UI shows the *effective* UA rescue, explicit or
	// auto.
	upstreamRangeBacked := make(map[string]bool, len(nginxconf.UARangePresets))
	for pat := range nginxconf.UARangePresets {
		upstreamRangeBacked[pat] = true
	}
	upstreamRVActive := nginxconf.UpstreamRangeActive(cur)
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
		cur.JA4Verdicts.ExtraCreatedAt,
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
			"Type":      mt,
			"Pattern":   rl.Pattern,
			"Title":     rl.Title,
			"Disabled":  rl.Disabled,
			"CreatedAt": rl.CreatedAt,
			"UpdatedAt": rl.UpdatedAt,
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
	if tab == "retention" || tab == "performance" {
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
	// Normalize exactly like the save handler does (lowercase, port stripped,
	// trailing dot dropped).  The scope picker's "add a host" prompt sends
	// whatever the operator typed, so "CodeZine.jp" or "codezine.jp:443" used
	// to render a page whose scope string could never match the key the save
	// wrote -- the form looked empty on return and a second save landed on a
	// different row than the first.
	if scope != "" {
		if n := normalizeSite(scope); n != "" && n != defaultSite {
			scope = n
		}
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
	for _, host := range h.cfg().Sites.ActiveDefined() {
		if host != "" {
			scopeHostSet[host] = true
		}
	}
	// The scope currently being edited.  A host typed into the picker's "add"
	// prompt exists in none of the sources above until something about it is
	// saved, so without this the <select> had no matching <option> and fell
	// back to displaying "Default" -- while the banner beside it announced the
	// new host and the form edited that host's record.  An operator reading
	// the pulldown would believe they were editing Default, or re-pick from
	// the list and silently land on a different site.
	if scopeIsSite {
		scopeHostSet[scope] = true
	}
	scopeHosts := make([]string, 0, len(scopeHostSet))
	for h := range scopeHostSet {
		scopeHosts = append(scopeHosts, h)
	}
	sort.Strings(scopeHosts)

	staleAutoChrome, staleAutoChromeSrc := settings.AutoChromeBaseline()
	staleAutoFF, staleAutoFFSrc := settings.AutoFirefoxBaseline()

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
		// Monitor mode is stored on the challenge record but presented on the
		// operating-mode tab, so the template needs it alongside Global.
		"ObserveOnly": h.snapshotSettings().Challenge.Default.IsObserveOnly(),
		// Shipped current-Chrome-major baseline shown as the placeholder for the
		// stale-browser tier's optional override field.
		"StaleBrowserBaseline":     settings.DefaultCurrentChromeMajor,
		"StaleBrowserFFBaseline":   settings.DefaultCurrentFirefoxMajor,
		"StaleBrowserLagDefault":   settings.DefaultStaleBrowserLag,
		"StaleBrowserLagDefaultFF": settings.DefaultStaleBrowserLagFirefox, // judged per family; equal to Chromium's today by coincidence
		// Automatic-baseline rows: the value the tier would use with no manual
		// override, its origin (hub / builtin), when the last hub pull
		// happened (operator cookie TZ), and the exempt ESR majors.
		"StaleAutoChrome":    staleAutoChrome,
		"StaleAutoChromeSrc": staleAutoChromeSrc,
		"StaleAutoFF":        staleAutoFF,
		"StaleAutoFFSrc":     staleAutoFFSrc,
		"StaleHubFetchedAt": func() string {
			if hub, ok := settings.HubBrowserBaselines(); ok && !hub.FetchedAt.IsZero() {
				return hub.FetchedAt.In(loc).Format("2006-01-02 15:04")
			}
			return ""
		}(),
		"StaleESRList": func() string {
			var parts []string
			for _, m := range h.snapshotSettings().Global.FirefoxESRMajors() {
				parts = append(parts, strconv.Itoa(m))
			}
			return strings.Join(parts, ", ")
		}(),
		"IPGeoMMDBPath":        ipgeoCur.MMDBPath,
		"IPGeoMMDBASNPath":     ipgeoCur.MMDBASNPath,
		"IPGeoLoaded":          h.IPGeo != nil && h.IPGeo.Loaded(),
		"AsnMmdbLoaded":        h.IPGeo != nil && h.IPGeo.ASNLoaded(),
		"AsnProviders":         h.asnProviderView(cur.Asn),
		"AsnCustomRules":       asnCustomRuleView(cur.Asn),
		"AsnDefaultRate":       cur.Asn.DefaultRatePerMin,
		"AsnDefaultRuleAction": cur.Asn.ResolvedDefaultRuleAction(), // what a blank row action inherits
		"GeoDefaultRuleAction": cur.Geo.ResolvedDefaultRuleAction(),
		"GeoDefaultRate":       cur.Geo.DefaultRatePerMin,
		// What an UNSET chain picker acts as: protected paths / the ja4 default
		// chain fall back to the rate-limit default chmode; surfaced so the
		// "(unset)" option can show the value it resolves to.
		"RateDefaultChMode": h.snapshotSettings().RateLimit.Default.ResolvedChallengeMode(),
		// Literal prefixes of the protected paths that are actually enforced,
		// for the rate-limit tab's live warning: a zone whose effective mode
		// is deny and whose paths overlap one of these needs nginx 1.17.6+
		// (the dry_run composition).  Same composition as the render, reduced
		// to comparable heads.
		"RLProtectedPrefixes": protectedLiteralPrefixes(h.snapshotSettings()),
		"GeoExemptRows":       bypassPathRows(cur.Geo.ExemptPaths), // country-axis exempt paths (RSS etc.)
		"AsnExemptRows":       bypassPathRows(cur.Asn.ExemptPaths), // ASN-axis exempt paths (RSS etc.)
		"IPGeoASNLoaded":      h.IPGeo != nil && h.IPGeo.ASNLoaded(),
		"IPGeoAutoUpdate":     ipgeoCur.AutoUpdate,
		"IPGeoAutoUpdateASN":  ipgeoCur.AutoUpdateASN,
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
		"RoamingCap":    h.cfg().Rebind.MaxEntriesResolved(),
		"RoamingCapRaw": h.cfg().Rebind.MaxEntries,
		"RoamingMode":   h.cfg().Rebind.RebindMode(),
		"ASNDBLoaded":   h.IPGeo != nil && h.IPGeo.ASNLoaded(),
		// Active-row metadata for the in-line vendor / build / size badges.
		"IPGeoActiveInfo": func() IPGeoPathInfo {
			info, _ := buildIPGeoPathInfo(h.cfg().IPGeo.MMDBPath, loc)
			return info
		}(),
		"IPGeoASNActiveInfo": func() IPGeoPathInfo {
			info, _ := buildIPGeoPathInfo(h.cfg().IPGeo.MMDBASNPath, loc)
			return info
		}(),
		"LBPresets":             buildLBPresetView(cur),
		"LBExtras":              buildLBExtraView(cur),
		"SearchBotsRules":       pairRules(cur.SearchBots.Extra, cur.SearchBots.ExtraTitle, cur.SearchBots.ExtraDisabled, cur.SearchBots.ExtraCreatedAt, cur.SearchBots.ExtraUpdatedAt, nil),
		"UpstreamRescue":        upstreamRescue,
		"UpstreamUAOff":         upstreamUAOffView,
		"UpstreamRescueTotal":   upstreamTotal,
		"UpstreamRescueEnabled": upstreamEnabled,
		"UpstreamGroupMode":     upstreamGroupMode,
		"UpstreamGroupAction":   upstreamGroupAction,
		"UpstreamRangeBacked":   upstreamRangeBacked,
		"UpstreamRVActive":      upstreamRVActive,
		"UpstreamCatHasRV":      upstreamCatHasRV,
		"JA4Groups":             ja4Groups,
		"JA4Rules":              ja4ExtraRules,
		"JA4Verdicts":           cur.JA4Verdicts,
		"JA4PresetAction":       cur.JA4Verdicts.PresetAction,
		"JA4ExtraAction":        padToLen(cur.JA4Verdicts.ExtraAction, len(cur.JA4Verdicts.Extra)),
		"ChallengeAll":          cur.ChallengeTargets.All,
		"ChallengeGroups":       tgtGroups,
		"ChallengeRules":        pairRules(cur.ChallengeTargets.Extra, cur.ChallengeTargets.ExtraTitle, cur.ChallengeTargets.ExtraDisabled, cur.ChallengeTargets.ExtraCreatedAt, cur.ChallengeTargets.ExtraUpdatedAt, cur.ChallengeTargets.ExtraAction),
		// What "inherit" resolves to, so a row that pins nothing still says
		// which chain it will run rather than just "inherit".
		"ChallengeDefaultActionLabel": h.resolvedUABlacklistAction(),
		"ChallengeTargets":            cur.ChallengeTargets,
		"ChallengePresetAction":       cur.ChallengeTargets.PresetAction,
		"HoneypotGroups":              honeypotGroups,
		"HoneypotRules":               honeypotURLRows(cur.Honeypot.URLs),
		"HoneypotDefaultBanDuration":  cur.Honeypot.BanDurationSec,
		"Honeypot":                    cur.Honeypot,
		"HoneypotPresetAction":        cur.Honeypot.PresetAction,
		"BypassIPsRules":              pairBypassRules(cur.BypassIPs, cur.BypassIPsTitle, cur.BypassIPsDisabled, cur.BypassIPsCreatedAt, cur.BypassIPsUpdatedAt),
		"StatsExcludeRules":           pairStatsExcludeRules(cur.StatsExcludeIPs, cur.StatsExcludeIPsTitle),
		"CrawlerVerify":               cur.CrawlerVerify,
		"CrawlerVerifyForgedAction":   cur.CrawlerVerify.ResolvedForgedAction(),
		"CrawlerVerifyCrawlers":       crawlerVerifyCrawlerRows(cur.CrawlerVerify),
		"BypassPresetGroups":          bypassPresetGroups,
		"IPRangeSync":                 h.IPRangeSyncStatus(),
		"ProtectedRules":              protectedPathRows(cur.ProtectedPaths.Paths),
		"BypassPathGroups":            bypassPathGroups,
		"PrivateNetworkCIDRs":         nginxconf.PrivateNetworkCIDRs,
		"RedirectExemptGroups":        redirectExemptGroups,
		"RedirectExemptRules":         redirectExemptRules,
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
		"AdminIPsAllowAll": adminIPsAllowAll(settings.EnabledValues(cur.AdminAllowedIPs, cur.AdminAllowedIPsDisabled)),
		// Active row counts for the three list state lines -- rows switched
		// off must not count toward "restricted to N entries" (all-off = the
		// list is effectively open, and the state line has to say so).
		"AdminIPsActive":        len(settings.EnabledValues(cur.AdminAllowedIPs, cur.AdminAllowedIPsDisabled)),
		"AdminHostsActive":      len(settings.EnabledValues(cur.AdminAllowedHosts, cur.AdminAllowedHostsDisabled)),
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
		// (= cur.Branding.Sites[host].Theme) so the theme card preview shows
		// the per-site selection.  Lives on the branding record because it is
		// what the page looks like, not how the challenge behaves.
		"ChallengeTheme": func() string {
			t := scopeBranding.Theme
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
		"ChallengeCustomColors":    scopeBranding.CustomColors,
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
		// Resolved (site-over-Default) records for the checkbox fields.  A
		// checkbox cannot show "inherit" as a third state, so it renders the
		// EFFECTIVE value -- what the challenge page actually does.  Rendering
		// the raw *bool lies in both directions: Go templates treat any
		// non-nil pointer as true, so a site that pinned a flag OFF shows a
		// ticked box (and the next save of that form flips the flag back on),
		// while a site that inherits ON shows an empty box (and an untouched
		// save pins it off).  Sparsify keeps the round trip lossless: posting
		// the inherited value back collapses to nil = still inheriting.
		"BrandingEff":  snap.Branding.Resolve(scope),
		"ChallengeEff": snap.Challenge.Resolve(scope),
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
			// Point at the SITE-scoped serve route when a per-site scope is
			// being edited.  The plain /branding/logo route resolves the
			// REQUEST host -- i.e. the admin's own hostname -- so a correctly
			// saved per-site logo still rendered as a broken thumbnail (404)
			// unless the operator happened to be browsing the admin on that
			// exact site.  That made a successful save look like a failed one
			// and sent operators re-saving into the wrong scope.  The
			// site-scoped route is admin-session gated (testSiteOverride), so
			// the settings page is authorized for it.
			url := base + "/branding/logo"
			if scopeIsSite && testSiteHostRE.MatchString(scope) {
				// Wildcard / non-hostname scopes (e.g. "*.example.com") are not
				// addressable on that route; they keep the host-resolved URL
				// rather than pointing at a guaranteed 404.
				url = base + "/branding/" + scope + "/logo"
			}
			if st, err := os.Stat(p); err == nil {
				url += "?v=" + strconv.FormatInt(st.ModTime().Unix(), 10)
			}
			return url
		}(),
		// Base URL (trailing slash included) for the theme tab's live preview
		// iframes.  The plain /challenge/ route resolves branding by REQUEST
		// host -- the admin's own hostname -- so at a per-site scope the five
		// previews showed the wrong site's identity and, visibly, no logo: a
		// logo cannot ride a _preview_* query param the way the site name
		// does, it is fetched by the challenge page from its branding route.
		// The site-scoped route (/test/site/<site>/) resolves the previewed
		// site's branding and is admin-session gated (testSiteOverride), same
		// as the thumbnail above.  Same wildcard guard as the thumbnail:
		// "*.example.com" is not addressable on that route, keep the plain
		// one rather than pointing five iframes at a guaranteed 404.
		"ChallengePreviewBase": func() string {
			base := strings.TrimRight(h.cfg().Server.BasePath, "/")
			if scopeIsSite && testSiteHostRE.MatchString(scope) {
				return base + "/test/site/" + scope + "/"
			}
			return base + "/challenge/"
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
		// Which fields the scoped site actually overrides, keyed by form field
		// name.  The per-site form is pre-filled with RESOLVED values, so a
		// number that the site pins and a number it is borrowing from Default
		// look identical without this -- and per-field inheritance is only
		// legible if the page says which is which.  Empty for the Default
		// scope, where there is nothing to inherit from.
		"ChallengeFieldOverrides": func() map[string]bool {
			if !scopeIsSite {
				return map[string]bool{}
			}
			return settings.ChallengeOverridesFor(snap.Challenge, scope)
		}(),
		"BrandingFieldOverrides": func() map[string]bool {
			if !scopeIsSite {
				return map[string]bool{}
			}
			return settings.BrandingOverridesFor(snap.Branding, scope)
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
	for _, s := range sc.ActiveDefined() {
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
	CreatedAt int64 // unix sec of the ADD (see settings: the name is historical)
	UpdatedAt int64 // unix sec of the last edit, 0 while untouched
	// Action: the chain this row alone runs, "" to inherit the list default.
	// Only the black list offers it; the allowlist leaves it empty.
	Action string
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
	CreatedAt int64
	UpdatedAt int64 // unix sec of the last edit, 0 while untouched
}

// pairBypassRules: zip 4 parallel slices into the row-UI struct slice.
func pairBypassRules(ips, titles []string, disabled []bool, createdAt, updatedAt []int64) []bypassRule {
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
		if i < len(createdAt) {
			ts = createdAt[i]
		}
		var cs int64
		if i < len(updatedAt) {
			cs = updatedAt[i]
		}
		out[i] = bypassRule{IP: ip, Title: t, Enabled: !isDisabled, CreatedAt: ts, UpdatedAt: cs}
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
	CreatedAt int64
	UpdatedAt int64 // unix sec of the last edit, 0 while untouched
}

// pairJA4Rules: zip the 4 parallel slices of JA4Verdicts into the row-UI struct slice.
func pairJA4Rules(
	extras []settings.JA4VerdictExtraRule, titles []string, disabled []bool, createdAt, updatedAt []int64,
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
		if i < len(createdAt) {
			ts = createdAt[i]
		}
		action := e.Action
		if !nginxconf.IsValidJA4Action(action) {
			action = nginxconf.JA4ActionOK
		}
		var cs int64
		if i < len(updatedAt) {
			cs = updatedAt[i]
		}
		out[i] = ja4ExtraRule{
			ID:      e.ID,
			Pattern: e.Pattern, Verdict: e.Verdict, Action: action,
			Title: t, Enabled: !isDisabled, CreatedAt: ts, UpdatedAt: cs,
		}
	}
	return out
}

// pairRules: zip parallel slices (= patterns + titles + disabled + createdAt)
// into the template-bound struct slice. The shorter side is padded with defaults.
// actions is optional: pass nil for lists whose rows carry no chain.
func pairRules(patterns, titles []string, disabled []bool, createdAt, updatedAt []int64, actions []string) []extraRule {
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
		if i < len(createdAt) {
			ts = createdAt[i]
		}
		var cs int64
		if i < len(updatedAt) {
			cs = updatedAt[i]
		}
		var act string
		if i < len(actions) {
			act = actions[i]
		}
		out[i] = extraRule{Pattern: p, Title: t, Enabled: !isDisabled, CreatedAt: ts, UpdatedAt: cs, Action: act}
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
	case "global", "network", "ua-filter", "ja4-verdicts", "honeypot", "bypass-ips", "bypass-paths", "web-bot-auth", "privacy-pass", "protected", "captcha", "challenge", "rate_limit", "deny_design", "theme", "branding", "appearance", "notifications", "smtp", "retention", "performance", "community-bans", "sites", "about", "geo", "asn":
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
	// The SQLite memory budget is baked into the DSN when the pool opens, so a
	// change here is start-only exactly like the listen settings above.
	beforeDB := cur.DB
	switch section {
	case "global":
		cur.Global.Passthrough = r.FormValue("global_passthrough") == "1"
		// Monitor mode lives on the challenge record (it is resolved per site by
		// both deploy paths), but the operator meets it here, beside the other
		// switch that suppresses the challenge.
		cur.Challenge.Default.ObserveOnly = settings.BoolPtr(r.FormValue("global_observe_only") == "1")
		validBucket := func(v string) string {
			v = strings.TrimSpace(v)
			if v == "pass" || settings.IsValidRateChallengeMode(v) {
				return v
			}
			// Unset/garbage stores "" = the strict built-in default
			// (pow_only).  The old fallback was "pass", which turned a
			// malformed POST into a fail-open wave-through.
			return ""
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
		// Header-integrity axis: toggle + optional action (pow_only / captcha_only
		// / pow_then_captcha -- deny is never accepted here; a blank / anything else
		// stores unset so HeaderIntegrityResolvedAction applies its captcha_only
		// default).
		cur.Global.HeaderIntegrity = r.FormValue("header_integrity") == "1"
		switch strings.TrimSpace(r.FormValue("header_integrity_action")) {
		case settings.RateChallengePoWOnly, settings.RateChallengeCaptchaOnly, settings.RateChallengePoWThenCaptcha:
			cur.Global.HeaderIntegrityAction = strings.TrimSpace(r.FormValue("header_integrity_action"))
		default:
			cur.Global.HeaderIntegrityAction = ""
		}
		parseIntInRange := func(v string, lo, hi int) int {
			n, err := strconv.Atoi(strings.TrimSpace(v))
			if err != nil || n < lo || n > hi {
				return 0
			}
			return n
		}
		cur.Global.CurrentChromeMajor = parseIntInRange(r.FormValue("current_chrome_major"), 1, 999)
		cur.Global.CurrentFirefoxMajor = parseIntInRange(r.FormValue("current_firefox_major"), 1, 999)
		// Lags follow the same auto/manual convention as the currents: the
		// number input is disabled (= not submitted) on "auto", so a blank
		// stores 0 -- Chrome resolves to the built-in default, Firefox follows
		// the Chrome-side lag (FirefoxStaleLagN).
		cur.Global.StaleBrowserLag = parseIntInRange(r.FormValue("stale_browser_lag"), 1, 99)
		cur.Global.StaleBrowserLagFirefox = parseIntInRange(r.FormValue("stale_browser_lag_firefox"), 1, 99)
		if a := strings.TrimSpace(r.FormValue("stale_browser_action")); settings.IsValidRateChallengeMode(a) && a != "pass" {
			cur.Global.StaleBrowserAction = a
		} else {
			cur.Global.StaleBrowserAction = ""
		}
		// Black-list default action (= independent of rate-limit chain).  A
		// blank/invalid value RESETS to unset so the picker's "(unset)" option
		// round-trips: a tab save without an explicit choice must not pin the
		// displayed fallback (that pin is how every fleet node ended up with
		// pow_then_captcha here).
		if v := strings.TrimSpace(r.FormValue("ua_black_action")); settings.IsValidRateChallengeMode(v) {
			cur.Nginx.ChallengeTargets.DefaultAction = v
		} else {
			cur.Nginx.ChallengeTargets.DefaultAction = ""
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
		if raw := strings.TrimSpace(r.FormValue("roaming_cap")); raw == "" {
			// Blank field = unset: track MaxEntriesResolved's ceiling default.
			cur.Rebind.MaxEntries = 0
		} else if v, err := strconv.Atoi(raw); err == nil {
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
		// Country-axis exempt paths (RSS feeds etc.) live on the geo tab.
		if err := applyExemptPathsForm(&cur.Nginx.Geo.ExemptPaths, "gx", r, lang); err != nil {
			redirBack(err.Error())
			return
		}
	case "asn":
		if err := applyAsnForm(&cur.Nginx.Asn, r); err != nil {
			redirBack(err.Error())
			return
		}
		// ASN-axis exempt paths (RSS feeds etc.) live on the ASN tab.
		if err := applyExemptPathsForm(&cur.Nginx.Asn.ExemptPaths, "ax", r, lang); err != nil {
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
		cur.Branding.Default.Theme = t
		cur.Branding.Default.CustomColors = parseChallengeCustomColors(r)
	case "branding":
		// Branding tab save: applyBrandingFormV2 updates Default + Sites
		// from the same form payload.  See settings.Branding for the data
		// shape and handlers.go ServeBrandingLogo for the logo serve path.
		if err := applyBrandingFormV2(&cur.Branding, r); err != nil {
			redirBack(err.Error())
			return
		}
	case "appearance":
		// Combined save for the theme tab: branding identity + copy preset
		// + theme card + "show credit" badge.  Multiple forms with multiple
		// save buttons on the same page confused operators; appearance
		// dispatches them all from one button press.  All operate on the
		// Default record.
		if err := applyBrandingFormV2(&cur.Branding, r); err != nil {
			redirBack(err.Error())
			return
		}
		t := strings.TrimSpace(r.FormValue("theme"))
		if !challengeThemes[t] {
			t = "auto"
		}
		cur.Branding.Default.Theme = t
		cur.Branding.Default.CustomColors = parseChallengeCustomColors(r)
		// show_credit was previously on the challenge tab; now lives next
		// to the theme cards so the operator sees the live preview toggle
		// alongside it.  Plain checkbox -> bool.
		cur.Branding.Default.ShowCredit = settings.BoolPtr(r.FormValue("show_credit") == "1")
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
	case "performance":
		// Resource dials.  The DB knobs are baked into the DSN when the pool
		// opens, so a change there is start-only (beforeDB comparison below sets
		// the restart flag); the event-flusher knobs hot-reload.
		if v := strings.TrimSpace(r.FormValue("perf_profile")); v != "" {
			switch v {
			case settings.PerfProfileConservative, settings.PerfProfileStandard,
				settings.PerfProfileGenerous, settings.PerfProfileCustom:
				cur.DB.PerfProfile = v
			}
		}
		// Custom-only fields.  Parsed whenever present so switching profile and
		// editing the numbers in one save works, but they only take effect under
		// the custom profile (see db.sqlitePerConnBytesFor).
		if _, present := r.Form["sqlite_cache_mb"]; present {
			v, err := strconv.Atoi(strings.TrimSpace(r.FormValue("sqlite_cache_mb")))
			if err != nil || v < 0 {
				v = 0 // blank / garbage -> fall back to the derived budget
			} else if v > 2048 {
				v = 2048
			}
			cur.DB.SQLiteCacheMB = v
		}
		if _, present := r.Form["db_max_conns"]; present {
			v, err := strconv.Atoi(strings.TrimSpace(r.FormValue("db_max_conns")))
			if err != nil || v < 0 {
				v = 0 // blank -> derive from CPUs
			} else if v > 32 {
				v = 32
			}
			cur.DB.MaxConns = v
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

		// nginx_log_enabled toggle. To apply, the next render-nginx + nginx
		// reload + admin service restart (= socket bind close/reopen) is
		// required. We don't toggle this on the fly (= the recvLoop goroutine's
		// running state is not changed by design).
		cur.NginxLog.Enabled = r.FormValue("nginx_log_enabled") == "1"
	}

	// Record the admin version at the moment the user saves the settings page.
	// On the next render, presets with AddedIn newer than this are treated as
	// new (= forced OFF + NEW badge).  A dev / RC build carries a
	// "MAJOR.MINOR.PATCH-<git-hash>" Version; parseVer strips the suffix, so it
	// stamps and orders by its release number (reviewing that release's presets
	// while still badging a later release's).  A bare-git-hash build stays
	// unparseable and keeps the previous SeenVersion.
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
	// OR, never assign: a section handler above may already have flagged its own
	// start-only change (the SQLite memory budget is baked into the DSN when the
	// pool opens), and a plain assignment here would silently drop that.
	unmaskRestartNeeded = cur.Server != beforeServer || cur.DB != beforeDB

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
	allow, allowNotes, allowDis, allowCr, allowUp := formListWithNotesEnabled(r.Form["admin_allowed_ips"], r.Form["admin_allowed_ips_title"], r.Form["admin_allowed_ips_enabled"], r.Form["admin_allowed_ips_created_at"], r.Form["admin_allowed_ips_updated_at"])
	for _, a := range allow {
		if !ipOrCIDRRE.MatchString(a) {
			return fmt.Errorf("%s", i18n.Tf(lang, "err.admin_allow_invalid", a))
		}
	}
	// The gate only enforces enabled rows, so the lockout check must judge the
	// same subset: disabling the one row that admits the operator is exactly
	// as much a lockout as deleting it -- unless the list goes effectively
	// empty, which (like an empty list) means "no restriction".
	if act := settings.EnabledValues(allow, allowDis); len(act) > 0 && !ipAllowed(curIP, act) {
		return fmt.Errorf("%s", i18n.Tf(lang, "err.admin_lockout_ip", curIP))
	}
	n.AdminAllowedIPs = allow
	n.AdminAllowedIPsTitle = allowNotes
	n.AdminAllowedIPsCreatedAt = allowCr
	n.AdminAllowedIPsUpdatedAt = allowUp
	n.AdminAllowedIPsDisabled = allowDis

	// Host allowlist (= which domains may reach /admin/* when one nginx serves
	// many vhosts).  Matched in-app, never written to nginx config, so no
	// injection guard is needed beyond the self-lockout check.
	hosts, hostNotes, hostDis, hostsCr, hostsUp := formListWithNotesEnabled(r.Form["admin_allowed_hosts"], r.Form["admin_allowed_hosts_title"], r.Form["admin_allowed_hosts_enabled"], r.Form["admin_allowed_hosts_created_at"], r.Form["admin_allowed_hosts_updated_at"])
	if act := settings.EnabledValues(hosts, hostDis); len(act) > 0 && !hostAllowed(curHost, act) {
		return fmt.Errorf("%s", i18n.Tf(lang, "err.admin_lockout_host", curHost))
	}
	n.AdminAllowedHosts = hosts
	n.AdminAllowedHostsTitle = hostNotes
	n.AdminAllowedHostsCreatedAt = hostsCr
	n.AdminAllowedHostsUpdatedAt = hostsUp
	n.AdminAllowedHostsDisabled = hostDis

	mallow, mallowNotes, mallowDis, mallowCr, mallowUp := formListWithNotesEnabled(r.Form["metrics_allow_from"], r.Form["metrics_allow_from_title"], r.Form["metrics_allow_from_enabled"], r.Form["metrics_allow_from_created_at"], r.Form["metrics_allow_from_updated_at"])
	for _, a := range mallow {
		if !ipOrCIDRRE.MatchString(a) {
			return fmt.Errorf("%s", i18n.Tf(lang, "err.metrics_allow_invalid", a))
		}
	}
	n.MetricsAllowFrom = mallow
	n.MetricsAllowFromTitle = mallowNotes
	n.MetricsAllowFromCreatedAt = mallowCr
	n.MetricsAllowFromUpdatedAt = mallowUp
	n.MetricsAllowFromDisabled = mallowDis
	return nil
}

// formListWithNotesEnabled sanitizes the per-row values of a structured list
// field (= the value-rule-list UI) together with each row's note and enabled
// flag ("<name>_enabled" hidden inputs, "0" = off): trim, drop empty, dedup,
// reject control chars / quotes (an nginx-config-injection guard), order
// preserved.  The three slices ride the same index, so a dropped value must
// drop its note and flag too -- filtering them independently would slide
// every toggle onto the wrong row, and a toggle (or note) on the wrong
// address is worse than none.  Notes are stripped of the characters that
// would break the YAML the config is written as.  disabled comes back nil
// when every surviving row is enabled, keeping untouched configs in their
// old yml shape.
func formListWithNotesEnabled(vals, notes, enabled, created, updated []string) (
	outVals, outNotes []string, outDisabled []bool, outCreated, outUpdated []int64,
) {
	noteClean := strings.NewReplacer("\n", " ", "\r", " ", "\"", "'", "\\", "/")
	seen := map[string]bool{}
	anyOff := false
	anyDate := false
	now := time.Now().Unix()
	for i, v := range vals {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			continue
		}
		if strings.ContainsAny(v, "\"\\\x00\r\n") {
			continue
		}
		seen[v] = true
		note := ""
		if i < len(notes) {
			note = noteClean.Replace(strings.TrimSpace(notes[i]))
		}
		off := i < len(enabled) && enabled[i] == "0"
		var cr, up int64
		if i < len(created) {
			cr, _ = strconv.ParseInt(strings.TrimSpace(created[i]), 10, 64)
		}
		if i < len(updated) {
			up, _ = strconv.ParseInt(strings.TrimSpace(updated[i]), 10, 64)
		}
		if cr <= 0 {
			cr = now
		}
		up = clampUpdatedAt(up, cr, now)
		outVals = append(outVals, v)
		outNotes = append(outNotes, note)
		outDisabled = append(outDisabled, off)
		outCreated = append(outCreated, cr)
		outUpdated = append(outUpdated, up)
		anyOff = anyOff || off
		anyDate = anyDate || up > 0
	}
	if !anyDate {
		outUpdated = nil
	}
	if !anyOff {
		outDisabled = nil
	}
	return outVals, outNotes, outDisabled, outCreated, outUpdated
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
	ID       string
	Label    string
	CIDRs    string
	Header   string
	Disabled bool
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
			ID:       e.ID,
			Label:    e.Label,
			CIDRs:    strings.Join(e.CIDRs, ", "),
			Header:   nginxconf.HeaderFromNginxVar(e.Header),
			Disabled: e.Disabled,
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
	labels := r.Form["lb_extra_label"]
	ens := r.Form["lb_extra_enabled"]
	maxLen := len(ids)
	for _, l := range []int{len(cidrs), len(hdrs)} {
		if l > maxLen {
			maxLen = l
		}
	}
	extras := make([]settings.TrustedLBExtra, 0, maxLen)
	for i := 0; i < maxLen; i++ {
		var id, c, h, label string
		off := false
		if i < len(ids) {
			id = strings.TrimSpace(ids[i])
		}
		if i < len(cidrs) {
			c = strings.TrimSpace(cidrs[i])
		}
		if i < len(hdrs) {
			h = strings.TrimSpace(hdrs[i])
		}
		if i < len(labels) {
			label = strings.TrimSpace(labels[i])
		}
		if i < len(ens) {
			off = ens[i] == "0"
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
			ID:       id,
			Label:    label,
			CIDRs:    cidrList,
			Header:   nginxconf.NginxVarFromHeader(h),
			Disabled: off,
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
	// Auto-update: a plain checkbox, so absence means off.  Only meaningful in
	// the managed (dbip) mode -- the custom-path mode's file belongs to the
	// operator and AutoUpdateStale skips it regardless of this flag.
	g.AutoUpdate = r.FormValue("ipgeo_auto_update") != ""
	g.AutoUpdateASN = r.FormValue("ipgeo_auto_update_asn") != ""
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
	n.SearchBots.Extra, n.SearchBots.ExtraTitle, n.SearchBots.ExtraDisabled, n.SearchBots.ExtraCreatedAt, n.SearchBots.ExtraUpdatedAt, _ = pairExtras(
		r.Form["white_extra"], r.Form["white_extra_title"], r.Form["white_extra_enabled"], r.Form["white_extra_created_at"], r.Form["white_extra_updated_at"], nil)

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

	// Explicit UA-string rescue opt-in for range-backed patterns.  The
	// submit JS mirrors every range-backed checkbox into exactly one of the
	// two hidden lists (checked -> upstream_ua_enabled, unchecked ->
	// upstream_disabled), so a saved UA-filter tab is fully explicit and the
	// preset-driven auto default (uarange.go) no longer applies to it.
	// Non-range-backed patterns are dropped: UA rescue is their only path,
	// so listing them would be dead weight in the YAML.
	seenUA := map[string]bool{}
	uaEnabled := []string{}
	for _, p := range r.Form["upstream_ua_enabled"] {
		p = strings.TrimSpace(p)
		if p == "" || seenUA[p] || seen[p] || nginxconf.RangeVerifiedPresetIDs(p) == nil {
			continue
		}
		seenUA[p] = true
		uaEnabled = append(uaEnabled, p)
	}
	n.SearchBots.UpstreamUAEnabled = uaEnabled

	// Standing policy: refuse the UA-string rescue for every vendor that
	// publishes an egress range.  Kept separate from the per-pattern lists
	// above so turning it off restores them untouched -- they are still in
	// the config, just outranked while this is on (EffectiveUpstreamUAOff).
	// Store only the departure from the default.  Unset already means on, so
	// writing an explicit `true` would add a line to every config the moment
	// this tab is saved -- and a save that changes the file without changing
	// anything is exactly what the no-op-save guard exists to catch.
	if r.FormValue("require_range_verification") == "1" {
		n.SearchBots.RequireRangeVerification = nil
	} else {
		n.SearchBots.RequireRangeVerification = settings.BoolPtr(false)
	}

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
	// ChallengeTargets.All has NO control on this form (the black_all checkbox
	// was removed with the preset overhaul), so the save must not touch it —
	// reading the absent field here forced All=false on every ua-filter save,
	// silently flipping a config-file-managed all:true install.
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
	n.ChallengeTargets.Extra, n.ChallengeTargets.ExtraTitle, n.ChallengeTargets.ExtraDisabled, n.ChallengeTargets.ExtraCreatedAt, n.ChallengeTargets.ExtraUpdatedAt, n.ChallengeTargets.ExtraAction = pairExtras(
		r.Form["black_extra"], r.Form["black_extra_title"], r.Form["black_extra_enabled"], r.Form["black_extra_created_at"], r.Form["black_extra_updated_at"], r.Form["black_extra_action"])
}

// crawlerVerifyRow is one rDNS-verifiable crawler for the settings card: its
// name, whether a range preset usually covers it (informational), and the
// operator's per-crawler enable state.
type crawlerVerifyRow struct {
	Name        string
	RangeBacked bool
	Active      bool
}

func crawlerVerifyCrawlerRows(cv settings.CrawlerVerifyConfig) []crawlerVerifyRow {
	cs := crawlerverify.Crawlers()
	rows := make([]crawlerVerifyRow, len(cs))
	for i, c := range cs {
		rows[i] = crawlerVerifyRow{Name: c.Name, RangeBacked: c.RangeBacked, Active: cv.CrawlerActive(c.Name)}
	}
	return rows
}

// applyBypassIPsForm: receive the bypass-ips tab form. Zip the row-UI 4
// parallel arrays (ip + title + enabled + updated_at) into the BypassIPs*
// 4 slices for save.
func applyBypassIPsForm(n *settings.Nginx, r *http.Request, lang i18n.Lang) error {
	ips := r.Form["bypass_ip"]
	titles := r.Form["bypass_title"]
	enabled := r.Form["bypass_enabled"]
	createdAtArr := r.Form["bypass_created_at"]
	updatedAtArr := r.Form["bypass_updated_at"]
	maxLen := len(ips)
	for _, l := range []int{len(titles), len(enabled), len(createdAtArr)} {
		if l > maxLen {
			maxLen = l
		}
	}
	outIP := make([]string, 0, maxLen)
	outTitle := make([]string, 0, maxLen)
	outDisabled := make([]bool, 0, maxLen)
	outUpdated := make([]int64, 0, maxLen)
	outChanged := make([]int64, 0, len(outUpdated))
	now := time.Now().Unix()
	for i := 0; i < maxLen; i++ {
		var ip, t string
		isEnabled := true
		var ts, cs int64
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
		if i < len(createdAtArr) {
			ts, _ = strconv.ParseInt(strings.TrimSpace(createdAtArr[i]), 10, 64)
		}
		if i < len(updatedAtArr) {
			cs, _ = strconv.ParseInt(strings.TrimSpace(updatedAtArr[i]), 10, 64)
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
		outChanged = append(outChanged, clampUpdatedAt(cs, ts, now))
	}
	n.BypassIPs = outIP
	n.BypassIPsTitle = outTitle
	n.BypassIPsDisabled = outDisabled
	n.BypassIPsCreatedAt = outUpdated
	n.BypassIPsUpdatedAt = outChanged

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

	// Reverse-DNS crawler verification (rDNS): the DNS-based sibling of the
	// IP-range presets above -- verify a crawler-claiming UA against its vendor's
	// published rDNS instead of a static range.
	n.CrawlerVerify.Enabled = r.FormValue("crawler_verify_enabled") == "1"
	fa := strings.TrimSpace(r.FormValue("crawler_verify_forged_action"))
	if fa != "" && !settings.IsValidGeoAction(fa) {
		fa = ""
	}
	// pow_then_captcha IS ResolvedForgedAction's default -- store the
	// non-deviation as unset so re-saving the rendered form is a no-op.
	if fa == settings.GeoActionPoWThenCaptcha {
		fa = ""
	}
	n.CrawlerVerify.ForgedAction = fa

	// Per-crawler enable state.  The card renders a checkbox per catalog crawler
	// (value = its name, checked = verified); a name absent from the submitted set
	// is disabled.  Gated on a presence marker so a form that doesn't render the
	// card can't wipe the setting.
	if r.FormValue("crawler_verify_present") == "1" {
		enabled := map[string]bool{}
		for _, name := range r.Form["crawler_verify_crawler"] {
			enabled[strings.TrimSpace(name)] = true
		}
		var disabled []string
		for _, ci := range crawlerverify.Crawlers() {
			if !enabled[ci.Name] {
				disabled = append(disabled, ci.Name)
			}
		}
		n.CrawlerVerify.DisabledCrawlers = disabled
	}

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
	createdAtArr := r.Form["honeypot_url_created_at"]
	updatedAtArr := r.Form["honeypot_url_updated_at"]
	sites := r.Form["honeypot_url_site"]
	actions := r.Form["honeypot_url_action"]
	maxLen := len(pats)
	for _, l := range []int{len(titles), len(enabled), len(createdAtArr), len(sites), len(actions)} {
		if l > maxLen {
			maxLen = l
		}
	}
	urls := make([]settings.HoneypotURL, 0, maxLen)
	now := time.Now().Unix()
	for i := 0; i < maxLen; i++ {
		var p, t, site, action string
		isEnabled := true
		var ts, cs int64
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
		if i < len(createdAtArr) {
			ts, _ = strconv.ParseInt(strings.TrimSpace(createdAtArr[i]), 10, 64)
		}
		if i < len(updatedAtArr) {
			cs, _ = strconv.ParseInt(strings.TrimSpace(updatedAtArr[i]), 10, 64)
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
			CreatedAt: ts,
			UpdatedAt: clampUpdatedAt(cs, ts, now),
			Site:      site,
		})
	}
	n.Honeypot.URLs = urls

	// honeypot default action (= chain for trips).
	// Blank/invalid resets to unset (= the picker's "(unset)" option) so a
	// no-op tab save cannot pin the displayed fallback.
	if v := strings.TrimSpace(r.FormValue("honeypot_default_action")); settings.IsValidRateChallengeMode(v) {
		n.Honeypot.DefaultAction = v
	} else {
		n.Honeypot.DefaultAction = ""
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
// (cleaned_patterns, titles, disabled, createdAt).
//   - drop rows where pattern is empty
//   - drop rows where pattern contains control chars / quotes
//   - drop rows where pattern fails to compile as regex
//   - title is trimmed; control chars are replaced with spaces
//   - enabled = "1" → enabled; otherwise disabled
//   - createdAt is unix sec. "0" / empty / invalid is filled with now
//     (= new row or when JS overwrites with 0 on "dirty" detection)
//
// actions is nil for the lists whose rows carry no chain of their own (the
// allowlist: a rescued UA is not challenged, so there is nothing to pick).
func pairExtras(patterns, titles, enabled, createdAt, updatedAt, actions []string) ([]string, []string, []bool, []int64, []int64, []string) {
	maxLen := len(patterns)
	if len(titles) > maxLen {
		maxLen = len(titles)
	}
	if len(enabled) > maxLen {
		maxLen = len(enabled)
	}
	if len(createdAt) > maxLen {
		maxLen = len(createdAt)
	}
	outP := make([]string, 0, maxLen)
	outT := make([]string, 0, maxLen)
	outD := make([]bool, 0, maxLen)
	outU := make([]int64, 0, maxLen)
	outC := make([]int64, 0, maxLen)
	outA := make([]string, 0, maxLen)
	now := time.Now().Unix()
	for i := 0; i < maxLen; i++ {
		var p, t string
		isEnabled := true
		var ts, cs int64
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
		if i < len(createdAt) {
			ts, _ = strconv.ParseInt(strings.TrimSpace(createdAt[i]), 10, 64)
		}
		if i < len(updatedAt) {
			cs, _ = strconv.ParseInt(strings.TrimSpace(updatedAt[i]), 10, 64)
		}
		if p == "" {
			continue
		}
		// A literal pattern is escaped at render time, so the regex rules
		// below do not apply to it -- only the characters that would break
		// the config file itself.
		if settings.IsLiteralPattern(p) {
			if strings.ContainsAny(p, "\x00\r\n") {
				continue
			}
		} else {
			if strings.ContainsAny(p, "\"\\\x00\r\n") {
				continue
			}
			if _, err := regexp.Compile(p); err != nil {
				continue
			}
		}
		if ts <= 0 {
			ts = now
		}
		// An unknown chain reads as "inherit" rather than being kept: the row
		// would otherwise claim an action nothing implements.
		act := ""
		if i < len(actions) {
			act = strings.TrimSpace(actions[i])
			if !settings.IsValidRateChallengeMode(act) {
				act = ""
			}
		}
		outP = append(outP, p)
		outT = append(outT, t)
		outD = append(outD, !isEnabled)
		outU = append(outU, ts)
		outC = append(outC, clampUpdatedAt(cs, ts, now))
		outA = append(outA, act)
	}
	// All-empty is the common case (nobody pinned a chain); drop it so the
	// YAML does not carry a column of "".
	allEmpty := true
	for _, a := range outA {
		if a != "" {
			allEmpty = false
			break
		}
	}
	if allEmpty {
		outA = nil
	}
	return outP, outT, outD, outU, outC, outA
}

// clampUpdatedAt keeps an edit timestamp inside [added, now].  The value is
// stamped by the row UI when the operator confirms an edit, so it arrives from
// the form: a bad one should read as "not edited" rather than as a date before
// the row existed or one in the future.
func clampUpdatedAt(changed, added, now int64) int64 {
	if changed <= 0 || changed < added || changed > now {
		return 0
	}
	return changed
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
	createdAtArr := r.Form["ja4_extra_created_at"]
	updsUpdated := r.Form["ja4_extra_updated_at"]
	ids := r.Form["ja4_extra_id"] // hidden input for ID-based linking; existing entries keep their ID.
	maxLen := len(pats)
	for _, l := range []int{len(verds), len(acts), len(titles), len(enabledArr), len(createdAtArr), len(ids)} {
		if l > maxLen {
			maxLen = l
		}
	}
	extras := make([]settings.JA4VerdictExtraRule, 0, maxLen)
	outTitles := make([]string, 0, maxLen)
	outDisabled := make([]bool, 0, maxLen)
	outUpdated := make([]int64, 0, maxLen)
	outChanged := make([]int64, 0, maxLen)
	now := time.Now().Unix()
	for i := 0; i < maxLen; i++ {
		var p, v, a, t string
		isEnabled := true
		var ts, cs int64
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
		if i < len(createdAtArr) {
			ts, _ = strconv.ParseInt(strings.TrimSpace(createdAtArr[i]), 10, 64)
		}
		if i < len(updsUpdated) {
			cs, _ = strconv.ParseInt(strings.TrimSpace(updsUpdated[i]), 10, 64)
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
		outChanged = append(outChanged, clampUpdatedAt(cs, ts, now))
	}
	n.JA4Verdicts.Extra = extras
	n.JA4Verdicts.ExtraTitle = outTitles
	n.JA4Verdicts.ExtraDisabled = outDisabled
	n.JA4Verdicts.ExtraCreatedAt = outUpdated
	n.JA4Verdicts.ExtraUpdatedAt = outChanged

	// JA4 default action (= challenge chain when ja4 hits action=bot).
	// Blank/invalid resets to unset (= the picker's "(unset)" option) so a
	// no-op tab save cannot pin the displayed fallback.
	if v := strings.TrimSpace(r.FormValue("ja4_default_action")); settings.IsValidRateChallengeMode(v) {
		n.JA4Verdicts.DefaultAction = v
	} else {
		n.JA4Verdicts.DefaultAction = ""
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
	createdAtArr := r.Form["protected_created_at"]
	updatedAtArr := r.Form["protected_updated_at"]
	modes := r.Form["protected_mode"]
	sites := r.Form["protected_site"]
	actions := r.Form["protected_action"]
	maxLen := len(pats)
	for _, l := range []int{len(titles), len(enabledArr), len(createdAtArr), len(modes), len(sites), len(actions)} {
		if l > maxLen {
			maxLen = l
		}
	}
	rows := make([]settings.ProtectedPath, 0, maxLen)
	now := time.Now().Unix()
	for i := 0; i < maxLen; i++ {
		var p, t, mode, site, action string
		isEnabled := true
		var ts, cs int64
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
		if i < len(createdAtArr) {
			ts, _ = strconv.ParseInt(strings.TrimSpace(createdAtArr[i]), 10, 64)
		}
		if i < len(updatedAtArr) {
			cs, _ = strconv.ParseInt(strings.TrimSpace(updatedAtArr[i]), 10, 64)
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
			CreatedAt: ts,
			UpdatedAt: clampUpdatedAt(cs, ts, now),
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
	// Blank/invalid resets to unset (= the picker's "(unset)" option) so a
	// no-op tab save cannot pin the displayed fallback.
	if v := strings.TrimSpace(r.FormValue("protected_default_action")); settings.IsValidRateChallengeMode(v) {
		n.ProtectedPaths.DefaultAction = v
	} else {
		n.ProtectedPaths.DefaultAction = ""
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
	CreatedAt int64
	UpdatedAt int64 // unix sec of the last edit, 0 while untouched
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
			CreatedAt: r.CreatedAt,
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
			CreatedAt: r.CreatedAt,
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
	CreatedAt int64
	UpdatedAt int64 // unix sec of the last edit, 0 while untouched
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
			CreatedAt: r.CreatedAt,
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
	createdAtArr := r.Form["bp_created_at"]
	updatedAtArr := r.Form["bp_updated_at"]
	sites := r.Form["bp_site"]
	maxLen := len(pats)
	for _, l := range []int{len(titles), len(rowEnabled), len(createdAtArr), len(sites)} {
		if l > maxLen {
			maxLen = l
		}
	}
	rows := make([]settings.BypassPath, 0, maxLen)
	now := time.Now().Unix()
	for i := 0; i < maxLen; i++ {
		var p, t, site string
		isEnabled := true
		var ts, cs int64
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
		if i < len(createdAtArr) {
			ts, _ = strconv.ParseInt(strings.TrimSpace(createdAtArr[i]), 10, 64)
		}
		if i < len(updatedAtArr) {
			cs, _ = strconv.ParseInt(strings.TrimSpace(updatedAtArr[i]), 10, 64)
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
			CreatedAt: ts,
			UpdatedAt: clampUpdatedAt(cs, ts, now),
			Site:      site,
		})
	}
	n.BypassPaths.Paths = rows
	return nil
}

// applyExemptPathsForm: receive one per-axis exempt-path list (geo tab uses
// prefix "gx", asn tab "ax").  Same row shape as the bypass-paths rows --
// <prefix>_path / _title / _enabled / _updated_at / _site zipped into
// BypassPath -- but no presets, and written to the axis's ExemptPaths (drops
// only that axis) instead of BypassPaths (which vetoes every judgment).
func applyExemptPathsForm(dst *[]settings.BypassPath, prefix string, r *http.Request, lang i18n.Lang) error {
	pats := r.Form[prefix+"_path"]
	titles := r.Form[prefix+"_title"]
	rowEnabled := r.Form[prefix+"_enabled"]
	createdAtArr := r.Form[prefix+"_created_at"]
	updatedAtArr := r.Form[prefix+"_updated_at"]
	sites := r.Form[prefix+"_site"]
	maxLen := len(pats)
	for _, l := range []int{len(titles), len(rowEnabled), len(createdAtArr), len(sites)} {
		if l > maxLen {
			maxLen = l
		}
	}
	rows := make([]settings.BypassPath, 0, maxLen)
	now := time.Now().Unix()
	for i := 0; i < maxLen; i++ {
		var p, t, site string
		isEnabled := true
		var ts, cs int64
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
		if i < len(createdAtArr) {
			ts, _ = strconv.ParseInt(strings.TrimSpace(createdAtArr[i]), 10, 64)
		}
		if i < len(updatedAtArr) {
			cs, _ = strconv.ParseInt(strings.TrimSpace(updatedAtArr[i]), 10, 64)
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
			CreatedAt: ts,
			UpdatedAt: clampUpdatedAt(cs, ts, now),
			Site:      site,
		})
	}
	*dst = rows
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
	createdAtArr := r.Form["re_created_at"]
	updatedAtArr := r.Form["re_updated_at"]
	maxLen := len(pats)
	for _, l := range []int{len(types), len(titles), len(rowEnabled), len(createdAtArr)} {
		if l > maxLen {
			maxLen = l
		}
	}
	rows := make([]settings.HTTPSRedirectExemptRule, 0, maxLen)
	now := time.Now().Unix()
	for i := 0; i < maxLen; i++ {
		var typ, p, t string
		isEnabled := true
		var ts, cs int64
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
		if i < len(createdAtArr) {
			ts, _ = strconv.ParseInt(strings.TrimSpace(createdAtArr[i]), 10, 64)
		}
		if i < len(updatedAtArr) {
			cs, _ = strconv.ParseInt(strings.TrimSpace(updatedAtArr[i]), 10, 64)
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
			CreatedAt: ts,
			UpdatedAt: clampUpdatedAt(cs, ts, now),
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
	CreatedAt int64
	UpdatedAt int64 // unix sec of the last edit, 0 while untouched
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
	} else {
		// Blank field = unset: track ResolvedPowDifficulty's built-in default
		// instead of pinning today's number.
		c.PowDifficulty = 0
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
		c.PublicTestPages = settings.BoolPtr(r.FormValue("public_test_pages") == "1")
		// Optional Basic Auth password.  Only honored when PublicTestPages
		// is on, but persist the value regardless so toggling the checkbox
		// back on doesn't silently lose what the operator typed.
		c.PublicTestPagesPassword = strings.TrimSpace(r.FormValue("public_test_pages_password"))
	}
	// public_test_pages_site_picker: same hidden-marker pattern as above.
	if r.FormValue("public_test_pages_site_picker_present") != "" {
		c.PublicTestPagesSitePicker = settings.BoolPtr(r.FormValue("public_test_pages_site_picker") == "1")
	}
	return nil
}

// applyRateLimitForm: receive the rate-limit tab form. Only the default zone
// is editable here (= named zones are edited directly in yaml; UI for them
// is planned for v0.2).
// protectedLiteralPrefixes: the enforced protected-path set reduced to
// comparable literal path heads (deduped, empty heads dropped).  Feeds the
// rate-limit tab's deny-overlap warning.
func protectedLiteralPrefixes(s settings.Settings) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, r := range nginxconf.EffectiveProtectedPathRules(s) {
		p := nginxconf.ProtectedPatternLiteralPrefix(r.Pattern)
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

func applyRateLimitForm(c *settings.RateLimitConfig, r *http.Request) error {
	// The default card is an axis TABLE now: three always-visible rows (IP /
	// JA4 / IP+JA4), each an independent parallel limit with its own enable
	// toggle.  Storage stays in the pre-row shape: the PRIMARY row (first
	// enabled in ip > ip+ja4 > ja4 order) writes Key + Default exactly as the
	// old single-key form did -- an untouched install round-trips
	// byte-identically and an older binary still reads the primary correctly
	// -- while non-primary rows (and switched-off rows with tuned values)
	// live in the per-axis structs.
	type axisPost struct {
		kind string
		on   bool
		rpm  int // -1 = field left empty
		bur  int
		win  int
		mode string
	}
	readInt := func(field string, minV, maxV int) (int, error) {
		v := strings.TrimSpace(r.FormValue(field))
		if v == "" {
			return -1, nil
		}
		n, err := strconv.Atoi(v)
		if err != nil || n < minV || n > maxV {
			return 0, fmt.Errorf("%s must be an integer in %d-%d (got %q)", field, minV, maxV, v)
		}
		return n, nil
	}
	posts := make([]axisPost, 0, 3)
	for _, ax := range []struct{ kind, field string }{
		{settings.RateLimitKeyIP, "ip"},
		{settings.RateLimitKeyJA4, "ja4"},
		{settings.RateLimitKeyIPAndJA4, "ipja4"},
	} {
		p := axisPost{kind: ax.kind, on: r.FormValue("axis_"+ax.field+"_on") != ""}
		var err error
		if p.rpm, err = readInt("axis_"+ax.field+"_rpm", 1, 100000); err != nil {
			return err
		}
		if p.bur, err = readInt("axis_"+ax.field+"_burst", 0, 100000); err != nil {
			return err
		}
		if p.win, err = readInt("axis_"+ax.field+"_window", 1, 3600); err != nil {
			return err
		}
		p.mode = strings.TrimSpace(r.FormValue("axis_" + ax.field + "_chmode"))
		if p.mode != "" && !settings.IsValidRateChallengeMode(p.mode) {
			return fmt.Errorf("axis %s: challenge_mode invalid (got %q)", ax.field, p.mode)
		}
		posts = append(posts, p)
	}
	primaryIdx := -1
	for _, i := range []int{0, 2, 1} { // ip > ip+ja4 > ja4
		if posts[i].on {
			primaryIdx = i
			break
		}
	}
	if primaryIdx < 0 {
		return fmt.Errorf("%s", "rate-limit: at least one of the IP / JA4 / IP+JA4 rows must stay enabled (the default zone cannot be switched off entirely)")
	}
	pr := posts[primaryIdx]
	primaryChanged := c.ResolvedKey() != pr.kind
	if pr.kind == settings.RateLimitKeyIP {
		// "ip" IS the resolve default -- store the non-deviation as unset so
		// a no-op save leaves the config untouched.
		c.Key = ""
	} else {
		c.Key = pr.kind
	}
	setDef := func(dst *int, posted, seed int) {
		if posted >= 0 {
			*dst = posted
		} else if primaryChanged {
			// Enabled fresh with the field on its placeholder: adopt the seed
			// rather than dragging the previous axis's threshold along.
			*dst = seed
		}
	}
	setDef(&c.Default.RequestsPerMin, pr.rpm, settings.AxisSeedRPM(pr.kind))
	setDef(&c.Default.Burst, pr.bur, settings.AxisSeedBurst(pr.kind))
	setDef(&c.Default.WindowSec, pr.win, settings.AxisSeedWindowSec)
	if pr.mode != "" {
		c.Default.ChallengeMode = pr.mode
	} else if primaryChanged {
		c.Default.ChallengeMode = "" // resolves to the recommended chain
	}
	// Default.Name is fixed (= "unmask_rate"). Not editable in the UI.
	if c.Default.Name == "" {
		c.Default.Name = "unmask_rate"
	}
	for i, p := range posts {
		st := &c.IPLimit
		switch p.kind {
		case settings.RateLimitKeyJA4:
			st = &c.JA4Limit
		case settings.RateLimitKeyIPAndJA4:
			st = &c.IPJA4Limit
		}
		if i == primaryIdx {
			*st = settings.AxisLimitConfig{} // the primary lives in Key+Default only
			continue
		}
		// The mode select always posts a concrete value (no inherit option on
		// axis rows), so it carries no touched/untouched signal -- an
		// untouched row is one with no numeric input and the toggle off.
		if !p.on && p.rpm < 0 && p.bur < 0 && p.win < 0 {
			*st = settings.AxisLimitConfig{} // untouched row leaves no trace
			continue
		}
		row := settings.AxisLimitConfig{Enabled: p.on, ChallengeMode: p.mode}
		pick := func(posted, seed int) int {
			if posted >= 0 {
				return posted
			}
			if p.on {
				return seed // enabling on the placeholder adopts the documented seed
			}
			return 0
		}
		row.RequestsPerMin = pick(p.rpm, settings.AxisSeedRPM(p.kind))
		row.Burst = pick(p.bur, settings.AxisSeedBurst(p.kind))
		row.WindowSec = pick(p.win, settings.AxisSeedWindowSec)
		*st = row
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
		if name == c.Default.Name || name == settings.JA4LimitZoneName ||
			name == settings.IPLimitZoneName || name == settings.IPJA4LimitZoneName {
			return fmt.Errorf("zone name %q is reserved", name)
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
			// The pattern lands inside an nginx map key, so a quote / brace /
			// semicolon would break out of it into an arbitrary directive.
			if strings.ContainsAny(line, " \t{}#;\"\\\r\x00") {
				return fmt.Errorf("zone %s: path %q contains invalid characters", name, line)
			}
			// Same contract as the other path lists: a pattern that does not
			// compile is refused HERE, so nothing unparsable can reach the
			// render (where it would fail `nginx -t` and disable the module)
			// or MatchPath (where it would silently never match).
			if _, err := regexp.Compile(line); err != nil {
				return fmt.Errorf("zone %s: path %q is not a valid regular expression: %v", name, line, err)
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
		// key: per-zone counter-key kind.  Empty = inherit the install-wide
		// key ("ip" is NOT normalised away here: at zone level it means "pin
		// to IP even if the global key changes", which is a real choice).
		zkey := strings.TrimSpace(r.FormValue(prefix + "key"))
		if zkey != "" && !settings.IsValidRateLimitKey(zkey) {
			return fmt.Errorf("zone %s: key must be empty (inherit) or one of ip / ja4 / ip+ja4 (got %q)", name, zkey)
		}
		// The checkbox submits when ON, so its absence is what marks a
		// disabled row -- carried by an explicit "_on" field rather than
		// inverting the visible control, so the stored flag and the UI agree
		// on which way is which.
		zones = append(zones, settings.RateZone{
			Name:           name,
			RequestsPerMin: rpm,
			Burst:          burst,
			WindowSec:      window,
			PathPatterns:   paths,
			ChallengeMode:  chmode,
			Site:           site,
			Key:            zkey,
			Disabled:       strings.TrimSpace(r.FormValue(prefix+"on")) == "",
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
		// "skip" IS the resolve default (ResolvedDefaultAction) — store the
		// non-deviation as unset so a no-op save leaves the config untouched.
		if v == settings.GeoActionSkip {
			v = ""
		}
		c.DefaultAction = v
	} else {
		c.DefaultAction = ""
	}
	// Registered-rule inherit target.  pow_then_captcha IS the resolve
	// default (ResolvedDefaultRuleAction) -> store the non-deviation as unset.
	if v := strings.TrimSpace(r.FormValue("geo_default_rule_action")); v != "" {
		if !settings.IsValidGeoAction(v) {
			return fmt.Errorf("geo_default_rule_action invalid (got %q)", v)
		}
		if v == settings.RateChallengePoWThenCaptcha {
			v = ""
		}
		c.DefaultRuleAction = v
	} else {
		c.DefaultRuleAction = ""
	}

	// Default rate the geo tab inherits (registered-rule inherit action is
	// parsed above), mirroring the ASN tab.
	c.DefaultRatePerMin = 0
	if raw := strings.TrimSpace(r.FormValue("geo_default_rate")); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil && v > 0 {
			if v > 1_000_000 {
				v = 1_000_000
			}
			c.DefaultRatePerMin = v
		}
	}

	countries := r.Form["geo_country"]
	labels := r.Form["geo_label"]
	actions := r.Form["geo_action"]
	rates := r.Form["geo_rate"]
	enabledArr := r.Form["geo_enabled"]
	createdAt := r.Form["geo_created_at"]
	createdAtCh := r.Form["geo_updated_at"]

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

		var ts, cs int64
		if i < len(createdAt) {
			if n, err := strconv.ParseInt(strings.TrimSpace(createdAt[i]), 10, 64); err == nil {
				ts = n
			}
		}
		if i < len(createdAtCh) {
			if n, err := strconv.ParseInt(strings.TrimSpace(createdAtCh[i]), 10, 64); err == nil {
				cs = n
			}
		}
		if ts == 0 {
			ts = now
		}

		var label string
		if i < len(labels) {
			label = strings.TrimSpace(labels[i])
		}

		// Nullable rate: blank -> nil (inherit DefaultRatePerMin); an explicit
		// number (incl. 0 = "no throttle") -> a pointer to it.  Same as ASN.
		var rate *int
		if i < len(rates) {
			if raw := strings.TrimSpace(rates[i]); raw != "" {
				if v, err := strconv.Atoi(raw); err == nil && v >= 0 {
					if v > 1_000_000 {
						v = 1_000_000
					}
					rv := v
					rate = &rv
				}
			}
		}

		rules = append(rules, settings.GeoRule{
			Country:    code,
			Label:      label,
			Action:     action,
			RatePerMin: rate,
			Enabled:    enOn,
			CreatedAt:  ts,
			UpdatedAt:  clampUpdatedAt(cs, ts, now),
		})
	}
	c.Rules = rules
	return nil
}

// applyAsnForm: receive the ASN sub-section of the geo tab.  The by-network
// sibling of applyGeoForm — same shape, keyed by AS number instead of country
// code.
// asnProviderRow: one catalog provider as the settings UI sees it.
type asnProviderRow struct {
	ID       string
	Label    string
	Enabled  bool
	Action   string // "" = inherit default
	ASNCount int    // distinct ASNs matched in the loaded mmdb (-1 = not computed / no db)
	AddedIn  string // release the provider joined the catalog (v-form)
	IsNew    bool   // added in a release newer than the operator's SeenVersion
	RateStr  string // per-provider rate override ("" = inherit the config default)
}

// asnProviderView returns the catalog providers merged with the operator's
// current selection, plus the number of ASNs each currently matches in the
// loaded mmdb (one walk for all providers; -1 when no ASN db is loaded).
func (h *Handler) asnProviderView(cfg settings.AsnConfig) []asnProviderRow {
	seenVer := h.snapshotSettings().Nginx.SeenVersion
	sel := map[string]settings.AsnProviderSel{}
	for _, p := range cfg.Providers {
		sel[p.ID] = p
	}
	// One mmdb walk tallies matched-ASN counts per provider.
	counts := map[string]int{}
	haveCounts := false
	if h.IPGeo != nil && h.IPGeo.ASNLoaded() {
		if path := strings.TrimSpace(h.cfg().IPGeo.MMDBASNPath); path != "" {
			pats := map[string][]string{}
			for _, hp := range settings.HostingProviders {
				pats[hp.ID] = hp.OrgPatterns
			}
			if c, err := ipgeo.ASNCounts(path, pats); err == nil {
				counts = c
				haveCounts = true
			}
		}
	}
	out := make([]asnProviderRow, 0, len(settings.HostingProviders))
	for _, hp := range settings.HostingProviders {
		row := asnProviderRow{
			ID:       hp.ID,
			Label:    hp.Label,
			ASNCount: -1,
			AddedIn:  hp.AddedIn,
			IsNew:    nginxconf.PresetIsNew(seenVer, hp.AddedIn),
		}
		if s, ok := sel[hp.ID]; ok {
			row.Enabled = s.Enabled
			row.Action = s.Action
			row.RateStr = rateStr(s.RatePerMin)
		}
		if haveCounts {
			row.ASNCount = counts[hp.ID]
		}
		out = append(out, row)
	}
	return out
}

// asnCustomRow: one custom rule (exact ASN or org substring) for the UI.
type asnCustomRow struct {
	Value     string // "AS16509" for exact, or the org string
	IsOrg     bool
	Label     string
	Action    string
	RateStr   string // rate input value: "" = inherit default, "0" = no throttle, "N" = throttle
	Enabled   bool
	CreatedAt int64
	UpdatedAt int64 // unix sec of the last edit, 0 while untouched
}

// rateStr renders a nullable rate override for a form input: nil (inherit) -> "",
// an explicit value (incl. 0) -> its decimal string.
func rateStr(r *int) string {
	if r == nil {
		return ""
	}
	return strconv.Itoa(*r)
}

func asnCustomRuleView(cfg settings.AsnConfig) []asnCustomRow {
	out := make([]asnCustomRow, 0, len(cfg.Rules))
	for _, r := range cfg.Rules {
		row := asnCustomRow{Label: r.Label, Action: r.Action, RateStr: rateStr(r.RatePerMin), Enabled: r.Enabled, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt}
		if r.ASN != 0 {
			row.Value = "AS" + strconv.FormatUint(uint64(r.ASN), 10)
		} else {
			row.Value = r.Org
			row.IsOrg = true
		}
		out = append(out, row)
	}
	return out
}

func applyAsnForm(c *settings.AsnConfig, r *http.Request) error {
	if v := strings.TrimSpace(r.FormValue("asn_default_action")); v != "" {
		if !settings.IsValidGeoAction(v) {
			return fmt.Errorf("asn_default_action invalid (got %q)", v)
		}
		if v == settings.GeoActionSkip {
			v = "" // "skip" is the resolve default; store as unset (no-op save clean)
		}
		c.DefaultAction = v
	} else {
		c.DefaultAction = ""
	}

	// Registered-rule inherit target.  pow_then_captcha IS the resolve
	// default (ResolvedDefaultRuleAction) -> store the non-deviation as unset.
	if v := strings.TrimSpace(r.FormValue("asn_default_rule_action")); v != "" {
		if !settings.IsValidGeoAction(v) {
			return fmt.Errorf("asn_default_rule_action invalid (got %q)", v)
		}
		if v == settings.RateChallengePoWThenCaptcha {
			v = ""
		}
		c.DefaultRuleAction = v
	} else {
		c.DefaultRuleAction = ""
	}

	// Default rate: blank / 0 -> no default throttle.  A rule/provider inherits
	// this when its own rate is left blank (nil), mirroring DefaultAction.
	c.DefaultRatePerMin = 0
	if raw := strings.TrimSpace(r.FormValue("asn_default_rate")); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil && v > 0 {
			if v > 1_000_000 {
				v = 1_000_000
			}
			c.DefaultRatePerMin = v
		}
	}

	// ── preset providers (catalog) ───
	// One checkbox + action select per catalog provider.  Store only enabled
	// ones (or ones with a non-inherit action, so a toggled-off provider that
	// carried an action round-trips its choice); a fully-default+disabled
	// provider is dropped to keep the YAML tidy.
	providers := make([]settings.AsnProviderSel, 0, len(settings.HostingProviders))
	for _, hp := range settings.HostingProviders {
		enOn := r.FormValue("asn_provider_enabled_"+hp.ID) == "1"
		action := strings.TrimSpace(r.FormValue("asn_provider_action_" + hp.ID))
		if action != "" && !settings.IsValidGeoAction(action) {
			return fmt.Errorf("provider %s: action invalid (got %q)", hp.ID, action)
		}
		// Nullable rate override, same rules as the custom rows: blank -> nil
		// (inherit DefaultRatePerMin), an explicit number (incl. 0 = no throttle)
		// -> a pointer to it.
		var rate *int
		if raw := strings.TrimSpace(r.FormValue("asn_provider_rate_" + hp.ID)); raw != "" {
			if v, err := strconv.Atoi(raw); err == nil && v >= 0 {
				if v > 1_000_000 {
					v = 1_000_000
				}
				rv := v
				rate = &rv
			}
		}
		// Drop a fully-default row (disabled, inherit action, inherit rate) to
		// keep the YAML tidy; a rate override alone is enough to keep it.
		if !enOn && action == "" && rate == nil {
			continue
		}
		providers = append(providers, settings.AsnProviderSel{ID: hp.ID, Action: action, Enabled: enOn, RatePerMin: rate})
	}
	c.Providers = providers

	// ── custom rules (exact AS number OR org substring) ───
	nums := r.Form["asn_number"]  // may hold "16509", "AS16509", or an org string
	labels := r.Form["asn_label"] // parallel to the row (org rules use this too)
	actions := r.Form["asn_action"]
	rates := r.Form["asn_rate"] // per-minute cap; "" / "0" -> action every request
	enabledArr := r.Form["asn_enabled"]
	createdAt := r.Form["asn_created_at"]
	createdAtCh := r.Form["asn_updated_at"]

	rules := make([]settings.AsnRule, 0, len(nums))
	seenNum := map[uint]bool{}
	seenOrg := map[string]bool{}
	now := time.Now().Unix()
	for i, raw := range nums {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		var action string
		if i < len(actions) {
			action = strings.TrimSpace(actions[i])
		}
		if action != "" && !settings.IsValidGeoAction(action) {
			return fmt.Errorf("rule %q: action invalid (got %q)", s, action)
		}
		var label string
		if i < len(labels) {
			label = strings.TrimSpace(labels[i])
			if len([]rune(label)) > 80 {
				label = string([]rune(label)[:80])
			}
		}
		enVal := r.FormValue(fmt.Sprintf("asn_enabled_%d", i))
		if enVal == "" && i < len(enabledArr) {
			enVal = enabledArr[i]
		}
		enOn := enVal == "1"
		var ts, cs int64
		if i < len(createdAt) {
			if v, err := strconv.ParseInt(strings.TrimSpace(createdAt[i]), 10, 64); err == nil {
				ts = v
			}
		}
		if i < len(createdAtCh) {
			if v, err := strconv.ParseInt(strings.TrimSpace(createdAtCh[i]), 10, 64); err == nil {
				cs = v
			}
		}
		if ts == 0 {
			ts = now
		}
		// Nullable rate: blank -> nil (inherit DefaultRatePerMin); an explicit
		// number (incl. 0 = "no throttle") -> a pointer to it.
		var rate *int
		if i < len(rates) {
			if raw := strings.TrimSpace(rates[i]); raw != "" {
				if v, err := strconv.Atoi(raw); err == nil && v >= 0 {
					if v > 1_000_000 { // sanity cap; a per-minute rate above this is meaningless
						v = 1_000_000
					}
					rv := v
					rate = &rv
				}
			}
		}

		rule := settings.AsnRule{Label: label, Action: action, RatePerMin: rate, Enabled: enOn, CreatedAt: ts, UpdatedAt: clampUpdatedAt(cs, ts, now)}
		// "AS16509" / "16509" -> exact AS number; anything else -> org substring.
		numStr := strings.TrimPrefix(strings.TrimPrefix(s, "AS"), "as")
		if n, err := strconv.ParseUint(numStr, 10, 32); err == nil && n != 0 {
			if seenNum[uint(n)] {
				return fmt.Errorf("duplicate ASN %d", n)
			}
			seenNum[uint(n)] = true
			rule.ASN = uint(n)
		} else {
			org := s
			if len([]rune(org)) > 80 {
				org = string([]rune(org)[:80])
			}
			key := strings.ToLower(org)
			if seenOrg[key] {
				return fmt.Errorf("duplicate org rule %q", org)
			}
			seenOrg[key] = true
			rule.Org = org
		}
		rules = append(rules, rule)
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
	// Write-health probe: a real (no-op) write statement executed by THIS
	// daemon process.  A DB the daemon can read but not write is invisible from
	// the outside — challenges keep serving (config/HMAC only) while every
	// event insert fails, so stats stay empty.  The classic cause is running
	// `unmask migrate` as root, which leaves unmask.sqlite owned root:root.
	WriteChecked bool   // probe ran (false only when the DB handle is absent)
	WriteOK      bool   // the daemon can write
	WriteErr     string // short driver error when NG (e.g. "readonly database")
	DaemonUser   string // user this daemon process runs as
	DBFileOwner  string // sqlite only: "user:group" owner of the DB file
	FixCmd       string // NG + sqlite: suggested chown/restart one-liner
	// Memory plan (sqlite only): the sizing this process resolved.  Shown
	// because the numbers are derived per box (CPU count + memory limit), so an
	// operator cannot judge "is this too much for my VPS" without seeing what
	// their own daemon actually chose.
	MemPlanShow   bool
	MemConns      int
	MemPerConnStr string // e.g. "10.7 MB"
	MemTotalStr   string // EVERYTHING across the pool (cache + mmap) -- the headline figure
	MemCacheStr   string // the page-cache half (anonymous; the OOM-relevant part)
	MemMmapStr    string // mmap across the pool (file-backed, reclaimable)
	MemAutomatic  bool   // false = pinned via sqlite_cache_mb
	MemCacheMB    int    // the stored override (0 = automatic), for the form
	MemLimitStr   string // the memory limit the budget came from
	MemFromCgroup bool   // that limit was a cgroup limit, not total RAM
	MemCPUs       int    // CPUs the automatic pool sizing derives from
	MemMaxConns   int    // stored pool override (0 = CPU-derived), for the form
	MemProfileID  string // the active profile id
	// MemAutoCacheStr is the cache budget the blank ("auto") custom field
	// resolves to on THIS host, so the placeholder can name the number the
	// operator is choosing to keep.
	MemAutoCacheStr string
	// MemStandardTotalStr is what the standard profile would use here.  Shown
	// beside the custom fields so a hand-picked number has a reference point.
	MemStandardTotalStr string
	// MemProfiles powers the profile picker.  Every estimate is computed here,
	// server-side, so the page never re-implements the budget rule in JS and the
	// two cannot drift.
	MemProfiles []memProfileView
}

// memProfileView is one choice in the performance tab's profile picker.
type memProfileView struct {
	ID       string
	LabelKey string
	NoteKey  string
	// TotalStr is the headline: everything this profile would use on THIS host
	// (page cache + mmap).  Operators ask "how much will it take", so the sum
	// leads and the split is the footnote, not the other way round.
	TotalStr string
	SplitStr string // "96.0 MB x 2 connections" -- per-connection x pool size
	// RatioStr is what the profile actually IS ("6% of memory"); TotalStr is
	// only what that works out to on this host.  Leading with the ratio is what
	// makes it obvious the presets follow the machine rather than being fixed
	// sizes -- the confusion that made an extra "automatic" choice feel needed.
	RatioStr string
	Capped   bool // the ratio hit this profile's ceiling, so TotalStr is the cap
	Auto     bool // follows the host (false only for custom)
	Active   bool
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

	// Memory plan: what this process resolved for the SQLite pool.  MariaDB
	// pools its own memory server-side, so the card only shows this for sqlite.
	if v.DBDriver != "mariadb" {
		plan := db.SQLiteMemPlanFor(dbc)
		v.MemPlanShow = true
		v.MemConns = plan.Conns
		v.MemPerConnStr = humanBytes(plan.PerConn)
		v.MemTotalStr = humanBytes(plan.TotalCache + plan.TotalMmap)
		v.MemCacheStr = humanBytes(plan.TotalCache)
		v.MemMmapStr = humanBytes(plan.TotalMmap)
		v.MemAutomatic = plan.Automatic
		v.MemCacheMB = dbc.SQLiteCacheMB
		v.MemFromCgroup = plan.FromCgroup
		if plan.MemLimit > 0 {
			v.MemLimitStr = humanBytes(plan.MemLimit)
		}
		v.MemCPUs = plan.CPUs
		v.MemMaxConns = dbc.MaxConns
		v.MemProfileID = dbc.ResolvedPerfProfile()
		{
			std := db.SQLiteMemPlanFor(settings.DB{Driver: dbc.Driver, SQLitePath: dbc.SQLitePath, PerfProfile: settings.PerfProfileStandard})
			v.MemStandardTotalStr = humanBytes(std.TotalCache + std.TotalMmap)
			// What "leave it blank" actually means here, in the same unit the
			// field takes (the pool-wide cache budget).
			auto := db.SQLiteMemPlanFor(settings.DB{Driver: dbc.Driver, SQLitePath: dbc.SQLitePath, PerfProfile: settings.PerfProfileCustom})
			v.MemAutoCacheStr = humanBytes(auto.TotalCache)
		}
		// Estimate each profile against THIS host so the picker shows real
		// numbers rather than abstract percentages.
		for _, p := range []struct{ id, label, note string }{
			{settings.PerfProfileConservative, "settings.perf.profile_conservative", "settings.perf.profile_conservative_note"},
			{settings.PerfProfileStandard, "settings.perf.profile_standard", "settings.perf.profile_standard_note"},
			{settings.PerfProfileGenerous, "settings.perf.profile_generous", "settings.perf.profile_generous_note"},
			{settings.PerfProfileCustom, "settings.perf.profile_custom", "settings.perf.profile_custom_note"},
		} {
			// Every branch below assigns total, including custom-with-blank
			// (= auto), so there is no "unknown" case left to seed.
			var total, split, ratio string
			capped, auto := false, p.id != settings.PerfProfileCustom
			if auto {
				pp := db.SQLiteMemPlanFor(settings.DB{Driver: dbc.Driver, SQLitePath: dbc.SQLitePath, PerfProfile: p.id})
				total = humanBytes(pp.TotalCache + pp.TotalMmap)
				split = fmt.Sprintf("%s x %d", humanBytes(pp.PerConn), pp.Conns)
				ratio = fmt.Sprintf("%d%%", pp.SharePercent)
				capped = pp.Capped
			} else if dbc.SQLiteCacheMB > 0 {
				pinned := int64(dbc.SQLiteCacheMB) << 20
				total = humanBytes(pinned * 2)
				split = fmt.Sprintf("%s x %d", humanBytes(pinned/int64(max(v.MemConns, 1))), v.MemConns)
			} else {
				// Custom with the cache field left blank means "auto" (the
				// placeholder says so), and sqlitePerConnBytesFor resolves it
				// exactly like the automatic profiles do.  So the figure is
				// knowable -- showing "—" here claimed the opposite, on the
				// very state a fresh custom selection starts in.
				pp := db.SQLiteMemPlanFor(settings.DB{
					Driver: dbc.Driver, SQLitePath: dbc.SQLitePath,
					PerfProfile: settings.PerfProfileCustom,
				})
				total = humanBytes(pp.TotalCache + pp.TotalMmap)
				split = fmt.Sprintf("%s x %d", humanBytes(pp.PerConn), pp.Conns)
			}
			v.MemProfiles = append(v.MemProfiles, memProfileView{
				ID: p.id, LabelKey: p.label, NoteKey: p.note,
				TotalStr: total, SplitStr: split, RatioStr: ratio,
				Capped: capped, Auto: auto, Active: p.id == v.MemProfileID,
			})
		}
	}

	// Write-health probe.  DELETE of a never-existing id is a real write
	// statement (SQLite starts a write transaction and MariaDB executes a
	// write plan, so a root-owned / readonly DB fails here exactly like the
	// daemon's event inserts do) that touches no data and seeks the primary
	// key — O(1) even on a multi-GB table.  Runs on its own short deadline,
	// independent of the stats budget above: a slow COUNT must not read as
	// "cannot write".
	pctx, pcancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer pcancel()
	v.WriteChecked = true
	if _, err := h.DB.ExecContext(pctx, `DELETE FROM unmask_event WHERE id = -1`); err != nil {
		v.WriteErr = truncateAt(err.Error(), 200)
	} else {
		v.WriteOK = true
	}
	if u, err := user.Current(); err == nil && u.Username != "" {
		v.DaemonUser = u.Username
	}
	if v.DBDriver != "mariadb" && dbc.SQLitePath != "" {
		if st, err := os.Stat(dbc.SQLitePath); err == nil {
			if sys, ok := st.Sys().(*syscall.Stat_t); ok {
				v.DBFileOwner = ownerNames(sys.Uid, sys.Gid)
			}
		}
		if !v.WriteOK {
			du := v.DaemonUser
			if du == "" {
				du = "unmask"
			}
			// The glob also catches -wal / -shm, which carry the same wrong
			// owner when the daemon could never write them.
			v.FixCmd = fmt.Sprintf("sudo chown %s: %s*  &&  sudo systemctl restart unmask", du, dbc.SQLitePath)
		}
	}
	return v
}

// ownerNames renders a uid:gid pair with names when resolvable
// ("root:root", "unmask:unmask", or "1001:1001" as the numeric fallback).
func ownerNames(uid, gid uint32) string {
	us := strconv.FormatUint(uint64(uid), 10)
	gs := strconv.FormatUint(uint64(gid), 10)
	if u, err := user.LookupId(us); err == nil && u.Username != "" {
		us = u.Username
	}
	if g, err := user.LookupGroupId(gs); err == nil && g.Name != "" {
		gs = g.Name
	}
	return us + ":" + gs
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

// brandingLogoDir: where uploaded logos are persisted.  Variable data lives
// under /var/lib (FHS), NOT next to config.yml in /etc — binary uploads in
// /etc surprise operators and config-management tooling.  A var so tests can
// point it at a temp dir.  Configs from before this move keep working: the
// serve path reads the absolute LogoPath stored in the config, and the next
// upload writes here and removes the old file wherever it was.
var brandingLogoDir = "/var/lib/unmask/branding"

// brandingLogoName: per-scope logo file name.  The Default record and every
// per-site override MUST land on distinct files — a single shared "logo.<ext>"
// silently cross-overwrote Default and site logos (the reason per-site logos
// never worked).  scope "" = Default.
func brandingLogoName(scope, ext string) string {
	if scope == "" {
		return "logo" + ext
	}
	s := strings.ToLower(scope)
	var b strings.Builder
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '.', c == '-':
			b.WriteRune(c)
		default:
			b.WriteRune('_')
		}
	}
	return "logo." + b.String() + ext
}

// applyBrandingForm mutates cur in place with the values from the branding
// form (= section=branding).  scope selects the logo file name ("" =
// Default, else the site identifier) so records never share a file; the
// bytes are persisted under brandingLogoDir.
//
// Operates on a *settings.BrandingValues record (= one Default or one site
// entry).  applyBrandingFormV2 wraps this for the default + sites save path.
//
// The logo file accepts a single upload.  Missing file = leave existing
// logo untouched (= operator only changed text fields).  branding_logo_clear=1
// removes the on-disk file + clears LogoPath.
// brandingFormHasEdits reports whether a per-site branding POST carried values
// the operator typed or picked.  Used to tell "uncheck the override and save"
// (= a deliberate drop, arrives empty because the page disables the fields)
// apart from "the fields were live and are about to be discarded".
func brandingFormHasEdits(r *http.Request) bool {
	if r.MultipartForm != nil && len(r.MultipartForm.File["branding_logo_file"]) > 0 {
		return true
	}
	for _, k := range []string{"branding_site_name", "branding_footer_text"} {
		if strings.TrimSpace(r.FormValue(k)) != "" {
			return true
		}
	}
	return false
}

func applyBrandingForm(cur *settings.BrandingValues, scope string, r *http.Request) error {
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
	if err := os.MkdirAll(brandingLogoDir, 0o755); err != nil {
		return fmt.Errorf("logo: mkdir failed: %w", err)
	}
	path := filepath.Join(brandingLogoDir, brandingLogoName(scope, ext))
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
	// Drop the record's prior file when the new upload landed elsewhere — an
	// extension change, or a legacy location (pre-move configs stored logos
	// next to config.yml in /etc/unmask/branding).  Only after the new file
	// is safely in place, and only this record's own path, so Default and
	// site overrides can never remove each other's files.
	if old := cur.LogoPath; old != "" && old != path {
		_ = os.Remove(old)
	}
	cur.LogoPath = path
	return nil
}

// applyBrandingFormV2: top-level entry point for the branding tab save.
// In v2 there is a single form per tab that edits the Default record only;
// per-site cards have their own add / edit / delete endpoints (see the
// HandleBrandingSite* methods below).  Until the cards land, this is a thin
// adapter onto applyBrandingForm targeting cur.Default.
func applyBrandingFormV2(cur *settings.Branding, r *http.Request) error {
	return applyBrandingForm(&cur.Default, "", r)
}

// applyChallengeFormV2: top-level entry point for the challenge tab save.
// Mirrors applyBrandingFormV2: the Default record is edited via the same
// form fields, per-site entries via dedicated card endpoints.
func applyChallengeFormV2(cur *settings.ChallengeConfig, r *http.Request) error {
	if err := applyChallengeForm(&cur.Default, r); err != nil {
		return err
	}
	// Collapse Default back to "unset" where the submitted value is what unset
	// already means.  Sparsify does this for a SITE record (against Default);
	// Default has no parent, so it is compared against the shipped resolution
	// instead.  Without this, opening the tab and saving without touching
	// anything writes public_test_pages_site_picker: true into config.yml --
	// the same "an untouched save pins a value" problem the checkboxes were
	// just fixed for, only one level up.
	// Unset resolves to ON (IsPublicTestPagesSitePicker), so an explicit true
	// on Default carries no information.
	if p := cur.Default.PublicTestPagesSitePicker; p != nil && *p {
		cur.Default.PublicTestPagesSitePicker = nil
	}
	return nil
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
			// Refuse to report success while throwing the operator's edits
			// away.  The page disables every field when the toggle is off, so
			// a normal "uncheck + save" (= drop the override) arrives with
			// nothing filled in and proceeds below.  Fields DO arrive when
			// that script never ran -- JS disabled, a stale tab rendered
			// before the toggle sync landed, a hand-built POST -- and the old
			// code then silently discarded them, logo upload included, and
			// still redirected with "saved".  A save that keeps nothing must
			// not look like a save that worked.
			if brandingFormHasEdits(r) {
				return fmt.Errorf("nothing was saved: %q is off for this site. "+
					"Tick it and save again to store these values, or clear the fields to turn the override off", "override settings for this host")
			}
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
		if err := applyBrandingForm(&bv, site, r); err != nil {
			return err
		}
		// theme + show_credit ride the same form as the logo, and now land on
		// the same record.  They used to be written to cur.Challenge.Sites[site]
		// instead -- and because a challenge record is inherited whole or owned
		// whole, storing them there meant seeding a full snapshot of
		// Challenge.Default for the site.  Choosing a theme therefore minted a
		// challenge-behaviour override the operator never asked for, which then
		// stopped tracking Default forever after.
		t := strings.TrimSpace(r.FormValue("theme"))
		if !challengeThemes[t] {
			t = "default"
		}
		bv.Theme = t
		bv.ShowCredit = settings.BoolPtr(r.FormValue("show_credit") == "1")
		bv.Disabled = false
		// The form submits every field, so store only what actually differs
		// from Default: the rest keeps tracking Default instead of freezing at
		// whatever it happened to say the day this site was first saved.
		cur.Branding.Sites[site] = settings.SparsifyBranding(bv, cur.Branding.Default)
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
			// First save for this site: seed from Default so the knobs this
			// form does not expose keep the operator's configured values
			// rather than dropping to the built-in ones.  (A record is
			// inherited whole or owned whole -- see ChallengeConfig.Resolve.)
			cv = cur.Challenge.Default
		}
		if err := applyChallengeForm(&cv, r); err != nil {
			return err
		}
		// captcha provider shares the form field names with the captcha tab.
		// Reuse the existing parser so the per-site card form behaves the same
		// as the default form.  The theme is NOT read here: it belongs to the
		// branding record, and picking one must not create a challenge override.
		if err := applyCaptchaForm(&cv.CaptchaProvider, r); err != nil {
			return err
		}
		cv.Disabled = false
		// Same as the branding save: keep only the fields this site really
		// overrides, so the others follow Default when Default changes.
		cur.Challenge.Sites[site] = settings.SparsifyChallenge(cv, cur.Challenge.Default)
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

	if raw := strings.TrimSpace(r.FormValue("cache_ttl_sec")); raw == "" {
		// Blank field = unset (the verifier's built-in TTL applies).
		c.CacheTTLSec = 0
	} else if n, err := strconv.Atoi(raw); err == nil && n > 0 {
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
