package handlers

import (
	"html/template"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/unmask-sh/unmask/admin/internal/classify"
	"github.com/unmask-sh/unmask/admin/internal/communitybans"
	"github.com/unmask-sh/unmask/admin/internal/dashboard"
	"github.com/unmask-sh/unmask/admin/internal/i18n"
	"github.com/unmask-sh/unmask/admin/internal/nginxconf"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The entry behind a force reason: the row of the settings that fired, as
// payload force_rule names it on the serve and on every beacon (the page
// echoes it beside force_reason).  The stats card breaks each reason down by
// it; the hunt rows and the CAPTCHA-pass list open it in a popover behind the
// reason badge (the badge itself stays the reason, as a rule's name can run to
// a sentence).  Every entry is one of a set the
// settings bound -- the operator's rules, the presets, a verdict, a country
// code -- since the hourly aggregate keys a bucket by it:
//
//	custom_rule     the rule's id
//	ua_target       preset:<group id> / own:<pattern> / crawler:<pattern>
//	asn             AS<number>, or the org substring of an org rule
//	geo             the country code
//	honeypot        the rule's name (a preset group's, or the row's title / path)
//	protected       the path's pattern
//	stale           chrome <major> / firefox <major>
//	header          the check (no_sch_ua)
//	ua_tls          the contradiction (family / version)
//	banned          the ban's source
//	community_bans  what matched (ip / ja4 / ip_ja4)
//	ja4_bot         the verdict
//
// rate_limit, reuse_limit, test and none have no entry.

// forceEntry names the entry behind reason for the request r: the serve, or
// a beacon (whose UA, address and JA4 are the same visitor's, and whose
// orig_path is what the page says it was).
func (h *Handler) forceEntry(r *http.Request, reason, verdict, ja4, origPath, site string) string {
	cfg := h.cfg()
	switch reason {
	case "custom_rule":
		return customRuleIDOrEmpty(r.Header.Get("X-Unmask-Rule"))
	case "ua_target":
		return uaListedEntry(firstNonEmpty(r.Header.Get("X-Original-UA"), r.Header.Get("User-Agent")), cfg.Nginx)
	case "asn", "geo":
		if got, _, entry := h.netChallengeReason(adminClientIP(r, *cfg), *cfg); got == reason {
			return entry
		}
	case "honeypot":
		if m, ok := nginxconf.ResolveHoneypotRule(origPath, site, cfg.Nginx); ok {
			return m.Rule
		}
	case "protected":
		return protectedPathEntry(origPath, site, *cfg)
	case "stale":
		return staleBrowserEntry(firstNonEmpty(r.Header.Get("X-Original-UA"), r.Header.Get("User-Agent")))
	case "header":
		if d, ok := headerDecideForServe(r, cfg.Global); ok {
			return strings.TrimPrefix(d.reason, "header:")
		}
	case "ua_tls":
		if e := strings.TrimSpace(r.Header.Get("X-UA-TLS-Mismatch")); uaTLSCheckNames[e] {
			return e
		}
	case "banned":
		if h.BanMgr != nil {
			if src, ok := h.BanMgr.IsBannedSource(r.Context(), clientIP(r), ja4); ok {
				return src
			}
		}
	case "community_bans":
		if m := h.communityBansMatcher(); m != nil {
			if kind, ok := m.Hit(clientIP(r), ja4); ok {
				return kind
			}
		}
	case "ja4_bot":
		return verdict
	}
	return ""
}

// headerCheckNames: the checks headerDecide can name, the one set a beacon
// may echo for the header reason (its own request's headers are a fetch's,
// not the page load's, so the check cannot be run again on it).
var headerCheckNames = map[string]bool{"no_sch_ua": true}

// uaTLSCheckNames: the contradictions the UA-TLS consistency tier names
// (http.inc's $unmask_ua_tls_mismatch): a Chromium fingerprint under a
// Firefox / Safari name, or a TLS 1.3 session under a pre-TLS 1.3 version.
var uaTLSCheckNames = map[string]bool{"family": true, "version": true, "reverse": true}

// uaTLSFiresForServe reports whether the UA-TLS consistency tier escalated
// this challenge serve: the tier is in force (on, and not held by the upgrade
// review) and nginx named a contradiction on the internal rewrite
// (X-UA-TLS-Mismatch; proxy_set_header overwrites a client's value).  Native
// only: the forward-auth path is frozen and gets no new axis.
func uaTLSFiresForServe(r *http.Request, s settings.Settings) bool {
	if !nginxconf.UATLSActive(s) {
		return false
	}
	return uaTLSCheckNames[strings.TrimSpace(r.Header.Get("X-UA-TLS-Mismatch"))]
}

// beaconForceEntry: the entry a beacon keeps for its force_reason, or "".
// The page is the client's to rewrite, so the echoed value is kept only when
// the daemon gets the same one again from what the beacon itself brings
// (its UA, its address, its JA4), or when it is one of a set the settings
// bound (a rule id, a verdict, a check, a trap's name, a protected path).
func (h *Handler) beaconForceEntry(r *http.Request, raw map[string]any, ja4, site string) string {
	reason, _ := raw["force_reason"].(string)
	echoed, _ := raw["force_rule"].(string)
	if echoed == "" || len(echoed) > 200 {
		return ""
	}
	ok := false
	switch reason {
	case "custom_rule":
		ok = h.knownCustomRuleID(echoed)
	case "ja4_bot":
		ok = h.VerdictNameToID(echoed) > 0
	case "header":
		ok = headerCheckNames[echoed]
	case "ua_tls":
		ok = uaTLSCheckNames[echoed]
	case "honeypot":
		ok = h.knownHoneypotRule(echoed)
	case "protected":
		ok = h.knownProtectedPattern(echoed, site)
	case "community_bans":
		ok = echoed == communitybans.HitKindIP || echoed == communitybans.HitKindJA4 || echoed == communitybans.HitKindIPJA4
	case "ua_target", "asn", "geo", "stale", "banned":
		ok = h.forceEntry(r, reason, "", ja4, "", site) == echoed
	}
	if ok {
		return echoed
	}
	return ""
}

// knownHoneypotRule: name is one of the honeypot rules' (a preset group's,
// or a row's title / path), on or off.
func (h *Handler) knownHoneypotRule(name string) bool {
	for _, g := range nginxconf.HoneypotPresetGroups {
		if g.Name() == name {
			return true
		}
	}
	for _, u := range h.cfg().Nginx.Honeypot.URLs {
		if nginxconf.HoneypotURLName(u) == name {
			return true
		}
	}
	return false
}

// knownProtectedPattern: p is the pattern of a protected path in force, for
// every host or for site.
func (h *Handler) knownProtectedPattern(p, site string) bool {
	for _, r := range nginxconf.EffectiveProtectedPathRules(*h.cfg()) {
		if r.Pattern == p && (r.Site == "" || r.Site == site) {
			return true
		}
	}
	return false
}

// uaListedEntry: the UA filter row lookupUAListed's "challenge" verdict
// came from -- the same branches in the same order, so the two never
// disagree on which row fired.  "" when the UA is listed as a rescue, or
// not at all.
func uaListedEntry(ua string, n settings.Nginx) string {
	if ua == "" {
		return ""
	}
	for i, p := range n.SearchBots.Extra {
		if i < len(n.SearchBots.ExtraDisabled) && n.SearchBots.ExtraDisabled[i] {
			continue
		}
		if matchedRegex(p, ua) {
			return "" // a rescue, not a target
		}
	}
	disabledCT := map[string]bool{}
	for _, id := range n.ChallengeTargets.DisabledPresets {
		disabledCT[strings.TrimSpace(id)] = true
	}
	for _, g := range nginxconf.ChallengeTargetGroups {
		if disabledCT[g.ID] || nginxconf.EnforcementHeld(n, g.AddedIn) {
			continue
		}
		for _, p := range g.Patterns {
			if matchedRegex(p, ua) {
				return "preset:" + g.ID
			}
		}
	}
	for i, p := range n.ChallengeTargets.Extra {
		if i < len(n.ChallengeTargets.ExtraDisabled) && n.ChallengeTargets.ExtraDisabled[i] {
			continue
		}
		if matchedRegex(p, ua) {
			return "own:" + strings.TrimSpace(p)
		}
	}
	sb := n.SearchBots
	for cat, entries := range classify.UpstreamRescueList() {
		if len(sb.UpstreamPatternMode) == 0 && classify.ResolveGroupMode(cat, sb.UpstreamGroupMode) != classify.GroupModeBlack {
			continue
		}
		for _, e := range entries {
			if classify.ResolvePatternMode(cat, e.Pattern, sb.UpstreamGroupMode, sb.UpstreamPatternMode) != classify.GroupModeBlack {
				continue
			}
			if matchedRegex(e.Pattern, ua) {
				return "crawler:" + e.Pattern
			}
		}
	}
	return ""
}

// protectedPathEntry: the protected path the URI falls under, matched the way
// the rendered maps match (a case-insensitive regex on the path; the host's
// own rows before the global ones): its pattern.
func protectedPathEntry(uri, site string, s settings.Settings) string {
	path := uri
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	if path == "" {
		return ""
	}
	rules := nginxconf.EffectiveProtectedPathRules(s)
	for _, own := range []bool{true, false} {
		for _, r := range rules {
			if own != (r.Site != "") || (own && r.Site != site) {
				continue
			}
			if re, err := regexp.Compile("(?i)" + r.Pattern); err == nil && re.MatchString(path) {
				return r.Pattern
			}
		}
	}
	return ""
}

// staleBrowserEntry: the browser and major the stale-browser axis judged.
func staleBrowserEntry(ua string) string {
	if m := classify.ChromeMajor(ua); m > 0 {
		return "chrome " + strconv.Itoa(m)
	}
	if m := classify.FirefoxMajor(ua); m > 0 {
		return "firefox " + strconv.Itoa(m)
	}
	return ""
}

// forceEntryName: what the page calls an entry -- a custom rule by its
// label, a UA preset by its label, an ASN rule with its note, a browser
// capitalised, a header check in words; the rest as recorded.
func (h *Handler) forceEntryName(lang i18n.Lang, reason, entry string) string {
	if entry == "" {
		return ""
	}
	cfg := h.cfg()
	switch reason {
	case "custom_rule":
		for _, cr := range cfg.Nginx.CustomRules {
			if cr.ID == entry {
				if l := strings.TrimSpace(cr.Label); l != "" {
					return l
				}
			}
		}
	case "ua_target":
		if id, ok := strings.CutPrefix(entry, "preset:"); ok {
			for _, g := range nginxconf.ChallengeTargetGroups {
				if g.ID == id {
					return g.Label
				}
			}
			return id
		}
		if p, ok := strings.CutPrefix(entry, "own:"); ok {
			return p
		}
		if p, ok := strings.CutPrefix(entry, "crawler:"); ok {
			return p
		}
	case "asn":
		if n, ok := strings.CutPrefix(entry, "AS"); ok {
			if asn, err := strconv.ParseUint(n, 10, 32); err == nil {
				for _, r := range cfg.Nginx.Asn.Rules {
					if r.ASN == uint(asn) {
						if l := strings.TrimSpace(r.Label); l != "" {
							return entry + " · " + l
						}
					}
				}
			}
		}
	case "stale":
		if m, ok := strings.CutPrefix(entry, "chrome "); ok {
			return "Chrome " + m
		}
		if m, ok := strings.CutPrefix(entry, "firefox "); ok {
			return "Firefox " + m
		}
	case "header":
		if entry == "no_sch_ua" {
			return i18n.T(lang, "captcha_force.header.no_sch_ua")
		}
	case "ua_tls":
		if uaTLSCheckNames[entry] {
			return i18n.T(lang, "captcha_force.ua_tls."+entry)
		}
	}
	return entry
}

// forceEntryLink: where the entry is set -- a custom rule on the list by its
// anchor, every other reason its settings page.  gone is a custom rule since
// deleted (no link; the page shows its id, marked).
func (h *Handler) forceEntryLink(reason, entry string) (link string, gone bool) {
	base := h.cfg().Server.BasePath
	if reason == "custom_rule" {
		if h.knownCustomRuleID(entry) {
			return base + "/admin/settings/custom-rules/#rule-" + entry, false
		}
		return "", true
	}
	if t, ok := overviewReasonSettings[reason]; ok {
		return base + "/admin/" + t.path, false
	}
	return "", false
}

// forceEntryNote: the popover behind a reason badge -- the stats card's
// sentence for the entry (captcha_force.entry.<reason>), with the entry's
// name in bold and linking to where it is set; a custom rule since deleted by
// its id, marked.  "" when the reason has no entry, or none was recorded.
func (h *Handler) forceEntryNote(lang i18n.Lang, reason, entry string) template.HTML {
	name := h.forceEntryName(lang, reason, entry)
	if name == "" {
		return ""
	}
	key := "captcha_force.entry." + reason
	sentence := i18n.T(lang, key)
	if sentence == key || !strings.Contains(sentence, "%s") {
		return ""
	}
	label := "<b>" + template.HTMLEscapeString(name) + "</b>"
	link, gone := h.forceEntryLink(reason, entry)
	if link != "" {
		label = `<a href="` + template.HTMLEscapeString(link) + `">` + label + `</a>`
	}
	body := strings.Replace(template.HTMLEscapeString(sentence), "%s", label, 1)
	if gone {
		body += ` <span class="muted">` + template.HTMLEscapeString(i18n.T(lang, "captcha_force.rule_deleted")) + `</span>`
	}
	return template.HTML(body)
}

// captchaForceRuleView is one row under a reason's row on the stats card:
// the entry by name, linking to where it is set; how many challenge pages
// loaded under it and from how many addresses.  The last row of a reason,
// when its entries fall short of the reason's count, is the loads whose page
// named no entry (an older challenge page); it has no address count, as the
// sketches cannot be told apart.
type captchaForceRuleView struct {
	Entry  string
	Label  string
	Link   string // where the entry is set; "" for the remainder row
	Gone   bool   // a custom rule since deleted: by its id, no link
	Rest   bool   // the remainder row
	Count  int
	UniqIP int
}

// captchaForceRuleViews groups CaptchaForceRules' rows under their reason,
// names each entry, and adds the remainder row from the card's count for
// the reason.
func (h *Handler) captchaForceRuleViews(lang i18n.Lang, rules []dashboard.CaptchaForceRuleRow, kinds []dashboard.CaptchaForceRow) map[string][]captchaForceRuleView {
	if len(rules) == 0 {
		return nil
	}
	out := map[string][]captchaForceRuleView{}
	sum := map[string]int{}
	for _, r := range rules {
		v := captchaForceRuleView{Entry: r.Rule, Label: h.forceEntryName(lang, r.Kind, r.Rule), Count: r.Count, UniqIP: r.UniqIP}
		v.Link, v.Gone = h.forceEntryLink(r.Kind, r.Rule)
		sum[r.Kind] += r.Count
		out[r.Kind] = append(out[r.Kind], v)
	}
	for _, k := range kinds {
		if rows, ok := out[k.Kind]; ok && k.Count > sum[k.Kind] {
			out[k.Kind] = append(rows, captchaForceRuleView{Rest: true, Count: k.Count - sum[k.Kind]})
		}
	}
	return out
}
