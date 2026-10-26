// The setup wizard's options step (first run only): the communication with
// unmask.sh, the hostname the admin UI answers on, and monitor mode.
//
// Every switch here exists on a settings tab already.  The step puts them in
// front of the operator before the daemon makes its first contact with
// unmask.sh, and before the admin UI is left reachable under any Host --
// the two things an operator later asks "why was I not told".  Nothing is
// changed unless the step is submitted (wizardState.OptionsSet): a wizard
// driven by a script keeps the config as it is.
package handlers

import (
	"net"
	"net/http"
	"strings"

	"github.com/unmask-sh/unmask/admin/internal/i18n"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// wizardOptionsFromSettings reads the switches as the config has them.  On a
// fresh install that is the defaults: every communication on, no admin host,
// enforcing.
func wizardOptionsFromSettings(s settings.Settings) wizardOptions {
	g := s.IPGeo
	return wizardOptions{
		Feed:         s.CommunityBans.SubscribeActive(),
		Liveness:     s.CommunityBans.PublishLiveness,
		Country:      s.CommunityBans.PublishCountry,
		GeoIP:        g.AutoFetch || g.AutoUpdate || g.AutoUpdateASN,
		Sync:         !s.Nginx.SyncDisabled,
		VersionCheck: !s.VersionCheckDisabled,
		ObserveOnly:  s.Challenge.Default.ObserveOnly != nil && *s.Challenge.Default.ObserveOnly,
	}
}

// applyWizardOptions writes the step's choices into cur.  A switch left on
// keeps whatever the config says (a subscribe mode of "fetch", one of the
// three GeoIP switches off): the step turns things off, and turns a switch
// back on only when the config has it fully off.
func applyWizardOptions(cur *settings.Settings, o wizardOptions) {
	cb := &cur.CommunityBans
	switch {
	case !o.Feed:
		cb.SubscribeMode = settings.SubscribeOff
	case !cb.SubscribeActive():
		cb.SubscribeMode = settings.SubscribeFetchApply
	}
	cb.PublishLiveness = o.Liveness
	cb.PublishCountry = o.Country
	g := &cur.IPGeo
	switch {
	case !o.GeoIP:
		g.AutoFetch, g.AutoUpdate, g.AutoUpdateASN = false, false, false
	case !g.AutoFetch && !g.AutoUpdate && !g.AutoUpdateASN:
		g.AutoFetch, g.AutoUpdate, g.AutoUpdateASN = true, true, true
	}
	cur.Nginx.SyncDisabled = !o.Sync
	cur.VersionCheckDisabled = !o.VersionCheck
	// The one entry replaces the list: on a first run the list is empty, and
	// the step offers one host, not an editor for several.
	cur.Nginx.AdminAllowedHosts = nil
	cur.Nginx.AdminAllowedHostsTitle = nil
	cur.Nginx.AdminAllowedHostsDisabled = nil
	cur.Nginx.AdminAllowedHostsCreatedAt = nil
	cur.Nginx.AdminAllowedHostsUpdatedAt = nil
	if o.AdminHost != "" {
		cur.Nginx.AdminAllowedHosts = []string{o.AdminHost}
	}
	if o.ObserveOnly {
		on := true
		cur.Challenge.Default.ObserveOnly = &on
	} else {
		cur.Challenge.Default.ObserveOnly = nil
	}
}

// wizardReachedHost: the Host this request arrived on, lowercased and without
// a port, and whether it is an IP address.  The admin host allowlist takes
// hostnames: an address is what a visitor reaches the box by before any DNS
// exists, and listing it would pin the admin UI to that address.
func wizardReachedHost(r *http.Request, cfg settings.Settings) (host string, isIP bool) {
	host = normalizeHostForAllowlist(adminClientHost(r, cfg))
	return host, net.ParseIP(host) != nil
}

// normalizeHostForAllowlist strips the port (and an IPv6 literal's brackets)
// and lowercases, the form the allowlist compares (hostAllowed).
func normalizeHostForAllowlist(h string) string {
	h = strings.TrimSpace(h)
	if strings.HasPrefix(h, "[") {
		if i := strings.IndexByte(h, ']'); i >= 0 {
			h = h[1:i]
		}
	} else if i := strings.LastIndexByte(h, ':'); i >= 0 && strings.Count(h, ":") == 1 {
		h = h[:i]
	}
	return strings.ToLower(h)
}

// feedPrivacyURL: the feed privacy document in the operator's language.
func feedPrivacyURL(lang i18n.Lang) string {
	if lang == i18n.LangJA {
		return "https://unmask.sh/ja/feed/privacy/"
	}
	return "https://unmask.sh/feed/privacy/"
}

// wizardCommLabels: the communications in the order the step lists them,
// each with the i18n key of its label and whether the option keeps it on.
func wizardCommLabels(o wizardOptions) []struct {
	Key string
	On  bool
} {
	return []struct {
		Key string
		On  bool
	}{
		{"setup.options.comm_feed", o.Feed},
		{"setup.options.comm_liveness", o.Liveness},
		{"setup.options.comm_country", o.Country},
		{"setup.options.comm_geoip", o.GeoIP},
		{"setup.options.comm_sync", o.Sync},
		{"setup.options.comm_version", o.VersionCheck},
	}
}

// wizardCommOffLabels: the labels of the communications the operator turned
// off, for the review step.
func wizardCommOffLabels(lang i18n.Lang, o wizardOptions) []string {
	var out []string
	for _, c := range wizardCommLabels(o) {
		if !c.On {
			out = append(out, i18n.T(lang, c.Key))
		}
	}
	return out
}

// AdminSetupSaveOptions: POST {base}/admin/setup/options -- store the options
// step's choices in the wizard state.  The config is written by install.
// First run only: a reconfiguring superadmin has no options step
// (wizardState.step) and is sent back to the wizard.
func (h *Handler) AdminSetupSaveOptions(w http.ResponseWriter, r *http.Request) {
	base := h.cfg().Server.BasePath
	if h.setupSuperadmin(r) != nil || !hasValidSetupToken(r) {
		http.Redirect(w, r, base+"/admin/setup/", http.StatusFound)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	lang := i18n.Resolve(r)
	s := h.getWizardState(r)
	if s == nil {
		http.Redirect(w, r, base+"/admin/setup/?err="+urlEncodeShort("setup session expired; reload and re-enter the token"), http.StatusFound)
		return
	}
	if !s.DBSet || !s.UserSet {
		http.Redirect(w, r, base+"/admin/setup/", http.StatusFound)
		return
	}
	on := func(name string) bool { return r.FormValue(name) != "" }
	o := wizardOptions{
		Feed:         on("comm_feed"),
		Liveness:     on("comm_liveness"),
		Country:      on("comm_country"),
		GeoIP:        on("comm_geoip"),
		Sync:         on("comm_sync"),
		VersionCheck: on("comm_version"),
		ObserveOnly:  on("observe_only"),
	}
	// The hostname: one plain name, kept as an exact entry.  Refused when it
	// is an address, has a character no hostname has, or is not the Host
	// this request arrived on -- the same lockout guard the Network tab has,
	// since the entry takes effect at install and the operator has to reach
	// the admin UI through it.
	hostText := strings.TrimSpace(r.FormValue("admin_host"))
	if hostText != "" {
		redirErr := func(msg string) {
			http.Redirect(w, r, base+"/admin/setup/?step=options&err="+urlEncodeShort(msg)+"&admin_host="+urlEncodeShort(hostText), http.StatusFound)
		}
		if strings.ContainsAny(hostText, "\x00\r\n\t /\\\"'<>") {
			redirErr(i18n.Tf(lang, "err.admin_host_invalid", hostText))
			return
		}
		host := normalizeHostForAllowlist(hostText)
		if net.ParseIP(host) != nil {
			redirErr(i18n.Tf(lang, "setup.err.admin_host_ip", host))
			return
		}
		entry := settings.MakePatternWithMode(host, settings.ModeExact)
		reached, _ := wizardReachedHost(r, h.snapshotSettings())
		if !hostAllowed(reached, []string{entry}) {
			redirErr(i18n.Tf(lang, "err.admin_lockout_host", reached))
			return
		}
		o.AdminHost = entry
	}
	s.Options = o
	s.OptionsSet = true
	touchWizardState(s)
	http.Redirect(w, r, base+"/admin/setup/", http.StatusFound)
}
