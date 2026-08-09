// Honeypot per-preset / per-URL action resolution, shared by the native-mode
// auto-ban path.  Forward-auth resolves the same override inline off its cached
// matcher (handlers.bypassMatchers); this is the standalone resolver the native
// honeypot callback (cmd/unmask/main.go) calls per hp=1 access-log line, where
// nginx has already decided the URI is a honeypot and we only need the matched
// rule's action to stamp onto the ban.
package nginxconf

import (
	"regexp"
	"strings"
	"sync"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// hpReCache memoizes compiled honeypot patterns by their string.  The native
// callback fires once per honeypot trip (= bot traffic, can flood), so compiling
// every preset pattern on each call would be a CPU sink; the cache is bounded by
// the count of distinct preset + custom patterns (finite, not request-driven).
var hpReCache sync.Map // pattern string -> *regexp.Regexp (nil = compile failed)

func hpCompile(pattern string) *regexp.Regexp {
	if v, ok := hpReCache.Load(pattern); ok {
		re, _ := v.(*regexp.Regexp)
		return re
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		hpReCache.Store(pattern, (*regexp.Regexp)(nil))
		return nil
	}
	hpReCache.Store(pattern, re)
	return re
}

// ResolveHoneypotAction returns the per-preset / per-URL action override for the
// FIRST honeypot rule that uri matches, mirroring render.go's active-set logic
// (OptIn / DisabledPresets / EnabledPresets) so the resolved rule agrees with
// what nginx actually rendered as a honeypot.  Preset patterns are
// global; custom URLs honor their per-row Site (site="" considers only global
// URLs, which is all the native callback -- it carries no host -- can resolve).
//
// The returned action is RAW (un-resolved): "" means "no override" so the caller
// inherits Honeypot.DefaultAction (and, persisted as a ban's action column,
// stays dynamic via EffectiveAction); a concrete chain mode pins the per-preset
// choice.  matched reports whether any honeypot rule hit.
func ResolveHoneypotAction(uri, site string, n settings.Nginx) (action string, matched bool) {
	if strings.TrimSpace(uri) == "" {
		return "", false
	}
	disabledHP := toSet(n.Honeypot.DisabledPresets)
	enabledHP := toSet(n.Honeypot.EnabledPresets)
	for _, g := range HoneypotPresetGroups {
		if g.OptIn {
			if !enabledHP[g.ID] {
				continue
			}
		} else if disabledHP[g.ID] {
			continue
		}
		for _, p := range g.Patterns {
			if re := hpCompile("(?i)" + p); re != nil && re.MatchString(uri) {
				return strings.TrimSpace(n.Honeypot.PresetAction[g.ID]), true
			}
		}
	}
	for _, u := range n.Honeypot.URLs {
		if u.Disabled {
			continue
		}
		if u.Site != "" && u.Site != site {
			continue
		}
		p := strings.TrimSpace(u.Path)
		if p == "" {
			continue
		}
		if re := hpCompile("(?i)" + p); re != nil && re.MatchString(uri) {
			return strings.TrimSpace(u.Action), true
		}
	}
	return "", false
}
