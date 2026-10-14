package settings

import (
	"log"
	"strings"

	"gopkg.in/yaml.v3"
)

// warnRemovedUpstreamLists: `search_bots.upstream_disabled` and
// `search_bots.upstream_ua_enabled` were the UA filter tab's per-crawler
// checkboxes until 0.1.50.  0.1.51 replaced them with upstream_pattern_mode,
// where each crawler is set to pass, normal checks or stop on its own.
//
// The generic unknown-key warning would read as harmless, and for
// upstream_disabled it is not: every crawler listed there was one the operator
// took off the rescue list, and it is rescued again until it is set to normal
// checks under the new key.  Name those, so the operator can.  A crawler the
// new key already sets is not rescued again, and is not named as if it were:
// the old list is only left over.
//
// Warn only.  The keys stay ignored -- no behavior returns
// (feedback_no_user_rescue).  upstream_ua_enabled needs nothing: a crawler
// whose group passes is passed already.
func warnRemovedUpstreamLists(resolved string, raw []byte) {
	var probe struct {
		Nginx struct {
			SearchBots struct {
				Disabled    []string          `yaml:"upstream_disabled"`
				UAEnabled   []string          `yaml:"upstream_ua_enabled"`
				PatternMode map[string]string `yaml:"upstream_pattern_mode"`
			} `yaml:"search_bots"`
		} `yaml:"nginx"`
	}
	if yaml.Unmarshal(raw, &probe) != nil {
		return
	}
	sb := probe.Nginx.SearchBots
	var unset []string
	for _, p := range sb.Disabled {
		if _, ok := sb.PatternMode[p]; !ok {
			unset = append(unset, p)
		}
	}
	switch {
	case len(unset) > 0:
		log.Printf("unmask: config %s still lists crawlers in search_bots.upstream_disabled (%s) -- REMOVED in 0.1.51 "+
			"and ignored, so these crawlers are rescued again by their group. Set each to Normal checks in its group's "+
			"Detail on the UA filter tab (stored as search_bots.upstream_pattern_mode: {<pattern>: none}), then "+
			"render-nginx + reload. Delete the `upstream_disabled:` list to silence this.",
			resolved, strings.Join(unset, ", "))
	case len(sb.Disabled) > 0:
		log.Printf("unmask: config %s still carries search_bots.upstream_disabled (removed in 0.1.51, ignored); "+
			"search_bots.upstream_pattern_mode sets each crawler it lists. Delete the `upstream_disabled:` list.", resolved)
	}
	if sb.UAEnabled != nil {
		log.Printf("unmask: config %s still carries search_bots.upstream_ua_enabled (removed in 0.1.51, ignored). "+
			"Delete the list; a crawler whose group passes is passed already.", resolved)
	}
}
