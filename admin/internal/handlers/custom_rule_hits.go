package handlers

import (
	"regexp"
	"strings"

	"github.com/unmask-sh/unmask/admin/internal/dashboard"
)

// customRuleIDOK is the shape of a custom rule's id (settings' "cr" + base36,
// with room for one an operator typed): the one thing a beacon may name as
// force_rule.
var customRuleIDOK = regexp.MustCompile(`^[A-Za-z0-9_-]{1,32}$`)

// customRuleIDOrEmpty: s trimmed when it is a rule id, else "".
func customRuleIDOrEmpty(s string) string {
	s = strings.TrimSpace(s)
	if customRuleIDOK.MatchString(s) {
		return s
	}
	return ""
}

// knownCustomRuleID: id names one of this install's custom rules.
func (h *Handler) knownCustomRuleID(id string) bool {
	if customRuleIDOrEmpty(id) == "" {
		return false
	}
	for _, cr := range h.cfg().Nginx.CustomRules {
		if cr.ID == id {
			return true
		}
	}
	return false
}

// customRuleNames: each custom rule's id to what the page calls it -- its
// label, or the id when it has none.
func (h *Handler) customRuleNames() map[string]string {
	rules := h.cfg().Nginx.CustomRules
	m := make(map[string]string, len(rules))
	for _, cr := range rules {
		if l := strings.TrimSpace(cr.Label); l != "" {
			m[cr.ID] = l
		} else {
			m[cr.ID] = cr.ID
		}
	}
	return m
}

// captchaForceRuleView is one row under the stats card's custom_rule row:
// the rule by name (by id when it has none or is gone), how many challenge
// pages loaded under it and from how many addresses.  The last row, when the
// rules fall short of the custom_rule count, is the loads that named no rule
// (an older challenge page); it has no address count, as the sketches cannot
// be told apart.
type captchaForceRuleView struct {
	ID     string
	Label  string
	Known  bool // on the list: the name links to the rule
	Rest   bool // the remainder row
	Count  int
	UniqIP int
}

// captchaForceRuleViews names the rules of CaptchaForceRules' rows and adds
// the remainder row from the card's custom_rule count.
func (h *Handler) captchaForceRuleViews(rules []dashboard.CaptchaForceRuleRow, kinds []dashboard.CaptchaForceRow) []captchaForceRuleView {
	if len(rules) == 0 {
		return nil
	}
	names := h.customRuleNames()
	out := make([]captchaForceRuleView, 0, len(rules)+1)
	sum := 0
	for _, r := range rules {
		v := captchaForceRuleView{ID: r.Rule, Label: r.Rule, Count: r.Count, UniqIP: r.UniqIP}
		if l, ok := names[r.Rule]; ok {
			v.Known, v.Label = true, l
		}
		sum += r.Count
		out = append(out, v)
	}
	for _, k := range kinds {
		if k.Kind == "custom_rule" && k.Count > sum {
			out = append(out, captchaForceRuleView{Rest: true, Count: k.Count - sum})
		}
	}
	return out
}
