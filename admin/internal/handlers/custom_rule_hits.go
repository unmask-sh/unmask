package handlers

import (
	"regexp"
	"strings"
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
