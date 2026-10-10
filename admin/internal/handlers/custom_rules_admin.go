package handlers

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/i18n"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The custom-rules tab: the operator's rules (settings.CustomRule) as a
// list of cards -- a name, the condition lines (all must hold), one action
// with an optional rate limit beside it -- with the day's hit count
// (rulehits).  Each card posts its own fields: cr_* once per card, in
// order, and the condition lines as cc_<key>_kind / _values / _memo, keyed
// by the card (its id, or a key the page gives a new card) so reordering
// and adding cards cannot shift the lines between rules.

type customCondView struct {
	Kind       string
	ValuesText string // the values joined for the field; one regex as is
	Memo       string
}

type customRuleView struct {
	settings.CustomRule
	Key     string // the card's key for its condition fields: the id, "draft", or "tpl"
	Conds   []customCondView
	Kinds   []string // the condition kinds, for the selects
	HitsDay int
	LastHit int64
	Lang    i18n.Lang // the card template reads its labels through this
	Draft   bool      // an unsaved card from the hunt or the assistant (?new=1)
	Blank   bool      // the page's template for "new rule"
}

func customRuleViewOf(r settings.CustomRule, lang i18n.Lang) customRuleView {
	v := customRuleView{CustomRule: r, Key: r.ID, Lang: lang, Kinds: settings.CustomConditionKinds}
	for _, c := range r.Conditions {
		v.Conds = append(v.Conds, customCondView{Kind: c.Kind, ValuesText: strings.Join(c.Values, ", "), Memo: c.Memo})
	}
	return v
}

func (h *Handler) customRuleViews(rules []settings.CustomRule, lang i18n.Lang) []customRuleView {
	stats, _ := h.RuleHits.Snapshot(time.Now())
	out := make([]customRuleView, 0, len(rules))
	for _, r := range rules {
		v := customRuleViewOf(r, lang)
		if st, ok := stats[r.ID]; ok {
			v.HitsDay, v.LastHit = int(st.Day), st.Last
		}
		out = append(out, v)
	}
	return out
}

// customRuleBlank is the page's template for a new rule: one empty
// condition line, CAPTCHA on a match.
func customRuleBlank(lang i18n.Lang) customRuleView {
	v := customRuleViewOf(settings.CustomRule{Enabled: true, Action: settings.GeoActionCaptchaOnly, Conditions: []settings.CustomCondition{{Kind: settings.CustomCondIP}}}, lang)
	v.Key, v.Blank = "tpl", true
	return v
}

func (h *Handler) customRuleHitsSince() int64 {
	_, since := h.RuleHits.Snapshot(time.Now())
	return since
}

// splitList turns "a, b c" into ["a","b","c"].
func splitList(v string) []string {
	var out []string
	for _, f := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '、' }) {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

// condValues splits a line's field for its kind: a regex is one value as
// typed (a comma inside it is part of the pattern); the rest are lists.
func condValues(kind, field string) []string {
	if settings.CustomCondIsRegex(kind) {
		if field = strings.TrimSpace(field); field != "" {
			return []string{field}
		}
		return nil
	}
	return splitList(field)
}

// customRuleDraft reads a rule the hunt or the assistant proposed
// (settings.CustomRuleDraftQuery: c=<kind>:<values> per line) into an
// unsaved card; nil without ?new=1.  Nothing is validated here -- the card
// is the operator's to finish, and the save validates.
func customRuleDraft(q url.Values, lang i18n.Lang) *customRuleView {
	if q.Get("new") != "1" {
		return nil
	}
	r := settings.CustomRule{Label: q.Get("label"), Enabled: true, Action: q.Get("action")}
	for _, c := range q["c"] {
		kind, vals, ok := strings.Cut(c, ":")
		if !ok {
			continue
		}
		kind = strings.ToLower(strings.TrimSpace(kind))
		if v := condValues(kind, vals); settings.IsValidCustomConditionKind(kind) && len(v) > 0 {
			r.Conditions = append(r.Conditions, settings.CustomCondition{Kind: kind, Values: v})
		}
	}
	if len(r.Conditions) == 0 {
		r.Conditions = []settings.CustomCondition{{Kind: settings.CustomCondIP}}
	}
	if n, err := strconv.Atoi(q.Get("rate")); err == nil && n > 0 {
		r.RatePerMin = n
		if a := q.Get("rate_action"); settings.IsValidCustomRuleRateAction(a) {
			r.RateAction = a
		}
	}
	if !settings.IsValidCustomRuleAction(r.Action) {
		r.Action = settings.GeoActionCaptchaOnly
	}
	v := customRuleViewOf(r, lang)
	v.Key, v.Draft = "draft", true
	return &v
}

// customRuleDraftLink: the hunt's "make a rule from this row" link -- one
// condition line of the given kind, with a name.
func customRuleDraftLink(kind, value, label string) string {
	r := settings.CustomRule{Label: label, Action: settings.GeoActionCaptchaOnly}
	if settings.IsValidCustomConditionKind(kind) && strings.TrimSpace(value) != "" {
		r.Conditions = []settings.CustomCondition{{Kind: kind, Values: []string{strings.TrimSpace(value)}}}
	}
	return settings.CustomRuleDraftQuery(r)
}

// applyCustomRulesForm reads the tab's cards in order.  A card without an
// id is a new rule and gets one; a rule missing from the form is removed;
// an edit stamps UpdatedAt.  The first error names the rule and field.
func applyCustomRulesForm(dst *[]settings.CustomRule, r *http.Request) error {
	if err := r.ParseForm(); err != nil {
		return err
	}
	ids := r.Form["cr_id"]
	at := func(key string, i int) string {
		if vs := r.Form[key]; i < len(vs) {
			return vs[i]
		}
		return ""
	}
	prev := map[string]settings.CustomRule{}
	for _, old := range *dst {
		prev[old.ID] = old
	}
	now := time.Now().Unix()
	out := make([]settings.CustomRule, 0, len(ids))
	seen := map[string]bool{}
	for i := range ids {
		rule := settings.CustomRule{
			ID:         strings.TrimSpace(ids[i]),
			Label:      at("cr_label", i),
			Enabled:    at("cr_enabled", i) != "0",
			Action:     at("cr_action", i),
			RateAction: at("cr_rate_action", i),
		}
		// The condition lines, keyed by the card.
		key := strings.TrimSpace(at("cr_key", i))
		if key == "" {
			key = rule.ID
		}
		kinds, vals, memos := r.Form["cc_"+key+"_kind"], r.Form["cc_"+key+"_values"], r.Form["cc_"+key+"_memo"]
		for j, kind := range kinds {
			c := settings.CustomCondition{Kind: kind}
			if j < len(vals) {
				c.Values = condValues(strings.ToLower(strings.TrimSpace(kind)), vals[j])
			}
			if j < len(memos) {
				c.Memo = memos[j]
			}
			rule.Conditions = append(rule.Conditions, c)
		}
		if v := strings.TrimSpace(at("cr_rate", i)); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n < 0 {
				return fmt.Errorf("%s: the rate must be a number of requests per minute", customRuleRef(i, rule.Label))
			}
			rule.RatePerMin = n
		}
		if rule.ID == "" {
			rule.ID = "cr" + strconv.FormatInt(now, 36) + strconv.Itoa(i)
		}
		if seen[rule.ID] {
			return fmt.Errorf("%s: duplicate id %s", customRuleRef(i, rule.Label), rule.ID)
		}
		seen[rule.ID] = true
		if err := settings.NormalizeCustomRule(&rule); err != nil {
			return fmt.Errorf("%s: %w", customRuleRef(i, rule.Label), err)
		}
		// The dates: the stored rule's when it is known (an edit stamps
		// UpdatedAt here, not in the browser), else the ones the form
		// carried, else now.
		if old, ok := prev[rule.ID]; ok {
			rule.CreatedAt, rule.UpdatedAt = old.CreatedAt, old.UpdatedAt
			if !customRuleSame(old, rule) {
				rule.UpdatedAt = now
			}
		} else {
			rule.CreatedAt, _ = strconv.ParseInt(strings.TrimSpace(at("cr_created_at", i)), 10, 64)
			rule.UpdatedAt, _ = strconv.ParseInt(strings.TrimSpace(at("cr_updated_at", i)), 10, 64)
		}
		if rule.CreatedAt <= 0 {
			rule.CreatedAt = now
		}
		rule.UpdatedAt = clampUpdatedAt(rule.UpdatedAt, rule.CreatedAt, now)
		out = append(out, rule)
	}
	*dst = out
	return nil
}

// customRuleRef names a rule in an error: its position on the tab, and its
// name when it has one.
func customRuleRef(i int, name string) string {
	if name = strings.TrimSpace(name); name != "" {
		return fmt.Sprintf("rule %d (%s)", i+1, name)
	}
	return fmt.Sprintf("rule %d", i+1)
}

func customRuleSame(a, b settings.CustomRule) bool {
	a.CreatedAt, a.UpdatedAt, b.CreatedAt, b.UpdatedAt = 0, 0, 0, 0
	return fmt.Sprintf("%+v", a) == fmt.Sprintf("%+v", b)
}
