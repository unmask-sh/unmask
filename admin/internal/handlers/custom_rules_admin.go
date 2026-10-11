package handlers

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

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
	// RateDefault names what the rate limit answers with when the rule
	// picks no answer of its own: the rate-limit tab's mode, as the row's
	// radios name it, so the operator need not look it up.
	RateDefault string
}

func customRuleViewOf(r settings.CustomRule, lang i18n.Lang, rateDefault string) customRuleView {
	v := customRuleView{CustomRule: r, Key: r.ID, Lang: lang, Kinds: settings.CustomConditionKinds, RateDefault: rateDefault}
	for _, c := range r.Conditions {
		v.Conds = append(v.Conds, customCondView{Kind: c.Kind, ValuesText: strings.Join(c.Values, ", "), Memo: c.Memo})
	}
	return v
}

func (h *Handler) customRuleViews(rules []settings.CustomRule, lang i18n.Lang) []customRuleView {
	stats, _ := h.RuleHits.Snapshot(time.Now())
	out := make([]customRuleView, 0, len(rules))
	def := h.customRuleRateDefault(lang)
	for _, r := range rules {
		v := customRuleViewOf(r, lang, def)
		if st, ok := stats[r.ID]; ok {
			v.HitsDay, v.LastHit = int(st.Day), st.Last
		}
		out = append(out, v)
	}
	return out
}

// customRuleRateDefault is the answer over a rule's rate limit when the
// rule picks none of its own -- the rate-limit tab's mode -- named as the
// row's radios name it (deny without its status: it sits in parentheses).
func (h *Handler) customRuleRateDefault(lang i18n.Lang) string {
	mode := h.snapshotSettings().RateLimit.Default.ResolvedChallengeMode()
	if mode == settings.RateChallengeDeny {
		return i18n.T(lang, "settings.cr.mode_deny")
	}
	return i18n.T(lang, "settings.cr.act_"+mode)
}

// customRuleBlank is the page's template for a new rule: one empty
// condition line, CAPTCHA on a match.
func customRuleBlank(lang i18n.Lang, rateDefault string) customRuleView {
	v := customRuleViewOf(settings.CustomRule{Enabled: true, Action: settings.GeoActionCaptchaOnly, Conditions: []settings.CustomCondition{{Kind: settings.CustomCondIP}}}, lang, rateDefault)
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
func customRuleDraft(q url.Values, lang i18n.Lang, rateDefault string) *customRuleView {
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
	v := customRuleViewOf(r, lang, rateDefault)
	v.Key, v.Draft = "draft", true
	return &v
}

// huntCustomRuleDraft turns the hunt's active filters into a custom-rule
// draft (settings.CustomRuleDraftQuery): one condition line per filter, each
// as the rule needs it -- the address and the network as they are, the
// fingerprint whole when it is one and as a prefix otherwise, the user-agent
// substring quoted into a regex.  Empty when no filter that can be a
// condition is active (a phase or a Ref ID is not one).  A ranking row has
// one key, and a rule of one condition is what BAN and the per-axis buttons
// already make, so the rows carry no entry; the filters, several at once,
// are where the combination a rule is for comes together.
func huntCustomRuleDraft(ip, ja4, ua string, asn int, lang i18n.Lang) string {
	r := settings.CustomRule{Action: settings.GeoActionCaptchaOnly}
	var parts []string
	add := func(kind, v, shown string) {
		r.Conditions = append(r.Conditions, settings.CustomCondition{Kind: kind, Values: []string{v}})
		parts = append(parts, shown)
	}
	if ip = strings.TrimSpace(ip); ip != "" {
		add(settings.CustomCondIP, ip, ip)
	}
	if ja4 = strings.ToLower(strings.TrimSpace(ja4)); ja4 != "" {
		v := ja4
		if !huntJA4WholeRE.MatchString(ja4) {
			v = strings.TrimRight(ja4, "*") + "*"
		}
		add(settings.CustomCondJA4, v, ja4)
	}
	if ua = strings.TrimSpace(ua); ua != "" {
		add(settings.CustomCondUA, regexp.QuoteMeta(ua), ua)
	}
	if asn > 0 {
		add(settings.CustomCondASN, strconv.Itoa(asn), "AS"+strconv.Itoa(asn))
	}
	if len(r.Conditions) == 0 {
		return ""
	}
	// The name is a suggestion, kept inside the rule's limit (the save
	// refuses a longer one rather than cutting it).
	r.Label = i18n.Tf(lang, "hunt.cr_name", strings.Join(parts, " + "))
	if utf8.RuneCountInString(r.Label) > settings.CustomRuleLabelMax {
		r.Label = i18n.Tf(lang, "hunt.cr_name", parts[0]+" + …")
	}
	return settings.CustomRuleDraftQuery(r)
}

// A whole JA4 (t13d1516h2_8daaf6152771_b0da82dd1658); anything shorter the
// hunt matched as a substring, which a rule can only take as a prefix.
var huntJA4WholeRE = regexp.MustCompile(`^[a-z][0-9]{2}[a-z][0-9]{4}[a-z0-9]{2}_[0-9a-f]{12}_[0-9a-f]{12}$`)

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

// AdminCustomRuleDraftCard: GET {base}/admin/settings/custom-rules/draft --
// a proposed rule (settings.CustomRuleDraftQuery, as the hunt and the
// assistant link it) as the custom-rules tab's card, open for editing.  The
// ask page shows it in a modal and saves it with section=custom-rules-add.
// A rule already on the list with the same conditions is named above it,
// so a second click on the same answer does not add the rule twice unseen.
func (h *Handler) AdminCustomRuleDraftCard(w http.ResponseWriter, r *http.Request) {
	tmpl, err := loadDashboardTemplate()
	if err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	lang := i18n.Resolve(r)
	q := r.URL.Query()
	q.Set("new", "1")
	card := customRuleDraft(q, lang, h.customRuleRateDefault(lang))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	data := map[string]any{"Card": card, "Dup": customRuleWithConditions(h.cfg().Nginx.CustomRules, card.Conditions)}
	if err := tmpl.ExecuteTemplate(w, "cr_draft_body", data); err != nil {
		log.Printf("custom rule draft card: %v", err)
	}
}

// customRuleWithConditions names the first rule whose conditions are the
// same as conds (each kind with the same values, in any order), or "".
func customRuleWithConditions(rules []settings.CustomRule, conds []settings.CustomCondition) string {
	sig := func(cs []settings.CustomCondition) string {
		var lines []string
		for _, c := range cs {
			vals := make([]string, 0, len(c.Values))
			for _, v := range c.Values {
				vals = append(vals, strings.ToLower(strings.TrimSpace(v)))
			}
			sort.Strings(vals)
			lines = append(lines, strings.ToLower(strings.TrimSpace(c.Kind))+":"+strings.Join(vals, ","))
		}
		sort.Strings(lines)
		return strings.Join(lines, "|")
	}
	want := sig(conds)
	for i, r := range rules {
		if len(r.Conditions) > 0 && sig(r.Conditions) == want {
			return strings.TrimPrefix(customRuleRef(i, r.Label), "rule ")
		}
	}
	return ""
}

// freeCustomRuleID is id, or id with a suffix when a rule already holds it:
// a rule added on its own gets the id a new card gets (the time and its
// position), which a rule saved in the same second can hold already.  The
// suffix keeps to the id's alphabet (settings: [a-z0-9], 24 at most).
func freeCustomRuleID(rules []settings.CustomRule, id string) string {
	taken := map[string]bool{}
	for _, r := range rules {
		taken[r.ID] = true
	}
	out := id
	for n := int64(1); taken[out]; n++ {
		out = id + strconv.FormatInt(n, 36)
	}
	return out
}
