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

// The custom-rules tab: the operator's conjunction rules (settings.CustomRule)
// as a list of cards, each with its conditions, action, throttle and the
// day's hit count (rulehits), saved as parallel form fields in order.

type customRuleView struct {
	settings.CustomRule
	IPsText, JA4sText, CountriesText, ASNsText, HostsText string
	HitsDay                                               int
	LastHit                                               int64
	Lang                                                  i18n.Lang // the card template reads its labels through this
	Draft                                                 bool      // an unsaved card from the hunt or the assistant (?new=1)
	Blank                                                 bool      // the page's template for "add a rule"
}

func customRuleViewOf(r settings.CustomRule, lang i18n.Lang) customRuleView {
	v := customRuleView{CustomRule: r, Lang: lang,
		IPsText: strings.Join(r.IPs, ", "), JA4sText: strings.Join(r.JA4s, ", "),
		CountriesText: strings.Join(r.Countries, ", "), HostsText: strings.Join(r.Hosts, ", ")}
	asns := make([]string, len(r.ASNs))
	for i, a := range r.ASNs {
		asns[i] = strconv.FormatUint(uint64(a), 10)
	}
	v.ASNsText = strings.Join(asns, ", ")
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

// customRuleDraft reads a rule the hunt or the assistant proposed
// (settings.CustomRuleDraftQuery) into an unsaved card; nil without ?new=1.
// Nothing is validated here -- the card is the operator's to finish, and the
// save validates.
func customRuleDraft(q url.Values, lang i18n.Lang) *customRuleView {
	if q.Get("new") != "1" {
		return nil
	}
	r := settings.CustomRule{
		Label: q.Get("label"), Enabled: true,
		IPs: splitList(q.Get("ips")), JA4s: splitList(q.Get("ja4s")), Countries: splitList(q.Get("countries")),
		UA: q.Get("ua"), Path: q.Get("path"), Hosts: splitList(q.Get("hosts")),
		Action: q.Get("action"),
	}
	for _, a := range splitList(q.Get("asns")) {
		if n, err := strconv.ParseUint(strings.TrimPrefix(strings.ToUpper(a), "AS"), 10, 32); err == nil {
			r.ASNs = append(r.ASNs, uint32(n))
		}
	}
	if !settings.IsValidCustomRuleAction(r.Action) {
		r.Action = settings.GeoActionCaptchaOnly
	}
	if n, err := strconv.Atoi(q.Get("rate")); err == nil && n > 0 {
		r.RatePerMin = n
	}
	v := customRuleViewOf(r, lang)
	v.Draft = true
	return &v
}

// customRuleDraftLink: the hunt's "make a rule from this row" link -- one
// condition of the given kind (ips / ja4s / asns / ua), with a label.
func customRuleDraftLink(kind, value, label string) string {
	r := settings.CustomRule{Label: label, Action: settings.GeoActionCaptchaOnly}
	switch kind {
	case "ips":
		r.IPs = []string{value}
	case "ja4s":
		r.JA4s = []string{value}
	case "asns":
		if n, err := strconv.ParseUint(value, 10, 32); err == nil {
			r.ASNs = []uint32{uint32(n)}
		}
	case "ua":
		r.UA = value
	}
	return settings.CustomRuleDraftQuery(r)
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
			ID:        strings.TrimSpace(ids[i]),
			Label:     at("cr_label", i),
			Enabled:   at("cr_enabled", i) != "0",
			IPs:       splitList(at("cr_ips", i)),
			JA4s:      splitList(at("cr_ja4s", i)),
			Countries: splitList(at("cr_countries", i)),
			UA:        at("cr_ua", i),
			Path:      at("cr_path", i),
			Hosts:     splitList(at("cr_hosts", i)),
			Action:    at("cr_action", i),
		}
		for _, a := range splitList(at("cr_asns", i)) {
			a = strings.TrimPrefix(strings.ToUpper(a), "AS")
			n, err := strconv.ParseUint(a, 10, 32)
			if err != nil || n == 0 {
				return fmt.Errorf("rule %q: %q is not an AS number", rule.Label, a)
			}
			rule.ASNs = append(rule.ASNs, uint32(n))
		}
		if v := strings.TrimSpace(at("cr_rate", i)); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n < 0 {
				return fmt.Errorf("rule %q: the rate must be a number of requests per minute", rule.Label)
			}
			rule.RatePerMin = n
		}
		if rule.ID == "" {
			rule.ID = "cr" + strconv.FormatInt(now, 36) + strconv.Itoa(i)
		}
		if seen[rule.ID] {
			return fmt.Errorf("rule %q: duplicate id %s", rule.Label, rule.ID)
		}
		seen[rule.ID] = true
		if err := settings.NormalizeCustomRule(&rule); err != nil {
			return err
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

func customRuleSame(a, b settings.CustomRule) bool {
	a.CreatedAt, a.UpdatedAt, b.CreatedAt, b.UpdatedAt = 0, 0, 0, 0
	return fmt.Sprintf("%+v", a) == fmt.Sprintf("%+v", b)
}
