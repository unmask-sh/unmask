package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/rulehits"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The custom-rules tab: it lists the rules as cards -- the name, the
// condition lines, the action row and the rate row -- with hit counts, and
// a save in the cards' order gives a new rule an id, reads each card's
// lines by its key, normalises them, keeps an edited rule's id and stamps
// it, drops a rule left out, refuses a bad line naming the rule and the
// line, and renders the rule into http.inc.
func TestCustomRulesTabRoundTrip(t *testing.T) {
	h := newTestHandler(t)
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yml")
	s := h.snapshotSettings()
	s.Server.BasePath = "/unmask"
	s.Nginx.OutputDir = dir
	s.CommunityBans.MapDir = dir
	s.Nginx.CustomRules = []settings.CustomRule{{ID: "crold", Label: "old", Enabled: true, Action: "deny", CreatedAt: 1_700_000_000,
		Conditions: []settings.CustomCondition{{Kind: "ip", Values: []string{"192.0.2.0/24"}, Memo: "why"}}}}
	if err := settings.Save(s, cfgPath); err != nil {
		t.Fatal(err)
	}
	h.ConfigPath = cfgPath
	loaded, _ := settings.Load(cfgPath)
	h.SetSettings(loaded)
	h.RuleHits = rulehits.New()
	h.RuleHits.Hit("crold", time.Now())

	tab := func() string {
		req := httptest.NewRequest(http.MethodGet, "/unmask/admin/settings/custom-rules/", nil)
		req.SetPathValue("tab", "custom-rules")
		req.Header.Set("Cookie", "unmask_lang=ja")
		rr := httptest.NewRecorder()
		h.AdminSettingsIndex(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("tab: %d", rr.Code)
		}
		return rr.Body.String()
	}
	page := tab()
	for _, want := range []string{`name="cr_id" value="crold"`, `name="cr_key" value="crold"`, `name="cc_crold_kind"`, `<option value="ip" selected>`, `name="cc_crold_values" value="192.0.2.0/24"`, `name="cc_crold_memo" value="why"`,
		`name="cr_action" value="deny"`, `name="cr_act_crold" value="deny" checked`, "条件 (すべて満たす)", "<legend>アクション</legend>", "当たったら", "件/分 を超えたら", `class="cr-row cr-rate off"`, `<input type="checkbox" class="cr-rate-cb">`, "rate-limit タブと同じ (PoW → CAPTCHA)", "条件を追加", "直近 24h 1 件",
		`id="cr-template"`, `id="cc-template"`, `name="cc_KEY_kind"`, `id="cr-add"`, "新規ルール", `section=custom-rules`, "</html>"} {
		if !strings.Contains(page, want) {
			t.Errorf("tab lacks %q", want)
		}
	}

	// post answers the status and whether the save was refused (the error
	// travels as a flash cookie to the redirect's target).
	post := func(form url.Values) (int, string) {
		pr := httptest.NewRequest(http.MethodPost, "/unmask/admin/settings/save?section=custom-rules", strings.NewReader(form.Encode()))
		pr.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		pr.Header.Set("Cookie", "unmask_lang=ja")
		prr := httptest.NewRecorder()
		h.AdminSettingsSave(prr, pr)
		refused := ""
		for _, c := range prr.Result().Cookies() {
			if strings.Contains(c.Name, "err") && c.Value != "" && c.MaxAge >= 0 {
				v, _ := url.QueryUnescape(c.Value)
				refused = "err=" + v
			}
		}
		return prr.Code, refused
	}
	// Two cards: the old rule edited (first), a new one keyed new1 with
	// three lines, a CAPTCHA on a match and a rate limit that denies.
	code, loc := post(url.Values{
		"cr_id": {"crold", ""}, "cr_key": {"crold", "new1"}, "cr_created_at": {"1700000000", ""},
		"cr_label": {"old edited", " Scraper "}, "cr_enabled": {"1", "0"},
		"cc_crold_kind": {"ip"}, "cc_crold_values": {"192.0.2.0/24, 198.51.100.7"}, "cc_crold_memo": {"why"},
		"cc_new1_kind": {"ja4", "asn", "ua", "ip"}, "cc_new1_values": {"T13D1516H2_8daaf6152771_b0da82dd1658, t13d*", "AS4134, 16509", "python-requests|scrapy", ""}, "cc_new1_memo": {" seen in the hunt ", "", "", ""},
		"cr_action": {"deny", "captcha_only"}, "cr_rate": {"", "30"}, "cr_rate_action": {"deny", "deny"},
	})
	if code >= 400 || strings.Contains(loc, "err=") {
		t.Fatalf("save: %d %s", code, loc)
	}
	got, err := settings.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	rules := got.Nginx.CustomRules
	if len(rules) != 2 {
		t.Fatalf("rules after the save: %+v", rules)
	}
	old := rules[0]
	// (its over-limit answer was posted without a rate, so it is dropped)
	if old.ID != "crold" || old.Label != "old edited" || len(old.Conditions) != 1 || len(old.Conditions[0].Values) != 2 || old.RateAction != "" || old.CreatedAt != 1_700_000_000 || old.UpdatedAt == 0 {
		t.Errorf("the edited rule: %+v", old)
	}
	nw := rules[1]
	c := nw.Conditions
	if nw.ID == "" || nw.ID == "crold" || nw.Enabled || nw.Label != "Scraper" || len(c) != 3 ||
		c[0].Kind != "ja4" || c[0].Values[0] != "t13d1516h2_8daaf6152771_b0da82dd1658" || c[0].Values[1] != "t13d*" || c[0].Memo != "seen in the hunt" ||
		c[1].Kind != "asn" || c[1].Values[0] != "4134" || c[1].Values[1] != "16509" ||
		c[2].Kind != "ua" || c[2].Values[0] != "python-requests|scrapy" ||
		nw.Action != "captcha_only" || nw.RatePerMin != 30 || nw.RateAction != "deny" || nw.CreatedAt == 0 {
		t.Errorf("the new rule: %+v", nw)
	}
	// The rendered conf carries the enabled rule and not the disabled one.
	inc, err := os.ReadFile(filepath.Join(dir, "http.inc"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(inc), `"crold" "deny"`) || strings.Contains(string(inc), nw.ID) {
		t.Error("http.inc does not carry the enabled rule alone")
	}
	// A bad line is refused, naming the rule and the line, and nothing changes.
	code, loc = post(url.Values{"cr_id": {"crold"}, "cr_key": {"crold"}, "cr_label": {"old"}, "cr_enabled": {"1"}, "cc_crold_kind": {"ip", "ja4"}, "cc_crold_values": {"203.0.113.9", "not a ja4!"}, "cr_action": {"deny"}})
	if code >= 500 || !strings.Contains(loc, "err=") || !strings.Contains(loc, "rule 1 (old): condition 2 (ja4)") {
		t.Errorf("a bad line must be refused, naming the rule and the line: %d %s", code, loc)
	}
	// A rule whose lines are all empty is refused.
	code, loc = post(url.Values{"cr_id": {"crold"}, "cr_key": {"crold"}, "cr_label": {""}, "cr_enabled": {"1"}, "cc_crold_kind": {"ip"}, "cc_crold_values": {""}, "cr_action": {"deny"}})
	if code >= 500 || !strings.Contains(loc, "err=") || !strings.Contains(loc, "rule 1:") {
		t.Errorf("an empty rule must be refused: %d %s", code, loc)
	}
	again, _ := settings.Load(cfgPath)
	if len(again.Nginx.CustomRules) != 2 {
		t.Error("a refused save changed the rules")
	}
	// Leaving a card out removes the rule.
	code, _ = post(url.Values{"cr_id": {nw.ID}, "cr_key": {nw.ID}, "cr_created_at": {"1"}, "cr_label": {"Scraper"}, "cr_enabled": {"1"}, "cc_" + nw.ID + "_kind": {"ua"}, "cc_" + nw.ID + "_values": {"scrapy"}, "cr_action": {"monitor"}})
	if code >= 400 {
		t.Fatalf("second save: %d", code)
	}
	again, _ = settings.Load(cfgPath)
	if len(again.Nginx.CustomRules) != 1 || again.Nginx.CustomRules[0].ID != nw.ID {
		t.Errorf("the rule left out was not removed: %+v", again.Nginx.CustomRules)
	}
}

// A draft (?new=1&c=<kind>:<values>...) from the hunt or the assistant
// renders as an unsaved card with the lines filled in and no id, keyed
// "draft"; viewing it saves nothing, and the new-rule template is still
// there.
func TestCustomRulesTabDraft(t *testing.T) {
	h := newTestHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/settings/custom-rules/?new=1&label=scraper&c=ip%3A203.0.113.0%2F24%2C198.51.100.7&c=ja4%3At13d%2A&c=asn%3AAS4134&c=ua%3Apython-requests&action=deny&rate=30&rate_action=captcha_only", nil)
	req.SetPathValue("tab", "custom-rules")
	req.Header.Set("Cookie", "unmask_lang=ja")
	rr := httptest.NewRecorder()
	h.AdminSettingsIndex(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("tab: %d", rr.Code)
	}
	page := rr.Body.String()
	for _, want := range []string{`id="cr-draft"`, `name="cr_id" value=""`, `name="cr_key" value="draft"`, `name="cr_label" value="scraper"`,
		`name="cc_draft_values" value="203.0.113.0/24, 198.51.100.7"`, `name="cc_draft_values" value="t13d*"`, `name="cc_draft_values" value="AS4134"`, `name="cc_draft_values" value="python-requests"`,
		`name="cr_act_draft" value="deny" checked`, `<input type="checkbox" class="cr-rate-cb" checked>`, `name="cr_rate" min="0" value="30"`, `name="cr_ract_draft" value="captcha_only" checked`, "まだ保存されていません", `id="cr-template"`} {
		if !strings.Contains(page, want) {
			t.Errorf("draft tab lacks %q", want)
		}
	}
	if strings.Count(page, `name="cc_draft_kind"`) != 4 {
		t.Errorf("the draft has %d lines, want 4", strings.Count(page, `name="cc_draft_kind"`))
	}
	if strings.Contains(page, `id="cr-empty"`) {
		t.Error("the empty note shows beside a draft")
	}
	if n := h.snapshotSettings().Nginx.CustomRules; len(n) != 0 {
		t.Errorf("viewing a draft saved it: %+v", n)
	}
	// An unknown action falls back to CAPTCHA; without ?new=1 there is no draft.
	req = httptest.NewRequest(http.MethodGet, "/unmask/admin/settings/custom-rules/?new=1&c=ip%3A203.0.113.1&action=ban", nil)
	req.SetPathValue("tab", "custom-rules")
	rr = httptest.NewRecorder()
	h.AdminSettingsIndex(rr, req)
	if !strings.Contains(rr.Body.String(), `name="cr_act_draft" value="captcha_only" checked`) {
		t.Error("an unknown action did not fall back to captcha_only")
	}
	req = httptest.NewRequest(http.MethodGet, "/unmask/admin/settings/custom-rules/?c=ip%3A203.0.113.1", nil)
	req.SetPathValue("tab", "custom-rules")
	rr = httptest.NewRecorder()
	h.AdminSettingsIndex(rr, req)
	if strings.Contains(rr.Body.String(), `id="cr-draft"`) {
		t.Error("a draft without new=1")
	}
}

// The answer over a rule's rate limit that is not the rule's own is the
// rate-limit tab's mode, and the radio says which that is now -- the tab's
// current mode, not a fixed word -- so "as configured" never has to be
// looked up.  Deny shows without its status: it sits in parentheses.
func TestCustomRulesTabRateDefaultNamesTheMode(t *testing.T) {
	for mode, want := range map[string]string{
		"":             "rate-limit タブと同じ (PoW → CAPTCHA)",
		"captcha_only": "rate-limit タブと同じ (CAPTCHA)",
		"deny":         "rate-limit タブと同じ (遮断)",
	} {
		h := newTestHandler(t)
		s := h.snapshotSettings()
		s.RateLimit.Default.ChallengeMode = mode
		h.SetSettings(s)
		req := httptest.NewRequest(http.MethodGet, "/unmask/admin/settings/custom-rules/", nil)
		req.SetPathValue("tab", "custom-rules")
		req.Header.Set("Cookie", "unmask_lang=ja")
		rr := httptest.NewRecorder()
		h.AdminSettingsIndex(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("mode %q: tab %d", mode, rr.Code)
		}
		if !strings.Contains(rr.Body.String(), want) {
			t.Errorf("mode %q: the rate row's fallback does not say %q", mode, want)
		}
	}
}
