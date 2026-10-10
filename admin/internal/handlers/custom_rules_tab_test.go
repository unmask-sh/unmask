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

// The custom-rules tab: it lists the rules with their conditions and hit
// counts, and a save in the cards' order gives a new rule an id, normalises
// the conditions, keeps an edited rule's id and stamps it, drops a rule
// left out, refuses a bad condition, and renders the rule into http.inc.
func TestCustomRulesTabRoundTrip(t *testing.T) {
	h := newTestHandler(t)
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yml")
	s := h.snapshotSettings()
	s.Server.BasePath = "/unmask"
	s.Nginx.OutputDir = dir
	s.CommunityBans.MapDir = dir
	s.Nginx.CustomRules = []settings.CustomRule{{ID: "crold", Label: "old", Enabled: true, IPs: []string{"192.0.2.0/24"}, Action: "deny", CreatedAt: 1_700_000_000}}
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
	for _, want := range []string{`name="cr_id" value="crold"`, `name="cr_ips" value="192.0.2.0/24"`, `name="cr_action" value="deny"`, `name="cr_act_crold" value="deny" checked`, `name="cr_memo"`, "条件 (すべて満たす)", "適用 (ひとつ)", "直近 24h 1 件", `id="cr-template"`, `id="cr-add"`, `section=custom-rules`, "</html>"} {
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
	// Two cards: the old rule edited (first), a new one without an id.
	code, loc := post(url.Values{
		"cr_id": {"crold", ""}, "cr_created_at": {"1700000000", ""},
		"cr_label": {"old edited", " Scraper "}, "cr_memo": {"", " seen in the hunt "}, "cr_enabled": {"1", "0"},
		"cr_ips": {"192.0.2.0/24, 198.51.100.7", ""}, "cr_ja4s": {"", "T13D1516H2_8daaf6152771_b0da82dd1658, t13d*"},
		"cr_countries": {"", "cn, ru"}, "cr_asns": {"", "AS4134, 16509"},
		"cr_ua": {"", "python-requests|scrapy"}, "cr_path": {"", `^/search`}, "cr_hosts": {"", "Shop.Example.jp"},
		"cr_action": {"deny", "rate_limit"}, "cr_rate": {"", "30"},
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
	if old.ID != "crold" || old.Label != "old edited" || len(old.IPs) != 2 || old.CreatedAt != 1_700_000_000 || old.UpdatedAt == 0 {
		t.Errorf("the edited rule: %+v", old)
	}
	nw := rules[1]
	if nw.ID == "" || nw.ID == "crold" || nw.Enabled || nw.Label != "Scraper" || nw.JA4s[0] != "t13d1516h2_8daaf6152771_b0da82dd1658" || nw.JA4s[1] != "t13d*" ||
		nw.Countries[0] != "CN" || nw.Countries[1] != "RU" || nw.ASNs[0] != 4134 || nw.ASNs[1] != 16509 || nw.Hosts[0] != "shop.example.jp" ||
		nw.Action != "rate_limit" || nw.RatePerMin != 30 || nw.Memo != "seen in the hunt" || nw.CreatedAt == 0 {
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
	// A bad condition is refused, naming the rule by position and memo, and
	// nothing changes.
	code, loc = post(url.Values{"cr_id": {"crold"}, "cr_label": {"old"}, "cr_enabled": {"1"}, "cr_ips": {"not-an-address"}, "cr_action": {"deny"}})
	if code >= 500 || !strings.Contains(loc, "err=") || !strings.Contains(loc, "rule 1 (old)") {
		t.Errorf("a bad address must be refused, naming the rule: %d %s", code, loc)
	}
	// A rate limit without a rate is refused; a rate with another action is dropped.
	code, loc = post(url.Values{"cr_id": {"crold"}, "cr_label": {""}, "cr_enabled": {"1"}, "cr_ips": {"203.0.113.9"}, "cr_action": {"rate_limit"}, "cr_rate": {""}})
	if code >= 500 || !strings.Contains(loc, "err=") || !strings.Contains(loc, "rule 1:") {
		t.Errorf("a rate limit without a rate must be refused: %d %s", code, loc)
	}
	// A rule with no condition is refused too.
	code, loc = post(url.Values{"cr_id": {"crold"}, "cr_label": {"old"}, "cr_enabled": {"1"}, "cr_action": {"deny"}})
	if code >= 500 || !strings.Contains(loc, "err=") {
		t.Errorf("an empty rule must be refused: %d %s", code, loc)
	}
	again, _ := settings.Load(cfgPath)
	if len(again.Nginx.CustomRules) != 2 {
		t.Error("a refused save changed the rules")
	}
	// Leaving a card out removes the rule.
	code, _ = post(url.Values{"cr_id": {nw.ID}, "cr_created_at": {"1"}, "cr_label": {"Scraper"}, "cr_enabled": {"1"}, "cr_ua": {"scrapy"}, "cr_action": {"monitor"}})
	if code >= 400 {
		t.Fatalf("second save: %d", code)
	}
	again, _ = settings.Load(cfgPath)
	if len(again.Nginx.CustomRules) != 1 || again.Nginx.CustomRules[0].ID != nw.ID {
		t.Errorf("the rule left out was not removed: %+v", again.Nginx.CustomRules)
	}
}

// A draft (?new=1&...) from the hunt or the assistant renders as an unsaved
// card with the fields filled in and no id, and nothing is saved by viewing
// it; the add-a-rule template is still there.
func TestCustomRulesTabDraft(t *testing.T) {
	h := newTestHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/settings/custom-rules/?new=1&label=scraper&ips=203.0.113.0%2F24%2C198.51.100.7&ja4s=t13d%2A&asns=AS4134&ua=python-requests&action=deny&rate=30", nil)
	req.SetPathValue("tab", "custom-rules")
	req.Header.Set("Cookie", "unmask_lang=ja")
	rr := httptest.NewRecorder()
	h.AdminSettingsIndex(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("tab: %d", rr.Code)
	}
	page := rr.Body.String()
	for _, want := range []string{`id="cr-draft"`, `name="cr_id" value=""`, `name="cr_label" value="scraper"`, `name="cr_ips" value="203.0.113.0/24, 198.51.100.7"`, `name="cr_ja4s" value="t13d*"`, `name="cr_asns" value="4134"`, `name="cr_ua" value="python-requests"`, `name="cr_act_draft" value="deny" checked`, `name="cr_rate" min="1" value="30"`, "まだ保存されていません", `id="cr-template"`} {
		if !strings.Contains(page, want) {
			t.Errorf("draft tab lacks %q", want)
		}
	}
	if strings.Contains(page, `id="cr-empty"`) {
		t.Error("the empty note shows beside a draft")
	}
	if n := h.snapshotSettings().Nginx.CustomRules; len(n) != 0 {
		t.Errorf("viewing a draft saved it: %+v", n)
	}
	// An unknown action falls back to CAPTCHA; without ?new=1 there is no draft.
	req = httptest.NewRequest(http.MethodGet, "/unmask/admin/settings/custom-rules/?new=1&ips=203.0.113.1&action=ban", nil)
	req.SetPathValue("tab", "custom-rules")
	rr = httptest.NewRecorder()
	h.AdminSettingsIndex(rr, req)
	if !strings.Contains(rr.Body.String(), `name="cr_act_draft" value="captcha_only" checked`) {
		t.Error("an unknown action did not fall back to captcha_only")
	}
	req = httptest.NewRequest(http.MethodGet, "/unmask/admin/settings/custom-rules/?ips=203.0.113.1", nil)
	req.SetPathValue("tab", "custom-rules")
	rr = httptest.NewRecorder()
	h.AdminSettingsIndex(rr, req)
	if strings.Contains(rr.Body.String(), `id="cr-draft"`) {
		t.Error("a draft without new=1")
	}
}
