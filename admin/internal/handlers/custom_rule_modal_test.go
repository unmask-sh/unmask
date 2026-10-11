package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/rulehits"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The ask page's rule modal: the proposed rule as the tab's card (with a
// rule of the same conditions named above it), and the one-rule save that
// adds it after the list's own, answered in JSON.
func TestCustomRuleModalDraftAndAdd(t *testing.T) {
	h := newTestHandler(t)
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yml")
	s := h.snapshotSettings()
	s.Server.BasePath = "/unmask"
	s.Nginx.OutputDir = dir
	s.CommunityBans.MapDir = dir
	s.Nginx.CustomRules = []settings.CustomRule{{ID: "crold", Label: "old", Enabled: true, Action: "deny", CreatedAt: 1_700_000_000,
		Conditions: []settings.CustomCondition{{Kind: "ip", Values: []string{"192.0.2.0/24", "198.51.100.7"}}}}}
	if err := settings.Save(s, cfgPath); err != nil {
		t.Fatal(err)
	}
	h.ConfigPath = cfgPath
	loaded, _ := settings.Load(cfgPath)
	h.SetSettings(loaded)
	h.RuleHits = rulehits.New()

	card := func(q string) string {
		req := httptest.NewRequest(http.MethodGet, "/unmask/admin/settings/custom-rules/draft?"+q, nil)
		req.Header.Set("Cookie", "unmask_lang=ja")
		rr := httptest.NewRecorder()
		h.AdminCustomRuleDraftCard(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("draft card: %d", rr.Code)
		}
		return rr.Body.String()
	}
	body := card("label=scraper&c=ip%3A203.0.113.5&action=deny")
	for _, want := range []string{`class="cr-rule cr-draft editing" data-cr data-key="draft"`, `name="cr_label" value="scraper"`, `name="cc_draft_values" value="203.0.113.5"`, `name="cr_action" value="deny"`, `class="cr-draft-note"`} {
		if !strings.Contains(body, want) {
			t.Errorf("the card lacks %q", want)
		}
	}
	if strings.Contains(body, `class="cr-dup"`) || strings.Contains(body, "<html") {
		t.Error("a new rule is named a duplicate, or the card came as a page")
	}
	// The same conditions, written in another order: the old rule is named.
	if body = card("c=ip%3A198.51.100.7%2C192.0.2.0%2F24&action=captcha_only"); !strings.Contains(body, `class="cr-dup"`) || !strings.Contains(body, "1 (old)") {
		t.Errorf("the duplicate is not named: %s", body[:min(len(body), 300)])
	}

	add := func(form url.Values) (int, map[string]any) {
		req := httptest.NewRequest(http.MethodPost, "/unmask/admin/settings/save?section=custom-rules-add", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Cookie", "unmask_lang=ja")
		rr := httptest.NewRecorder()
		h.AdminSettingsSave(rr, req)
		var out map[string]any
		if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
			t.Fatalf("not JSON (%d): %s", rr.Code, rr.Body.String())
		}
		return rr.Code, out
	}
	form := url.Values{"cr_id": {""}, "cr_key": {"draft"}, "cr_label": {"scraper"}, "cr_enabled": {"1"}, "cr_action": {"deny"}, "cr_rate": {""}, "cr_rate_action": {""},
		"cc_draft_kind": {"ip"}, "cc_draft_values": {"203.0.113.5"}, "cc_draft_memo": {""}}
	code, out := add(form)
	if code != http.StatusOK || out["ok"] != true || out["reload"] != true {
		t.Fatalf("add: %d %v", code, out)
	}
	got, _ := settings.Load(cfgPath)
	rules := got.Nginx.CustomRules
	if len(rules) != 2 || rules[0].ID != "crold" || len(rules[0].Conditions[0].Values) != 2 || rules[1].Label != "scraper" || rules[1].ID == "" || rules[1].Conditions[0].Values[0] != "203.0.113.5" {
		t.Fatalf("after the add: %+v", rules)
	}
	// Again, at once: a second rule with an id of its own, in the id's alphabet.
	if code, out = add(form); code != http.StatusOK || out["ok"] != true {
		t.Fatalf("second add: %d %v", code, out)
	}
	got, _ = settings.Load(cfgPath)
	if rules = got.Nginx.CustomRules; len(rules) != 3 || rules[2].ID == rules[1].ID {
		t.Fatalf("ids: %+v", rules)
	}
	for _, r := range rules {
		if c := r; settings.NormalizeCustomRule(&c) != nil {
			t.Errorf("rule %q no longer passes the tab's own check", r.ID)
		}
	}
	// A rule that does nothing is refused, in JSON, and nothing is added.
	form.Set("cr_action", "monitor")
	if code, out = add(form); code != http.StatusBadRequest || out["ok"] != false || out["error"] == "" {
		t.Errorf("a rule that does nothing: %d %v", code, out)
	}
	if got, _ = settings.Load(cfgPath); len(got.Nginx.CustomRules) != 3 {
		t.Errorf("a refused add changed the list: %d rules", len(got.Nginx.CustomRules))
	}
}

// freeCustomRuleID steps past ids already held, inside the id's alphabet.
func TestFreeCustomRuleID(t *testing.T) {
	rules := []settings.CustomRule{{ID: "crabc0"}, {ID: "crabc01"}}
	if got := freeCustomRuleID(rules, "crabc0"); got != "crabc02" {
		t.Errorf("got %q", got)
	}
	if got := freeCustomRuleID(rules, "crxyz0"); got != "crxyz0" {
		t.Errorf("a free id was changed: %q", got)
	}
}
