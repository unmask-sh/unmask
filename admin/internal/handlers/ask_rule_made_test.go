package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/rulehits"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// askRuleMadeHandler: a handler with the chat table, a config file and the
// rules given.
func askRuleMadeHandler(t *testing.T, rules []settings.CustomRule) (*Handler, string) {
	t.Helper()
	h := newTestHandler(t)
	if _, err := h.DB.Exec(`CREATE TABLE IF NOT EXISTS unmask_ai_chat (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, asked_at INTEGER NOT NULL, question TEXT NOT NULL, answer TEXT NOT NULL DEFAULT '', tools TEXT NOT NULL DEFAULT '', model TEXT NOT NULL DEFAULT '', in_tokens INTEGER NOT NULL DEFAULT 0, out_tokens INTEGER NOT NULL DEFAULT 0, err TEXT NOT NULL DEFAULT '', added_rules TEXT NOT NULL DEFAULT '')`); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yml")
	s := h.snapshotSettings()
	s.Server.BasePath = "/unmask"
	s.Nginx.OutputDir = dir
	s.CommunityBans.MapDir = dir
	s.Nginx.CustomRules = rules
	if err := settings.Save(s, cfgPath); err != nil {
		t.Fatal(err)
	}
	h.ConfigPath = cfgPath
	loaded, err := settings.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	h.SetSettings(loaded)
	h.RuleHits = rulehits.New()
	return h, cfgPath
}

func askRuleTurn(t *testing.T, h *Handler, user int64, link, added string) db.AIChat {
	t.Helper()
	row := db.AIChat{UserID: user, AskedAt: time.Now().Unix(), Question: "how to stop it?", Answer: "A rule for it:\n" + link + "\nSave it.", AddedRules: added}
	if err := h.DB.Gorm.Create(&row).Error; err != nil {
		t.Fatal(err)
	}
	return row
}

// The history shows a rule button as made while its rule is on the list:
// the rule added from it (recorded on the turn), even when the dialog
// changed its conditions, or a rule with the same conditions.  A recorded
// rule since removed offers the rule again.
func TestAskHistoryShowsMadeRules(t *testing.T) {
	h, _ := askRuleMadeHandler(t, []settings.CustomRule{
		{ID: "credited", Label: "edited in the dialog", Enabled: true, Action: "deny", Conditions: []settings.CustomCondition{{Kind: "ip", Values: []string{"203.0.113.0/24"}}}},
		{ID: "crsame", Label: "same conditions", Enabled: true, Action: "captcha_only", Conditions: []settings.CustomCondition{{Kind: "country", Values: []string{"CN", "RU"}}, {Kind: "ja4", Values: []string{"t13d1516h2_8daaf6152771_b0da82dd1658"}}}},
	})
	edited := "/admin/settings/custom-rules/?new=1&label=a&c=ip%3A203.0.113.5&action=deny"
	same := "/admin/settings/custom-rules/?new=1&label=b&c=ja4%3At13d1516h2_8daaf6152771_b0da82dd1658&c=country%3ARU%2CCN&action=deny"
	gone := "/admin/settings/custom-rules/?new=1&label=c&c=ip%3A192.0.2.9&action=deny"
	askRuleTurn(t, h, 7, edited, `{"`+edited+`":"credited"}`)
	askRuleTurn(t, h, 7, same, "")
	askRuleTurn(t, h, 7, gone, `{"`+gone+`":"crremoved"}`)

	rec := httptest.NewRecorder()
	h.AdminAskHistory(rec, askReq("GET", "/unmask/admin/ask/history/", "", "admin"))
	body := rec.Body.String()
	for _, want := range []string{
		`<a class="ask-rule added" data-added="1" href="/unmask/admin/settings/custom-rules/#rule-credited" target="_blank" rel="noopener">✓ ルール作成済み: edited in the dialog ↗</a>`,
		`<a class="ask-rule added" data-added="1" href="/unmask/admin/settings/custom-rules/#rule-crsame" target="_blank" rel="noopener">✓ ルール作成済み: same conditions ↗</a>`,
		`data-link="/admin/settings/custom-rules/?new=1&amp;label=c&amp;c=ip%3A192.0.2.9&amp;action=deny"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the history lacks %s", want)
		}
	}
	// (the page's script writes the made button too, so the server's are
	// counted by their href.)
	if n := strings.Count(body, `data-added="1" href="/unmask/admin/settings/custom-rules/#rule-`); n != 2 {
		t.Errorf("%d buttons shown as made; 2 rules are on the list", n)
	}
	if n := strings.Count(body, ">この条件でルールを作る</a>"); n != 1 {
		t.Errorf("%d buttons offer the rule; only the removed one should", n)
	}
}

// The dialog's save names the turn and the button: the rule's id goes on
// that turn, and the answer names the rule.  A path that is not one of the
// answer's buttons, or another account's turn, records nothing.
func TestCustomRuleAddRecordsTheAnswer(t *testing.T) {
	h, cfgPath := askRuleMadeHandler(t, nil)
	link := "/admin/settings/custom-rules/?new=1&label=scraper&c=ip%3A203.0.113.5&action=deny"
	mine := askRuleTurn(t, h, 7, link, "")
	theirs := askRuleTurn(t, h, 8, link, "")

	add := func(turn int64, button string) map[string]any {
		form := url.Values{"cr_id": {""}, "cr_key": {"draft"}, "cr_label": {"scraper, renamed"}, "cr_enabled": {"1"}, "cr_action": {"captcha_only"}, "cr_rate": {""}, "cr_rate_action": {""},
			"cc_draft_kind": {"ip"}, "cc_draft_values": {"203.0.113.0/24"}, "cc_draft_memo": {""}, "ask_id": {strconv.FormatInt(turn, 10)}, "ask_link": {button}}
		req := askReq(http.MethodPost, "/unmask/admin/settings/save?section=custom-rules-add", form.Encode(), "admin")
		req.Header.Set("Accept", "application/json")
		rr := httptest.NewRecorder()
		h.AdminSettingsSave(rr, req)
		var out map[string]any
		if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil || rr.Code != http.StatusOK || out["ok"] != true {
			t.Fatalf("add: %d %s", rr.Code, rr.Body.String())
		}
		return out
	}
	recorded := func(id int64) map[string]string {
		var row db.AIChat
		if err := h.DB.Gorm.First(&row, id).Error; err != nil {
			t.Fatal(err)
		}
		return askAddedRules(row.AddedRules)
	}

	out := add(mine.ID, link)
	rule, _ := out["rule"].(map[string]any)
	got, _ := settings.Load(cfgPath)
	if len(got.Nginx.CustomRules) != 1 || rule == nil || rule["id"] != got.Nginx.CustomRules[0].ID || rule["label"] != "scraper, renamed" {
		t.Fatalf("the answer does not name the added rule: %v (list %+v)", out, got.Nginx.CustomRules)
	}
	id := got.Nginx.CustomRules[0].ID
	if m := recorded(mine.ID); len(m) != 1 || m[link] != id {
		t.Fatalf("the turn's record: %v", m)
	}
	// Not one of the answer's buttons, and another account's turn: nothing.
	add(mine.ID, "/admin/settings/custom-rules/?new=1&c=ip%3A198.51.100.1")
	add(theirs.ID, link)
	if m := recorded(mine.ID); len(m) != 1 || m[link] != id {
		t.Errorf("a path the answer does not hold was recorded: %v", m)
	}
	if m := recorded(theirs.ID); len(m) != 0 {
		t.Errorf("another account's turn was written: %v", m)
	}

	// The history: the button is made, named as the rule is (the dialog
	// changed its conditions, so only the record ties them).
	rec := httptest.NewRecorder()
	h.AdminAskHistory(rec, askReq("GET", "/unmask/admin/ask/history/", "", "admin"))
	if body := rec.Body.String(); !strings.Contains(body, `href="/unmask/admin/settings/custom-rules/#rule-`+id+`"`) || !strings.Contains(body, "✓ ルール作成済み: scraper, renamed ↗") {
		t.Errorf("the history does not show the rule as made")
	}
	// The tab carries the anchor the button opens.
	rec = httptest.NewRecorder()
	req := askReq("GET", "/unmask/admin/settings/custom-rules/", "", "admin")
	req.SetPathValue("tab", "custom-rules")
	h.AdminSettingsIndex(rec, req)
	if !strings.Contains(rec.Body.String(), `id="rule-`+id+`"`) {
		t.Errorf("the custom-rules tab has no anchor for rule %s", id)
	}
}

// A fresh answer (no record yet) proposing a rule already on the list: the
// send response's part names the rule.
func TestAskMarkRulesOnAFreshAnswer(t *testing.T) {
	rules := []settings.CustomRule{{ID: "crlisted", Label: "listed", Enabled: true, Action: "deny", Conditions: []settings.CustomCondition{{Kind: "asn", Values: []string{"64500"}}}}}
	parts := splitFences("Stop it:\n/admin/settings/custom-rules/?new=1&label=x&c=asn%3A64500&action=captcha_only\nor this one:\n/admin/settings/custom-rules/?new=1&c=asn%3A64501")
	askMarkRules(parts, nil, rules)
	// What the page's script reads: the JSON of the parts.
	b, _ := json.Marshal(parts)
	var sent []map[string]any
	if err := json.Unmarshal(b, &sent); err != nil {
		t.Fatal(err)
	}
	named := 0
	for _, p := range sent {
		if _, ok := p["rule_id"]; !ok {
			continue
		}
		named++
		if link, _ := p["link"].(string); p["rule_id"] != "crlisted" || p["rule_name"] != "listed" || !strings.Contains(link, "asn%3A64500") {
			t.Errorf("the listed rule is not named right: %v", p)
		}
	}
	if named != 1 {
		t.Errorf("%d parts name a rule; one of the two proposals is on the list: %s", named, b)
	}
}
