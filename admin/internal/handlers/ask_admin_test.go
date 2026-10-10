package handlers

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

func askReq(method, target, body string, role string) *http.Request {
	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, target, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		req = httptest.NewRequest(method, target, nil)
	}
	req.Header.Set("Cookie", "unmask_lang=ja")
	if role != "" {
		req = req.WithContext(context.WithValue(req.Context(), sessionCtxKey{}, &SessionPayload{UserID: 7, Role: role, Exp: time.Now().Add(time.Hour).Unix()}))
	}
	return req
}

// The page: a notice while no model is configured, the composer for an admin
// once one is, the history afterwards; a question runs the chat loop against
// the provider, stores the turn with its tool trace, and the account's
// history can be cleared.
func TestAskPageAndSend(t *testing.T) {
	h := newTestHandler(t)
	if _, err := h.DB.Exec(`CREATE TABLE IF NOT EXISTS unmask_ai_chat (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, asked_at INTEGER NOT NULL, question TEXT NOT NULL, answer TEXT NOT NULL DEFAULT '', tools TEXT NOT NULL DEFAULT '', model TEXT NOT NULL DEFAULT '', in_tokens INTEGER NOT NULL DEFAULT 0, out_tokens INTEGER NOT NULL DEFAULT 0, err TEXT NOT NULL DEFAULT '')`); err != nil {
		t.Fatal(err)
	}
	if _, err := h.DB.Exec(`CREATE TABLE IF NOT EXISTS unmask_ban (id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT NOT NULL, ja4 TEXT NOT NULL, source TEXT NOT NULL, reason TEXT, banned_at INTEGER NOT NULL, expires_at INTEGER NOT NULL DEFAULT 0, banned_by TEXT, action TEXT NOT NULL DEFAULT '', scope TEXT NOT NULL DEFAULT 'ip_ja4')`); err != nil {
		t.Fatal(err)
	}
	s := h.snapshotSettings()
	s.Server.BasePath = "/unmask"
	h.SetSettings(s)

	rec := httptest.NewRecorder()
	h.AdminAsk(rec, askReq("GET", "/unmask/admin/ask/", "", "admin"))
	body := rec.Body.String()
	if rec.Code != 200 || !strings.Contains(body, `id="ask-off"`) || strings.Contains(body, `id="ask-form"`) {
		t.Fatalf("without a model: code %d, off-notice %v, form %v", rec.Code, strings.Contains(body, `id="ask-off"`), strings.Contains(body, `id="ask-form"`))
	}
	if !strings.Contains(body, "/unmask/admin/settings/ai-advisor/") {
		t.Error("the notice does not link the AI settings")
	}
	rec = httptest.NewRecorder()
	h.AdminAskSend(rec, askReq("POST", "/unmask/admin/ask/send", "q=hi", "admin"))
	if rec.Code != 400 || !strings.Contains(rec.Body.String(), "AI advisor") {
		t.Errorf("send without a model: %d %s", rec.Code, rec.Body.String())
	}

	// A provider that asks for the bans and then answers.
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n++
		b, _ := io.ReadAll(r.Body)
		if n == 1 {
			if !strings.Contains(string(b), "日本語") {
				t.Error("the question did not ask for Japanese")
			}
			io.WriteString(w, `{"choices":[{"message":{"role":"assistant","content":"","tool_calls":[{"id":"c1","type":"function","function":{"name":"bans","arguments":"{\"limit\":5}"}}]}}],"usage":{"prompt_tokens":11,"completion_tokens":2}}`)
			return
		}
		if !strings.Contains(string(b), `"role":"tool"`) {
			t.Error("the tool result did not go back")
		}
		io.WriteString(w, `{"choices":[{"message":{"role":"assistant","content":"BAN は 0 件です。/admin/bans/ を見てください。\n`+"```"+`\nbans=0\n`+"```"+`"}}],"usage":{"prompt_tokens":30,"completion_tokens":8}}`)
	}))
	defer srv.Close()
	s = h.snapshotSettings()
	s.AIAdvisor = settings.AIAdvisorConfig{Enabled: true, Provider: "openai", Endpoint: srv.URL, APIKey: "k", Model: "m"}
	h.SetSettings(s)

	rec = httptest.NewRecorder()
	h.AdminAsk(rec, askReq("GET", "/unmask/admin/ask/", "", "admin"))
	body = rec.Body.String()
	for _, want := range []string{`id="ask-form"`, `id="ask-empty"`, `data-maxchars="2000"`, `openai · m`} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	rec = httptest.NewRecorder()
	h.AdminAsk(rec, askReq("GET", "/unmask/admin/ask/", "", "viewer"))
	if b := rec.Body.String(); strings.Contains(b, `id="ask-form"`) || !strings.Contains(b, `id="ask-viewer"`) {
		t.Error("a viewer got the composer, or no note")
	}

	rec = httptest.NewRecorder()
	h.AdminAskSend(rec, askReq("POST", "/unmask/admin/ask/send", url.Values{"q": {"BAN は?"}}.Encode(), "admin"))
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || rec.Code != 200 || out["ok"] != true {
		t.Fatalf("send: %d %s (%v)", rec.Code, rec.Body.String(), err)
	}
	if !strings.HasPrefix(out["answer"].(string), "BAN は 0 件です。") || out["in_tokens"] != float64(41) || out["out_tokens"] != float64(10) || out["model"] != "m" {
		t.Errorf("answer %v", out)
	}
	tools := out["tools"].([]any)
	if len(tools) != 1 || tools[0].(map[string]any)["name"] != "bans" {
		t.Errorf("tools %v", tools)
	}
	var rows []db.AIChat
	if err := h.DB.Gorm.Find(&rows).Error; err != nil || len(rows) != 1 || rows[0].UserID != 7 || rows[0].Answer == "" || !strings.Contains(rows[0].Tools, `"bans"`) {
		t.Fatalf("stored turn: %v %+v", err, rows)
	}
	var runs []db.AdvisorRun
	if err := h.DB.Gorm.Find(&runs).Error; err != nil || len(runs) != 1 || !strings.HasPrefix(runs[0].ResultKey, "chat|openai|m") || runs[0].InTokens != 41 {
		t.Errorf("run log: %v %+v", err, runs)
	}
	// The latest turn is on the ask tab, whole, with the tool chip, the
	// token line and a copy; the clear and the delete are the history tab's.
	rec = httptest.NewRecorder()
	h.AdminAsk(rec, askReq("GET", "/unmask/admin/ask/", "", "admin"))
	body = rec.Body.String()
	for _, want := range []string{"BAN は 0 件です。", `<a href="/unmask/admin/bans/">/admin/bans/</a>`, "<pre>bans=0</pre>", `class="tool-chip"`, "tokens 入力 41 / 出力 10", `class="a-copy"`, `class="ask-tabs"`} {
		if !strings.Contains(body, want) {
			t.Errorf("ask tab lacks %q", want)
		}
	}
	for _, gone := range []string{`action="/unmask/admin/ask/clear"`, `action="/unmask/admin/ask/delete"`, `class="a folded"`} {
		if strings.Contains(body, gone) {
			t.Errorf("ask tab carries %q", gone)
		}
	}
	rec = httptest.NewRecorder()
	h.AdminAskHistory(rec, askReq("GET", "/unmask/admin/ask/history/", "", "admin"))
	body = rec.Body.String()
	// The answer has several lines, so the history folds it.
	for _, want := range []string{`class="a folded"`, `class="a-toggle"`, `class="a-copy"`, `action="/unmask/admin/ask/delete"`, `action="/unmask/admin/ask/clear"`, "BAN は 0 件です。"} {
		if !strings.Contains(body, want) {
			t.Errorf("history tab lacks %q", want)
		}
	}
	// A viewer reads the history but gets no delete or clear.
	rec = httptest.NewRecorder()
	h.AdminAskHistory(rec, askReq("GET", "/unmask/admin/ask/history/", "", "viewer"))
	if body = rec.Body.String(); strings.Contains(body, `action="/unmask/admin/ask/delete"`) || strings.Contains(body, `action="/unmask/admin/ask/clear"`) {
		t.Error("a viewer is offered a delete or a clear")
	}
	// Refusals: empty, too long.
	rec = httptest.NewRecorder()
	h.AdminAskSend(rec, askReq("POST", "/unmask/admin/ask/send", "q=+", "admin"))
	if rec.Code != 400 {
		t.Errorf("empty question: %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	h.AdminAskSend(rec, askReq("POST", "/unmask/admin/ask/send", url.Values{"q": {strings.Repeat("あ", askQuestionMax+1)}}.Encode(), "admin"))
	if rec.Code != 400 || !strings.Contains(rec.Body.String(), "2000") {
		t.Errorf("long question: %d %s", rec.Code, rec.Body.String())
	}
	// Clear: the account's rows go, the page returns.
	rec = httptest.NewRecorder()
	h.AdminAskClear(rec, askReq("POST", "/unmask/admin/ask/clear", "", "admin"))
	if rec.Code != http.StatusSeeOther || !strings.Contains(rec.Header().Get("Location"), "/unmask/admin/ask/") {
		t.Errorf("clear: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	if err := h.DB.Gorm.Find(&rows).Error; err != nil || len(rows) != 0 {
		t.Errorf("rows after clear: %v %d", err, len(rows))
	}
}

// A failed turn is stored with its error and reported as one.
func TestAskSendFailureIsKept(t *testing.T) {
	h := newTestHandler(t)
	if _, err := h.DB.Exec(`CREATE TABLE IF NOT EXISTS unmask_ai_chat (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, asked_at INTEGER NOT NULL, question TEXT NOT NULL, answer TEXT NOT NULL DEFAULT '', tools TEXT NOT NULL DEFAULT '', model TEXT NOT NULL DEFAULT '', in_tokens INTEGER NOT NULL DEFAULT 0, out_tokens INTEGER NOT NULL DEFAULT 0, err TEXT NOT NULL DEFAULT '')`); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"bad key"}`, http.StatusUnauthorized)
	}))
	defer srv.Close()
	s := h.snapshotSettings()
	s.Server.BasePath = "/unmask"
	s.AIAdvisor = settings.AIAdvisorConfig{Enabled: true, Provider: "openai", Endpoint: srv.URL, APIKey: "k", Model: "m"}
	h.SetSettings(s)
	rec := httptest.NewRecorder()
	h.AdminAskSend(rec, askReq("POST", "/unmask/admin/ask/send", "q=x", "admin"))
	if rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), "401") {
		t.Errorf("failure: %d %s", rec.Code, rec.Body.String())
	}
	var rows []db.AIChat
	if err := h.DB.Gorm.Find(&rows).Error; err != nil || len(rows) != 1 || rows[0].Err == "" || rows[0].Answer != "" {
		t.Errorf("stored failure: %v %+v", err, rows)
	}
	rec = httptest.NewRecorder()
	h.AdminAsk(rec, askReq("GET", "/unmask/admin/ask/", "", "admin"))
	if b := rec.Body.String(); !strings.Contains(b, `class="a fail"`) || !strings.Contains(b, "失敗: ") {
		t.Error("the failed turn is not shown as failed")
	}
}

func TestAnswerLinksAdminPaths(t *testing.T) {
	parts := splitFences("BAN は /admin/bans/ で、設定は /admin/settings/ai-advisor/ です。外部は https://example.com/admin/x ではない。")
	var links []string
	for _, p := range parts {
		if p.Link != "" {
			links = append(links, p.Link)
			if p.Text != p.Link {
				t.Errorf("link text %q != %q", p.Text, p.Link)
			}
		}
	}
	// The host of a URL is not this admin: its /admin/x still links (it is
	// the same path under this base), and the sentence's full stops stay text.
	want := []string{"/admin/bans/", "/admin/settings/ai-advisor/", "/admin/x"}
	if strings.Join(links, " ") != strings.Join(want, " ") {
		t.Errorf("links %v, want %v", links, want)
	}
	if p := splitFences("see /admin/hunt/."); len(p) != 3 || p[1].Link != "/admin/hunt/" || p[2].Text != "." {
		t.Errorf("trailing stop: %+v", p)
	}
	// The page propose_custom_rule returns is a button, not a URL to read;
	// the whole percent-encoded query is the link.
	p := splitFences("A rule:\n/admin/settings/custom-rules/?new=1&label=scraper&ips=203.0.113.0%2F24&action=deny\nSave it there.")
	var rule *askPart
	for i := range p {
		if p[i].Rule {
			rule = &p[i]
		}
	}
	if rule == nil || rule.Link != "/admin/settings/custom-rules/?new=1&label=scraper&ips=203.0.113.0%2F24&action=deny" {
		t.Errorf("rule part: %+v", p)
	}
	if p := splitFences("/admin/settings/custom-rules/"); len(p) != 1 || p[0].Rule {
		t.Errorf("the bare tab is a plain link: %+v", p)
	}
}

func TestSplitFences(t *testing.T) {
	parts := splitFences("a\n```sh\nls\n```\nb")
	// The newline after a fence belongs to the fence (the page's script splits
	// the same way), so the prose after a block starts on its own text.
	if len(parts) != 3 || parts[0].Code || parts[0].Text != "a\n" || !parts[1].Code || parts[1].Text != "ls" || parts[2].Code || parts[2].Text != "b" {
		t.Errorf("%+v", parts)
	}
	if p := splitFences("plain"); len(p) != 1 || p[0].Code {
		t.Errorf("%+v", p)
	}
	if p := splitFences(""); len(p) != 0 {
		t.Errorf("%+v", p)
	}
}

// A delete removes one of the account's own turns, never another account's,
// and lands on the history tab; a short answer stays whole there.
func TestAskDeleteOwnTurn(t *testing.T) {
	h := newTestHandler(t)
	if _, err := h.DB.Exec(`CREATE TABLE IF NOT EXISTS unmask_ai_chat (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, asked_at INTEGER NOT NULL, question TEXT NOT NULL, answer TEXT NOT NULL DEFAULT '', tools TEXT NOT NULL DEFAULT '', model TEXT NOT NULL DEFAULT '', in_tokens INTEGER NOT NULL DEFAULT 0, out_tokens INTEGER NOT NULL DEFAULT 0, err TEXT NOT NULL DEFAULT '')`); err != nil {
		t.Fatal(err)
	}
	s := h.snapshotSettings()
	s.Server.BasePath = "/unmask"
	h.SetSettings(s)
	now := time.Now().Unix()
	mine := []db.AIChat{
		{UserID: 7, AskedAt: now - 20, Question: "first, long", Answer: strings.Repeat("長い答え ", 60)},
		{UserID: 7, AskedAt: now - 10, Question: "second, short", Answer: "短い"},
	}
	other := db.AIChat{UserID: 8, AskedAt: now - 5, Question: "theirs", Answer: "x"}
	for i := range mine {
		if err := h.DB.Gorm.Create(&mine[i]).Error; err != nil {
			t.Fatal(err)
		}
	}
	if err := h.DB.Gorm.Create(&other).Error; err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	h.AdminAskHistory(rec, askReq("GET", "/unmask/admin/ask/history/", "", "admin"))
	body := rec.Body.String()
	// (the page's script carries the copy button's markup once more, so the
	// turns are counted by their ids.)
	if strings.Count(body, `data-id="`) != 2 || strings.Count(body, `class="a-copy"`) < 2 || strings.Count(body, `class="a folded"`) != 1 || strings.Contains(body, "theirs") {
		t.Errorf("history: turns=%d copies=%d folded=%d theirs=%v", strings.Count(body, `data-id="`), strings.Count(body, `class="a-copy"`), strings.Count(body, `class="a folded"`), strings.Contains(body, "theirs"))
	}
	if strings.Index(body, "second, short") > strings.Index(body, "first, long") {
		t.Error("the history must read newest first")
	}
	// The ask tab: the latest alone, whole.
	rec = httptest.NewRecorder()
	h.AdminAsk(rec, askReq("GET", "/unmask/admin/ask/", "", "admin"))
	if body = rec.Body.String(); strings.Contains(body, "first, long") || !strings.Contains(body, "second, short") || !strings.Contains(body, `class="cnt">2<`) {
		t.Error("the ask tab must show the latest turn alone, and the history count")
	}
	// Delete the first; another account's id is a no-op.
	rec = httptest.NewRecorder()
	h.AdminAskDelete(rec, askReq("POST", "/unmask/admin/ask/delete", "id="+strconv.FormatInt(mine[0].ID, 10), "admin"))
	if rec.Code != 303 || rec.Header().Get("Location") != "/unmask/admin/ask/history/" {
		t.Errorf("delete: %d %s", rec.Code, rec.Header().Get("Location"))
	}
	rec = httptest.NewRecorder()
	h.AdminAskDelete(rec, askReq("POST", "/unmask/admin/ask/delete", "id="+strconv.FormatInt(other.ID, 10), "admin"))
	var rows []db.AIChat
	if err := h.DB.Gorm.Order("id").Find(&rows).Error; err != nil || len(rows) != 2 || rows[0].ID != mine[1].ID || rows[1].ID != other.ID {
		t.Errorf("rows after the deletes: %v %+v", err, rows)
	}
}

// deadlineRecorder records the write deadline a handler asks for, the way
// http.ResponseController hands it to the server's connection.
type deadlineRecorder struct {
	*httptest.ResponseRecorder
	writeDeadline time.Time
}

func (d *deadlineRecorder) SetWriteDeadline(t time.Time) error { d.writeDeadline = t; return nil }

// The send keeps its connection for the question's whole budget: the
// server's write timeout is a minute, an answer can take longer, and a
// connection closed before the answer is written loses it (the 2026-10-10
// answer about a load balancer took 65 s, was stored, and the page said
// the question had failed).
func TestAskSendExtendsWriteDeadline(t *testing.T) {
	h := newTestHandler(t)
	s := h.snapshotSettings()
	s.Server.BasePath = "/unmask"
	h.SetSettings(s)
	rec := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	// No model configured: the handler answers 4xx at once, after setting
	// the deadline it would have needed.
	h.AdminAskSend(rec, askReq("POST", "/unmask/admin/ask/send", "q=anything", "admin"))
	if rec.writeDeadline.IsZero() || time.Until(rec.writeDeadline) < askTimeout {
		t.Errorf("the send must keep the connection for at least %v; deadline %v", askTimeout, rec.writeDeadline)
	}
}
