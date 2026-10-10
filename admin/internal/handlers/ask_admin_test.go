package handlers

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
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
		io.WriteString(w, `{"choices":[{"message":{"role":"assistant","content":"BAN は 0 件です。\n`+"```"+`\nbans=0\n`+"```"+`"}}],"usage":{"prompt_tokens":30,"completion_tokens":8}}`)
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
	// The history is on the page, with the tool chip and the token line.
	rec = httptest.NewRecorder()
	h.AdminAsk(rec, askReq("GET", "/unmask/admin/ask/", "", "admin"))
	body = rec.Body.String()
	for _, want := range []string{"BAN は 0 件です。", "<pre>bans=0</pre>", `class="tool-chip"`, "tokens 入力 41 / 出力 10", `action="/unmask/admin/ask/clear"`} {
		if !strings.Contains(body, want) {
			t.Errorf("history lacks %q", want)
		}
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
