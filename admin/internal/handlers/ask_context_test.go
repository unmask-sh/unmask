package handlers

import (
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

// A question's context is the conversation the page names (ctx_ids): the
// account's own answered turns among them, oldest first, and nothing when
// the page names none -- the history is not sent on its own.  The
// provider's cache figure is kept with the turn and shown with the answer.
func TestAskContextIsThePagesConversation(t *testing.T) {
	h := newTestHandler(t)
	if _, err := h.DB.Exec(`CREATE TABLE IF NOT EXISTS unmask_ai_chat (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, asked_at INTEGER NOT NULL, question TEXT NOT NULL, answer TEXT NOT NULL DEFAULT '', tools TEXT NOT NULL DEFAULT '', model TEXT NOT NULL DEFAULT '', in_tokens INTEGER NOT NULL DEFAULT 0, out_tokens INTEGER NOT NULL DEFAULT 0, err TEXT NOT NULL DEFAULT '', added_rules TEXT NOT NULL DEFAULT '', cache_read_tokens INTEGER NOT NULL DEFAULT 0, cache_write_tokens INTEGER NOT NULL DEFAULT 0)`); err != nil {
		t.Fatal(err)
	}
	// What the provider was sent, per request: the roles and texts of the
	// messages.
	var sent [][2]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var req struct {
			Messages []struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"messages"`
		}
		_ = json.Unmarshal(b, &req)
		sent = sent[:0]
		for _, m := range req.Messages {
			sent = append(sent, [2]string{m.Role, m.Content})
		}
		io.WriteString(w, `{"choices":[{"message":{"role":"assistant","content":"fine."}}],"usage":{"prompt_tokens":100,"completion_tokens":3,"prompt_tokens_details":{"cached_tokens":60}}}`)
	}))
	defer srv.Close()
	s := h.snapshotSettings()
	s.Server.BasePath = "/unmask"
	s.AIAdvisor = settings.AIAdvisorConfig{Enabled: true, Provider: "openai", Endpoint: srv.URL, APIKey: "k", Model: "m"}
	h.SetSettings(s)
	// Earlier turns: the account's own (the admin test session is user 7)
	// and another account's.
	now := time.Now().Unix()
	mine := db.AIChat{UserID: 7, AskedAt: now - 100, Question: "earlier question", Answer: "earlier answer"}
	theirs := db.AIChat{UserID: 2, AskedAt: now - 50, Question: "someone else's", Answer: "their answer"}
	unanswered := db.AIChat{UserID: 7, AskedAt: now - 20, Question: "failed one", Answer: "", Err: "boom"}
	for _, row := range []*db.AIChat{&mine, &theirs, &unanswered} {
		if err := h.DB.Gorm.Create(row).Error; err != nil {
			t.Fatal(err)
		}
	}
	countRole := func(role string) int {
		n := 0
		for _, m := range sent {
			if m[0] == role {
				n++
			}
		}
		return n
	}

	// No ids: the question alone (the system prompt beside it).
	rec := httptest.NewRecorder()
	h.AdminAskSend(rec, askReq("POST", "/unmask/admin/ask/send", url.Values{"q": {"first"}}.Encode(), "admin"))
	if rec.Code != 200 {
		t.Fatalf("send: %d %s", rec.Code, rec.Body.String())
	}
	if countRole("assistant") != 0 || countRole("user") != 1 {
		t.Errorf("without ctx_ids the provider got %v", sent)
	}
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if out["cache_read_tokens"] != float64(60) || out["in_tokens"] != float64(100) {
		t.Errorf("the cache figure did not reach the page: %v", out)
	}
	var stored db.AIChat
	if err := h.DB.Gorm.First(&stored, int64(out["id"].(float64))).Error; err != nil || stored.CacheReadTokens != 60 || stored.InTokens != 100 {
		t.Errorf("the stored turn: %+v (%v)", stored, err)
	}

	// The page names its conversation: the own answered turn goes, in
	// order; another account's, an unanswered one and an unknown id do not.
	ids := strings.Join([]string{strconv.FormatInt(theirs.ID, 10), strconv.FormatInt(mine.ID, 10), strconv.FormatInt(unanswered.ID, 10), "999999"}, ",")
	rec = httptest.NewRecorder()
	h.AdminAskSend(rec, askReq("POST", "/unmask/admin/ask/send", url.Values{"q": {"second"}, "ctx_ids": {ids}}.Encode(), "admin"))
	if rec.Code != 200 {
		t.Fatalf("send with context: %d %s", rec.Code, rec.Body.String())
	}
	users := []string{}
	for _, m := range sent {
		if m[0] == "user" {
			users = append(users, m[1])
		}
	}
	if countRole("assistant") != 1 || len(users) != 2 || users[0] != "earlier question" || !strings.HasPrefix(users[1], "second") {
		t.Errorf("with ctx_ids the provider got %v", sent)
	}
	for _, m := range sent {
		if strings.Contains(m[1], "someone else") || strings.Contains(m[1], "failed one") {
			t.Errorf("another account's turn, or an unanswered one, was sent: %v", m)
		}
	}
}
