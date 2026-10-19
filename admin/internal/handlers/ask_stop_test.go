package handlers

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// A question stopped from the page: its request ends, the provider call ends
// with it, the turn is kept as stopped, and the next question is not told
// the previous one is still being answered.
func TestAskSendStoppedFromThePage(t *testing.T) {
	h := newTestHandler(t)
	if _, err := h.DB.Exec(`CREATE TABLE IF NOT EXISTS unmask_ai_chat (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, asked_at INTEGER NOT NULL, question TEXT NOT NULL, answer TEXT NOT NULL DEFAULT '', tools TEXT NOT NULL DEFAULT '', model TEXT NOT NULL DEFAULT '', in_tokens INTEGER NOT NULL DEFAULT 0, out_tokens INTEGER NOT NULL DEFAULT 0, err TEXT NOT NULL DEFAULT '', added_rules TEXT NOT NULL DEFAULT '', cache_read_tokens INTEGER NOT NULL DEFAULT 0, cache_write_tokens INTEGER NOT NULL DEFAULT 0)`); err != nil {
		t.Fatal(err)
	}
	var calls int32
	got := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body) // read, so that the server notices the client leaving
		if atomic.AddInt32(&calls, 1) == 1 {
			got <- struct{}{}
			select { // the question is stopped under it
			case <-r.Context().Done():
			case <-time.After(15 * time.Second):
			}
			return
		}
		io.WriteString(w, `{"choices":[{"message":{"role":"assistant","content":"after"}}],"usage":{"prompt_tokens":3,"completion_tokens":1}}`)
	}))
	defer srv.Close()
	s := h.snapshotSettings()
	s.Server.BasePath = "/unmask"
	s.AIAdvisor = settings.AIAdvisorConfig{Enabled: true, Provider: "openai", Endpoint: srv.URL, APIKey: "k", Model: "m"}
	h.SetSettings(s)

	req := askReq("POST", "/unmask/admin/ask/send", "q=slow", "admin")
	ctx, cancel := context.WithCancel(req.Context())
	defer cancel()
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	done := make(chan struct{})
	go func() { h.AdminAskSend(rec, req); close(done) }()
	select {
	case <-got:
	case <-time.After(10 * time.Second):
		t.Fatal("the provider never got the question")
	}
	cancel() // the page stopped it
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the handler did not return after the request ended")
	}
	if rec.Body.Len() != 0 {
		t.Errorf("a stopped question was answered: %s", rec.Body.String())
	}
	var rows []db.AIChat
	if err := h.DB.Gorm.Find(&rows).Error; err != nil || len(rows) != 1 || rows[0].Err != askErrStopped || rows[0].Answer != "" {
		t.Fatalf("stored turn: %v %+v", err, rows)
	}
	// The history shows the turn as stopped, not failed, with the retry that
	// brings the question back to the composer.
	rec = httptest.NewRecorder()
	h.AdminAskHistory(rec, askReq("GET", "/unmask/admin/ask/history/", "", "admin"))
	b := rec.Body.String()
	if !strings.Contains(b, `class="a stopped"`) || !strings.Contains(b, ">中止しました<") || strings.Contains(b, "失敗: ") || !strings.Contains(b, `class="a-retry" href="/unmask/admin/ask/?q=slow"`) {
		t.Error("the stopped turn is not shown as stopped with a retry")
	}
	// The next question goes straight through: the lock was let go.
	rec = httptest.NewRecorder()
	h.AdminAskSend(rec, askReq("POST", "/unmask/admin/ask/send", "q=next", "admin"))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"answer":"after"`) {
		t.Errorf("the question after the stopped one: %d %s", rec.Code, rec.Body.String())
	}
}

// askLock waits for the previous question's handler to let go, up to its
// wait, and not past the request's end.
func TestAskLockWaitsForThePreviousQuestion(t *testing.T) {
	var mu sync.Mutex
	mu.Lock()
	go func() { time.Sleep(200 * time.Millisecond); mu.Unlock() }()
	if !askLock(context.Background(), &mu, 3*time.Second) {
		t.Error("a lock let go within the wait was not taken")
	}
	mu.Unlock()
	mu.Lock()
	if askLock(context.Background(), &mu, 150*time.Millisecond) {
		t.Error("a lock held past the wait was taken")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if askLock(ctx, &mu, 3*time.Second) {
		t.Error("a lock was taken for a request that had ended")
	}
	mu.Unlock()
}
