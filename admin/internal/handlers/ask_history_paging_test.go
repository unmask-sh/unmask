package handlers

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
)

// The history tab pages: 50 turns a page, newest first, the range in the
// note, previous and next where there is one; a page past the last is the
// last; a delete lands back on its page.
func TestAskHistoryPages(t *testing.T) {
	h := newTestHandler(t)
	if _, err := h.DB.Exec(`CREATE TABLE IF NOT EXISTS unmask_ai_chat (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, asked_at INTEGER NOT NULL, question TEXT NOT NULL, answer TEXT NOT NULL, model TEXT NOT NULL DEFAULT '', in_tokens INTEGER NOT NULL DEFAULT 0, out_tokens INTEGER NOT NULL DEFAULT 0, cache_read_tokens INTEGER NOT NULL DEFAULT 0, cache_write_tokens INTEGER NOT NULL DEFAULT 0, tools TEXT NOT NULL DEFAULT '', err TEXT NOT NULL DEFAULT '', added_rules TEXT NOT NULL DEFAULT '')`); err != nil {
		t.Fatal(err)
	}
	s := h.snapshotSettings()
	s.Server.BasePath = "/unmask"
	h.SetSettings(s)
	now := time.Now().Unix()
	for i := 0; i < 120; i++ {
		if err := h.DB.Gorm.Create(&db.AIChat{UserID: 7, AskedAt: now - int64(i)*60, Question: fmt.Sprintf("q%03d", i), Answer: "a"}).Error; err != nil {
			t.Fatal(err)
		}
	}
	page := func(query string) string {
		t.Helper()
		rec := httptest.NewRecorder()
		h.AdminAskHistory(rec, askReq("GET", "/unmask/admin/ask/history/"+query, "", "admin"))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: %d", query, rec.Code)
		}
		return rec.Body.String()
	}
	b := page("")
	if n := strings.Count(b, `data-id="`); n != 50 {
		t.Errorf("page 1: %d turns, want 50", n)
	}
	for _, want := range []string{"1〜50 件目 (全 120 件)", "1 / 3 ページ", `?page=2">次へ</a>`, `<div class="q">q000</div>`} {
		if !strings.Contains(b, want) {
			t.Errorf("page 1 lacks %q", want)
		}
	}
	if strings.Contains(b, ">前へ</a>") {
		t.Error("page 1 offers a previous page")
	}
	b = page("?page=3")
	if n := strings.Count(b, `data-id="`); n != 20 {
		t.Errorf("page 3: %d turns, want 20", n)
	}
	for _, want := range []string{"101〜120 件目 (全 120 件)", "3 / 3 ページ", `?page=2">前へ</a>`, `<div class="q">q119</div>`} {
		if !strings.Contains(b, want) {
			t.Errorf("page 3 lacks %q", want)
		}
	}
	if strings.Contains(b, ">次へ</a>") {
		t.Error("the last page offers a next page")
	}
	if b2 := page("?page=99"); !strings.Contains(b2, "3 / 3 ページ") {
		t.Error("a page past the last is not the last")
	}
	// Page 2's previous is the first page, with no query.
	if b2 := page("?page=2"); !strings.Contains(b2, `href="/unmask/admin/ask/history/">前へ</a>`) {
		t.Error("page 2's previous link does not lead to the first page")
	}

	// A delete from page 2 goes back to page 2.
	var row db.AIChat
	if err := h.DB.Gorm.Where("question = ?", "q060").First(&row).Error; err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	h.AdminAskDelete(rec, askReq("POST", "/unmask/admin/ask/delete", fmt.Sprintf("id=%d&page=2", row.ID), "admin"))
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/unmask/admin/ask/history/?page=2" {
		t.Errorf("delete: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	if b2 := page("?page=3"); !strings.Contains(b2, "全 119 件") {
		t.Error("the deleted turn is still counted")
	}
}

// The history is kept until deleted unless the retention tab says how long;
// the daily prune then drops the turns older than that, everyone's.
func TestAskHistoryPrune(t *testing.T) {
	h := newTestHandler(t)
	if _, err := h.DB.Exec(`CREATE TABLE IF NOT EXISTS unmask_ai_chat (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, asked_at INTEGER NOT NULL, question TEXT NOT NULL, answer TEXT NOT NULL, model TEXT NOT NULL DEFAULT '', in_tokens INTEGER NOT NULL DEFAULT 0, out_tokens INTEGER NOT NULL DEFAULT 0, cache_read_tokens INTEGER NOT NULL DEFAULT 0, cache_write_tokens INTEGER NOT NULL DEFAULT 0, tools TEXT NOT NULL DEFAULT '', err TEXT NOT NULL DEFAULT '', added_rules TEXT NOT NULL DEFAULT '')`); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for _, c := range []struct {
		user int64
		age  time.Duration
	}{{7, time.Hour}, {7, 100 * 24 * time.Hour}, {8, 40 * 24 * time.Hour}} {
		if err := h.DB.Gorm.Create(&db.AIChat{UserID: c.user, AskedAt: now.Add(-c.age).Unix(), Question: "q", Answer: "a"}).Error; err != nil {
			t.Fatal(err)
		}
	}
	count := func() int64 {
		var n int64
		_ = h.DB.Gorm.Model(&db.AIChat{}).Count(&n).Error
		return n
	}
	if n, err := h.PruneAskHistory(context.Background(), 0); err != nil || n != 0 || count() != 3 {
		t.Errorf("no retention: pruned %d (%v), %d left, want none pruned", n, err, count())
	}
	if n, err := h.PruneAskHistory(context.Background(), 30); err != nil || n != 2 || count() != 1 {
		t.Errorf("30 days: pruned %d (%v), %d left, want 2 pruned", n, err, count())
	}
}
