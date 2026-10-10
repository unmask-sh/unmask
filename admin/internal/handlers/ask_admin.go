package handlers

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/unmask-sh/unmask/admin/internal/advisor"
	"github.com/unmask-sh/unmask/admin/internal/aitools"
	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/i18n"
)

// The ask page: an operator's questions to the configured model, answered
// with the install's own data through the read-only tools in aitools.  Every
// account may read the page; asking and clearing take the admin role, since
// a question costs provider tokens and carries the install's data (addresses,
// user agents, paths) to the provider.  The model changes nothing here: its
// suggestions are carried out by the operator in the admin.

const (
	askQuestionMax = 2000 // runes
	askHistoryShow = 50   // turns the page lists
	askKeep        = 90 * 24 * time.Hour
	askTimeout     = 6 * time.Minute // a question's whole budget, tools and rounds included
)

// askView is one turn as the page draws it.
type askView struct {
	ID        int64
	Question  string
	Answer    string
	Parts     []askPart // the answer split at ``` fences: text, and blocks
	Tools     []advisor.ToolTrace
	AskedTS   int64
	Model     string
	InTokens  int
	OutTokens int
	Err       string
}

func (h *Handler) askTools() aitools.Deps {
	return aitools.Deps{DB: h.DB, Settings: h.SnapshotSettings, IPGeo: h.IPGeo, Live: h.Live, Version: h.Version, ConfigPath: h.ConfigPath}
}

// askBusy serialises one account's questions: a double click must not pay
// for two answers.
var askBusy sync.Map

func (h *Handler) askHistory(ctx context.Context, userID int64, limit int) ([]db.AIChat, error) {
	var rows []db.AIChat
	if h.DB == nil {
		return rows, nil
	}
	err := h.DB.Gorm.WithContext(ctx).Where("user_id = ?", userID).Order("asked_at DESC, id DESC").Limit(limit).Find(&rows).Error
	// Oldest first for the page.
	for i, j := 0, len(rows)-1; i < j; i, j = i+1, j-1 {
		rows[i], rows[j] = rows[j], rows[i]
	}
	return rows, err
}

// askPart is a run of an answer: prose, a ``` block shown as one, or an
// admin path shown as a link to it.  The page's script splits a fresh answer
// the same way; nothing else in an answer is markup.
type askPart struct {
	Code bool
	Link string // the admin path (under the base path) this run links to
	Text string
}

var fenceRE = regexp.MustCompile("```[A-Za-z0-9_-]*\n?")

// adminPathRE: a path of this admin the model may name (the system prompt
// gives it a few).  Only such paths become links -- same origin, under the
// base path -- never a URL the model wrote.  Trailing punctuation stays text.
var adminPathRE = regexp.MustCompile(`/admin/[A-Za-z0-9_./?=&%#-]*[A-Za-z0-9_/=%#-]`)

func splitFences(text string) []askPart {
	segs := fenceRE.Split(text, -1)
	out := make([]askPart, 0, len(segs))
	for i, seg := range segs {
		if i%2 == 1 {
			seg = strings.TrimSuffix(seg, "\n")
			if seg != "" {
				out = append(out, askPart{Code: true, Text: seg})
			}
			continue
		}
		out = append(out, linkAdminPaths(seg)...)
	}
	return out
}

func linkAdminPaths(text string) []askPart {
	var out []askPart
	pos := 0
	for _, m := range adminPathRE.FindAllStringIndex(text, -1) {
		if m[0] > pos {
			out = append(out, askPart{Text: text[pos:m[0]]})
		}
		out = append(out, askPart{Link: text[m[0]:m[1]], Text: text[m[0]:m[1]]})
		pos = m[1]
	}
	if pos < len(text) {
		out = append(out, askPart{Text: text[pos:]})
	}
	return out
}

func askViews(rows []db.AIChat) []askView {
	out := make([]askView, 0, len(rows))
	for _, r := range rows {
		v := askView{ID: r.ID, Question: r.Question, Answer: r.Answer, Parts: splitFences(r.Answer), AskedTS: r.AskedAt, Model: r.Model, InTokens: r.InTokens, OutTokens: r.OutTokens, Err: r.Err}
		if r.Tools != "" {
			_ = json.Unmarshal([]byte(r.Tools), &v.Tools)
		}
		out = append(out, v)
	}
	return out
}

// AdminAsk: GET {base}/admin/ask/ -- the page with the account's history.
func (h *Handler) AdminAsk(w http.ResponseWriter, r *http.Request) {
	tmpl, err := loadDashboardTemplate()
	if err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	pay := SessionFromContext(r)
	var userID int64
	canAsk := false
	if pay != nil {
		userID = pay.UserID
		canAsk = roleAtLeast(pay.Role, "admin")
	}
	rows, err := h.askHistory(r.Context(), userID, askHistoryShow)
	if err != nil {
		log.Printf("ask: history: %v", err)
	}
	cfg := h.cfg().AIAdvisor
	month := advisor.Totals(h.DB, time.Now().Add(-30*24*time.Hour))
	data := map[string]any{
		"Lang":        i18n.Resolve(r),
		"TZ":          resolveTZ(r),
		"BasePath":    h.cfg().Server.BasePath,
		"Version":     h.Version,
		"AIActive":    cfg.Active(),
		"AIProvider":  cfg.ResolvedProvider(),
		"AIModel":     cfg.ResolvedModel(),
		"CanAsk":      canAsk,
		"Turns":       askViews(rows),
		"MonthRuns":   int(month.Runs),
		"MonthIn":     int(month.InTokens),
		"MonthOut":    int(month.OutTokens),
		"QuestionMax": askQuestionMax,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	h.addMeToData(r, data)
	if err := tmpl.ExecuteTemplate(w, "ask.html", data); err != nil {
		log.Printf("ask render: %v", err)
	}
}

// AdminAskSend: POST {base}/admin/ask/send (admin role), form field q.
// Answers JSON: {"ok":true,"id":..,"answer":"..","tools":[..],"in_tokens":..,
// "out_tokens":..,"model":"..","asked_ts":..} or {"ok":false,"error":".."}
// with 4xx/5xx.  The answer arrives whole; the page shows a pending row
// meanwhile and keeps the earlier turns.
func (h *Handler) AdminAskSend(w http.ResponseWriter, r *http.Request) {
	lang := i18n.Lang(i18n.Resolve(r))
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	fail := func(code int, msg string) {
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": msg})
	}
	pay := SessionFromContext(r)
	if pay == nil {
		fail(http.StatusUnauthorized, "unauthorized")
		return
	}
	cfg := h.cfg().AIAdvisor
	if !cfg.Active() {
		fail(http.StatusBadRequest, i18n.T(lang, "ask.err_off"))
		return
	}
	q := strings.TrimSpace(r.FormValue("q"))
	if q == "" {
		fail(http.StatusBadRequest, i18n.T(lang, "ask.err_empty"))
		return
	}
	if utf8.RuneCountInString(q) > askQuestionMax {
		fail(http.StatusBadRequest, i18n.Tf(lang, "err.value_long", askQuestionMax))
		return
	}
	mu, _ := askBusy.LoadOrStore(pay.UserID, &sync.Mutex{})
	if !mu.(*sync.Mutex).TryLock() {
		fail(http.StatusConflict, i18n.T(lang, "ask.err_busy"))
		return
	}
	defer mu.(*sync.Mutex).Unlock()

	ctx, cancel := context.WithTimeout(r.Context(), askTimeout)
	defer cancel()
	var history []advisor.ChatTurn
	if rows, err := h.askHistory(ctx, pay.UserID, 10); err == nil {
		for _, row := range rows {
			if row.Answer != "" {
				history = append(history, advisor.ChatTurn{Question: row.Question, Answer: row.Answer})
			}
		}
	}
	res, err := advisor.Chat(ctx, cfg, h.askTools(), history, q, string(lang))
	advisor.RecordChatRun(h.DB, cfg, res, err)
	row := db.AIChat{UserID: pay.UserID, AskedAt: time.Now().Unix(), Question: q, Answer: res.Answer, Model: cfg.ResolvedModel(), InTokens: res.Usage.Input, OutTokens: res.Usage.Output}
	if b, e := json.Marshal(res.Tools); e == nil && len(res.Tools) > 0 {
		row.Tools = string(b)
	}
	if err != nil {
		row.Err = err.Error()
	}
	if h.DB != nil {
		if e := h.DB.Gorm.Create(&row).Error; e != nil {
			log.Printf("ask: store turn: %v", e)
		} else if e := h.DB.Gorm.Where("asked_at < ?", time.Now().Add(-askKeep).Unix()).Delete(&db.AIChat{}).Error; e != nil {
			log.Printf("ask: prune: %v", e)
		}
	}
	if err != nil {
		log.Printf("ask: %v", err)
		fail(http.StatusBadGateway, err.Error())
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok": true, "id": row.ID, "answer": res.Answer, "tools": res.Tools,
		"in_tokens": res.Usage.Input, "out_tokens": res.Usage.Output, "model": row.Model, "asked_ts": row.AskedAt,
	})
}

// AdminAskClear: POST {base}/admin/ask/clear (admin role) -- forgets the
// account's history, then returns to the page.
func (h *Handler) AdminAskClear(w http.ResponseWriter, r *http.Request) {
	pay := SessionFromContext(r)
	if pay != nil && h.DB != nil {
		if err := h.DB.Gorm.Where("user_id = ?", pay.UserID).Delete(&db.AIChat{}).Error; err != nil {
			log.Printf("ask: clear: %v", err)
		}
	}
	http.Redirect(w, r, h.cfg().Server.BasePath+"/admin/ask/?cleared=1", http.StatusSeeOther)
}
