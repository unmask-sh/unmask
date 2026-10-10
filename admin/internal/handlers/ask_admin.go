package handlers

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"regexp"
	"strconv"
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
	// Folded: on the history tab a long answer opens on its first lines;
	// the ask tab's latest turn and short answers stay whole.
	Folded bool
	// QuestionHead names the turn in the delete confirmation.
	QuestionHead string
}

// askTools: the tools for one question.  The settings outline renders as
// the asking operator (their session rides in the chat's context) and in
// their language.
func (h *Handler) askTools(r *http.Request) aitools.Deps {
	lang := i18n.Lang(i18n.Resolve(r))
	return aitools.Deps{
		DB: h.DB, Settings: h.SnapshotSettings, IPGeo: h.IPGeo, Live: h.Live, Version: h.Version, ConfigPath: h.ConfigPath,
		SettingsFind: func(ctx context.Context, q string) (any, error) { return h.SettingsFind(ctx, lang, q) },
		SettingsTab:  func(ctx context.Context, tab string) (any, error) { return h.SettingsTabOutline(ctx, lang, tab) },
	}
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
	Rule bool   // Link opens the custom-rules tab with a proposed rule filled in: shown as a button
	Text string
}

// customRuleDraftPrefix: the path propose_custom_rule returns (the tab with
// ?new=1 and the rule's fields); the page shows it as a button, not a URL.
const customRuleDraftPrefix = "/admin/settings/custom-rules/?new=1"

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
		link := text[m[0]:m[1]]
		out = append(out, askPart{Link: link, Text: link, Rule: strings.HasPrefix(link, customRuleDraftPrefix)})
		pos = m[1]
	}
	if pos < len(text) {
		out = append(out, askPart{Text: text[pos:]})
	}
	return out
}

// askViews prepares turns for the page; fold folds the long answers.
func askViews(rows []db.AIChat, fold bool) []askView {
	out := make([]askView, 0, len(rows))
	for _, r := range rows {
		v := askView{ID: r.ID, Question: r.Question, Answer: r.Answer, Parts: splitFences(r.Answer), AskedTS: r.AskedAt, Model: r.Model, InTokens: r.InTokens, OutTokens: r.OutTokens, Err: r.Err}
		if r.Tools != "" {
			_ = json.Unmarshal([]byte(r.Tools), &v.Tools)
		}
		v.Folded = fold && r.Err == "" && (len([]rune(r.Answer)) > 160 || strings.Count(r.Answer, "\n") > 1)
		q := []rune(strings.Join(strings.Fields(r.Question), " "))
		if len(q) > 40 {
			q = append(q[:40], '…')
		}
		v.QuestionHead = string(q)
		out = append(out, v)
	}
	return out
}

// AdminAsk: GET {base}/admin/ask/ -- the composer with the latest turn
// under it.  The earlier turns are the history tab's.
func (h *Handler) AdminAsk(w http.ResponseWriter, r *http.Request) {
	h.askPage(w, r, "ask")
}

// AdminAskHistory: GET {base}/admin/ask/history/ -- every turn of the
// account, newest first, long answers folded, each with a copy and a delete.
func (h *Handler) AdminAskHistory(w http.ResponseWriter, r *http.Request) {
	h.askPage(w, r, "history")
}

func (h *Handler) askPage(w http.ResponseWriter, r *http.Request, tab string) {
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
	// The ask tab opens on the composer alone: the turns of this visit stack
	// under it as they are asked, and earlier ones are the history tab's
	// (2026-10-10, the operator's call).  The model still gets the last
	// turns as context whatever is shown.
	var turns []askView
	if tab == "history" {
		// Newest first: the list is read from the top.
		for i, j := 0, len(rows)-1; i < j; i, j = i+1, j-1 {
			rows[i], rows[j] = rows[j], rows[i]
		}
		turns = askViews(rows, true)
	}
	cfg := h.cfg().AIAdvisor
	month := advisor.Totals(h.DB, time.Now().Add(-30*24*time.Hour))
	data := map[string]any{
		"Lang":         i18n.Resolve(r),
		"TZ":           resolveTZ(r),
		"BasePath":     h.cfg().Server.BasePath,
		"Version":      h.Version,
		"AIActive":     cfg.Active(),
		"AIProvider":   cfg.ResolvedProvider(),
		"AIModel":      cfg.ResolvedModel(),
		"CanAsk":       canAsk,
		"Tab":          tab,
		"Turns":        turns,
		"HistoryCount": len(rows),
		"MonthRuns":    int(month.Runs),
		"MonthIn":      int(month.InTokens),
		"MonthOut":     int(month.OutTokens),
		"QuestionMax":  askQuestionMax,
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
	// An answer takes as long as the model's rounds through the tools -- a
	// minute or more when it reads the settings pages -- and the server's
	// write timeout (60 s, sized for the dashboard) would close the
	// connection first: the answer was stored, the page said the question
	// failed.  This response gets the question's whole budget.
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Now().Add(askTimeout + time.Minute))
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
	res, err := advisor.Chat(ctx, cfg, h.askTools(r), history, q, string(lang))
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
	http.Redirect(w, r, h.cfg().Server.BasePath+"/admin/ask/history/?cleared=1", http.StatusSeeOther)
}

// AdminAskDelete: POST {base}/admin/ask/delete (admin role), form field id.
// Removes one of the account's own turns.
func (h *Handler) AdminAskDelete(w http.ResponseWriter, r *http.Request) {
	pay := SessionFromContext(r)
	id, _ := strconv.ParseInt(strings.TrimSpace(r.FormValue("id")), 10, 64)
	if pay != nil && h.DB != nil && id > 0 {
		if err := h.DB.Gorm.Where("user_id = ? AND id = ?", pay.UserID, id).Delete(&db.AIChat{}).Error; err != nil {
			log.Printf("ask: delete: %v", err)
		}
	}
	http.Redirect(w, r, h.cfg().Server.BasePath+"/admin/ask/history/", http.StatusSeeOther)
}
