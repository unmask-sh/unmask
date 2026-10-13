package handlers

import (
	"context"
	"encoding/json"
	"fmt"
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
	"github.com/unmask-sh/unmask/admin/internal/settings"
	"net/netip"
	"sort"
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
	askTimeout     = 6 * time.Minute  // a question's whole budget, tools and rounds included
	askLongTimeout = 20 * time.Minute // the same at effort xhigh or max (advisor.ThinksLong)
)

// askView is one turn as the page draws it.
type askView struct {
	ID        int64
	Question  string
	Answer    string
	Parts     []askPart // the answer split at ``` fences: text, and blocks
	Tools     []askToolChip
	AskedTS   int64
	Model     string
	InTokens  int
	OutTokens int
	Err       string
	// Cost: the answer's estimated cost ("$0.007"), or "" (askCostOf).
	Cost string
	// Folded: on the history tab a long answer opens on its first lines;
	// the ask tab's latest turn and short answers stay whole.
	Folded bool
	// QuestionHead names the turn in the delete confirmation.
	QuestionHead string
}

// askToolChip is one tool on an answer's meta line.  A tool the model
// called more than once (events for two addresses, say) shows once with
// its count; Ms is the time all its calls took.
type askToolChip struct {
	Name  string `json:"name"`
	Calls int    `json:"calls"`
	Ms    int64  `json:"ms"`
	Err   bool   `json:"err,omitempty"` // a call failed
}

// askToolChips folds the calls into one chip per tool, in the order each
// tool was first called.
func askToolChips(calls []advisor.ToolTrace) []askToolChip {
	var out []askToolChip
	at := map[string]int{}
	for _, c := range calls {
		i, ok := at[c.Name]
		if !ok {
			i = len(out)
			at[c.Name] = i
			out = append(out, askToolChip{Name: c.Name})
		}
		out[i].Calls++
		out[i].Ms += c.Ms
		if c.Err != "" {
			out[i].Err = true
		}
	}
	return out
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
		Crawlers:     h.askCrawlers,
		Loc:          askLocation(r),
	}
}

// askCrawlers: the dashboard's crawler card for the model -- each category of
// known crawler and each crawler in it, with its requests, how many were
// challenged and how many passed over the trailing window.  Asked how much
// the search engines and AI crawlers came and whether they got through, the
// model had only the install-wide pass count to go on.
func (h *Handler) askCrawlers(ctx context.Context, hours int) (any, error) {
	minutes := hours * 60
	detail := aiTrafficDrilldown(ctx, h, minutes)
	cats := []map[string]any{}
	for _, c := range aiTrafficSummary(ctx, h, minutes) {
		if c.Total == 0 {
			continue
		}
		row := map[string]any{"category": c.Category, "requests": c.Total, "challenged": c.Served, "passed": c.Passed}
		var crawlers []map[string]any
		for _, d := range detail[c.Category] {
			crawlers = append(crawlers, map[string]any{"crawler": d.Crawler, "requests": d.Total, "challenged": d.Served, "passed": d.Passed, "range_verified": d.RangeVerified})
		}
		if len(crawlers) > 0 {
			row["crawlers"] = crawlers
		}
		cats = append(cats, row)
	}
	return map[string]any{
		"window_hours": hours, "categories": cats,
		"note": "Requests carrying a known crawler's user agent.  A range_verified crawler passes only from its vendor's published address ranges, so its challenged requests used its name from elsewhere: impostors, stopped.  Any other crawler passes on its user agent, which anyone can send, so its passes do not prove it is the crawler.",
	}, nil
}

// askTZRe: what a time zone name may hold (the TZ picker's allowlist).
var askTZRe = regexp.MustCompile(`^[A-Za-z0-9/_+-]{1,64}$`)

// askLocation: the asking operator's time zone -- the TZ picker's when one is
// set, else the browser's, which the page sends with the question (with the
// picker on "browser" the server has none of its own), else UTC.
func askLocation(r *http.Request) *time.Location {
	if resolveTZ(r) != "" {
		return resolveLocation(r)
	}
	if name := strings.TrimSpace(r.FormValue("tz")); askTZRe.MatchString(name) {
		if loc, err := time.LoadLocation(name); err == nil {
			return loc
		}
	}
	return time.UTC
}

// askContext is set after the question, as the language request is: what
// the model cannot know of itself.  The operator's clock, for "today" and
// for the times it names; and the browser versions current today, which it
// otherwise judged from what it remembered -- a released Chrome read as "a
// version that does not exist".
func askContext(now time.Time, loc *time.Location, g settings.GlobalConfig) string {
	return fmt.Sprintf("\n\n(Now: %s, time zone %s.  Current stable browsers: Chrome %d (Edge and the other Chromium browsers follow its numbers), Firefox %d.)",
		now.In(loc).Format("2006-01-02 15:04 -07:00"), loc.String(), g.CurrentChromeMajorResolved(), g.CurrentFirefoxMajorResolved())
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

// askPart is a run of an answer: prose, a ``` block shown as one, an admin
// path shown as a link to it, or an address shown with the hunt page's
// popover.  A fresh answer goes to the page split the same way (the send
// response carries the parts); nothing else in an answer is markup.
type askPart struct {
	Code bool   `json:"code,omitempty"`
	Link string `json:"link,omitempty"` // the admin path (under the base path) this run links to
	Rule bool   `json:"rule,omitempty"` // Link opens the custom-rules tab with a proposed rule filled in: shown as a button
	IP   string `json:"ip,omitempty"`   // an address the answer names: shown with the hunt page's popover
	Text string `json:"text"`
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
		out = append(out, linkAdminPaths(plainProse(seg))...)
	}
	return out
}

// emphRE / inlineCodeRE: markdown the page does not draw.  The prompt asks
// for plain text, and the model still bolds a line now and then; shown as
// typed, the asterisks and backticks only get in the way.
var (
	emphRE       = regexp.MustCompile(`\*\*([^*\n]+)\*\*`)
	inlineCodeRE = regexp.MustCompile("`([^`\n]+)`")
)

func plainProse(s string) string {
	return inlineCodeRE.ReplaceAllString(emphRE.ReplaceAllString(s, "$1"), "$1")
}

func linkAdminPaths(text string) []askPart {
	var out []askPart
	pos := 0
	for _, m := range adminPathRE.FindAllStringIndex(text, -1) {
		if m[0] > pos {
			out = append(out, markAddresses(text[pos:m[0]])...)
		}
		link := text[m[0]:m[1]]
		out = append(out, askPart{Link: link, Text: link, Rule: strings.HasPrefix(link, customRuleDraftPrefix)})
		pos = m[1]
	}
	if pos < len(text) {
		out = append(out, markAddresses(text[pos:])...)
	}
	return out
}

// ipv4RE and ipv6RE: what may be an address in prose.  A match counts only
// when netip parses it and it stands alone -- not the tail of a version
// (Chrome/120.0.0.0), a time (14:42:28 is no IPv6) or a longer token.
var (
	ipv4RE = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	ipv6RE = regexp.MustCompile(`[0-9A-Fa-f:]{3,45}`)
)

// markAddresses splits prose into text and the addresses it names.
func markAddresses(text string) []askPart {
	type span struct{ s, e int }
	var spans []span
	joined := func(c byte) bool {
		return c == '_' || c == ':' || c == '.' || c == '/' || c == '-' || c == '+' || c == '@' ||
			(c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
	}
	// alone: nothing joins the run to what is before it, and what follows is
	// not a word or a further dotted part (1.2.3.4.5, fe80::1.local).
	alone := func(s, e int) bool {
		if s > 0 && joined(text[s-1]) {
			return false
		}
		if e < len(text) {
			c := text[e]
			if c == '_' || (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') {
				return false
			}
			if c == '.' && e+1 < len(text) && joined(text[e+1]) && text[e+1] != '.' {
				return false
			}
		}
		return true
	}
	for _, m := range ipv4RE.FindAllStringIndex(text, -1) {
		if a, err := netip.ParseAddr(text[m[0]:m[1]]); err == nil && a.Is4() && alone(m[0], m[1]) {
			spans = append(spans, span{m[0], m[1]})
		}
	}
	for _, m := range ipv6RE.FindAllStringIndex(text, -1) {
		c := text[m[0]:m[1]]
		if strings.Count(c, ":") < 2 || c == "::" || !alone(m[0], m[1]) {
			continue
		}
		if a, err := netip.ParseAddr(c); err == nil && a.Is6() {
			spans = append(spans, span{m[0], m[1]})
		}
	}
	if len(spans) == 0 {
		return []askPart{{Text: text}}
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].s < spans[j].s })
	var out []askPart
	pos := 0
	for _, sp := range spans {
		if sp.s > pos {
			out = append(out, askPart{Text: text[pos:sp.s]})
		}
		out = append(out, askPart{IP: text[sp.s:sp.e], Text: text[sp.s:sp.e]})
		pos = sp.e
	}
	if pos < len(text) {
		out = append(out, askPart{Text: text[pos:]})
	}
	return out
}

// askCostOf is an answer's estimated cost as the page prints it, from the
// model's list price: "" when the provider is local (nothing is billed) or
// the model's price is not known.
func askCostOf(provider, model string, in, out int) string {
	if provider == "ollama" || in+out == 0 {
		return ""
	}
	usd, ok := advisor.Cost(model, in, out)
	if !ok {
		return ""
	}
	return advisor.FormatUSD(usd)
}

// askViews prepares turns for the page; fold folds the long answers.
func askViews(rows []db.AIChat, fold bool) []askView {
	out := make([]askView, 0, len(rows))
	for _, r := range rows {
		v := askView{ID: r.ID, Question: r.Question, Answer: r.Answer, Parts: splitFences(r.Answer), AskedTS: r.AskedAt, Model: r.Model, InTokens: r.InTokens, OutTokens: r.OutTokens, Err: r.Err}
		if r.Tools != "" {
			var calls []advisor.ToolTrace
			_ = json.Unmarshal([]byte(r.Tools), &calls)
			v.Tools = askToolChips(calls)
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
	for i := range turns {
		turns[i].Cost = askCostOf(cfg.ResolvedProvider(), turns[i].Model, turns[i].InTokens, turns[i].OutTokens)
	}
	// The history tab sums the month -- every account's questions, since the
	// provider bills the install -- in the operator's month.
	monthCost, monthCount := "", 0
	if tab == "history" && cfg.ResolvedProvider() != "ollama" {
		loc := resolveLocation(r)
		now := time.Now().In(loc)
		start := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, loc).Unix()
		var month []db.AIChat
		if err := h.DB.Gorm.WithContext(r.Context()).Select("model", "in_tokens", "out_tokens").Where("asked_at >= ?", start).Find(&month).Error; err != nil {
			log.Printf("ask: month: %v", err)
		}
		usd := 0.0
		for _, c := range month {
			if v, ok := advisor.Cost(c.Model, c.InTokens, c.OutTokens); ok && c.InTokens+c.OutTokens > 0 {
				usd += v
				monthCount++
			}
		}
		if monthCount > 0 {
			monthCost = advisor.FormatUSD(usd)
		}
	}
	data := map[string]any{
		"Lang":         i18n.Resolve(r),
		"MonthCost":    monthCost,
		"MonthCount":   monthCount,
		"TZ":           resolveTZ(r),
		"BasePath":     h.cfg().Server.BasePath,
		"Version":      h.Version,
		"AIActive":     cfg.Active(),
		"AIPicks":      h.aiPicks(r, "ask"),
		"Suggests":     askSuggestions(i18n.Resolve(r)),
		"CanAsk":       canAsk,
		"CRKinds":      settings.CustomConditionKinds,
		"Tab":          tab,
		"Turns":        turns,
		"HistoryCount": len(rows),
		"QuestionMax":  askQuestionMax,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	h.addMeToData(r, data)
	if err := tmpl.ExecuteTemplate(w, "ask.html", data); err != nil {
		log.Printf("ask render: %v", err)
	}
}

// AdminAskSend: POST {base}/admin/ask/send (admin role), form field q.
// Answers JSON: {"ok":true,"id":..,"answer":"..","parts":[..],"tools":[..],
// "in_tokens":..,"out_tokens":..,"model":"..","cost":"..","asked_ts":..} or
// {"ok":false,"error":".."}
// with 4xx/5xx.  The answer arrives whole; the page shows a pending row
// meanwhile and keeps the earlier turns.
func (h *Handler) AdminAskSend(w http.ResponseWriter, r *http.Request) {
	// An answer takes as long as the model's rounds through the tools -- a
	// minute or more when it reads the settings pages -- and the server's
	// write timeout (60 s, sized for the dashboard) would close the
	// connection first: the answer was stored, the page said the question
	// failed.  This response gets the question's whole budget.
	rc := http.NewResponseController(w)
	if err := rc.SetWriteDeadline(time.Now().Add(askTimeout + time.Minute)); err != nil {
		// A wrapper in the chain without Unwrap leaves the server's write
		// timeout in force; say so rather than find out at the 61st second.
		log.Printf("ask: the response's write deadline could not be extended (%v); the server's write timeout applies", err)
	}
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
	// The page's picks for this question: a model from the provider's list
	// (the one fetched for the AI tab, or the configured one) and an effort
	// the provider takes.  The configured values stay what they are.
	if err := h.applyAIPick(&cfg, r.FormValue("model"), r.FormValue("effort"), lang); err != nil {
		fail(http.StatusBadRequest, err.Error())
		return
	}
	// At xhigh or max each round may think for minutes: the question gets
	// the longer budget, and the response a deadline to match.
	budget := askTimeout
	if advisor.ThinksLong(cfg.ResolvedModel(), cfg.Effort) {
		budget = askLongTimeout
		_ = rc.SetWriteDeadline(time.Now().Add(budget + time.Minute)) // a failure was logged above
	}
	mu, _ := askBusy.LoadOrStore(pay.UserID, &sync.Mutex{})
	if !mu.(*sync.Mutex).TryLock() {
		fail(http.StatusConflict, i18n.T(lang, "ask.err_busy"))
		return
	}
	defer mu.(*sync.Mutex).Unlock()

	ctx, cancel := context.WithTimeout(r.Context(), budget)
	defer cancel()
	var history []advisor.ChatTurn
	if rows, err := h.askHistory(ctx, pay.UserID, 10); err == nil {
		for _, row := range rows {
			if row.Answer != "" {
				history = append(history, advisor.ChatTurn{Question: row.Question, Answer: row.Answer})
			}
		}
	}
	res, err := advisor.Chat(ctx, cfg, h.askTools(r), history, q+askContext(time.Now(), askLocation(r), h.cfg().Global), string(lang))
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
		"ok": true, "id": row.ID, "answer": res.Answer, "parts": splitFences(res.Answer), "tools": askToolChips(res.Tools),
		"cost":      askCostOf(cfg.ResolvedProvider(), row.Model, res.Usage.Input, res.Usage.Output),
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

// askSuggestions: the example questions in the composer's pick, in order.
func askSuggestions(lang i18n.Lang) []string {
	out := make([]string, 0, askSuggestionCount)
	for i := 1; i <= askSuggestionCount; i++ {
		out = append(out, i18n.T(lang, fmt.Sprintf("ask.suggest%d", i)))
	}
	return out
}

// askSuggestionCount is how many ask.suggestN strings the dictionary carries.
const askSuggestionCount = 12
