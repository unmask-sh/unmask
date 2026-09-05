// advisor_admin.go — /admin/advisor/: the deterministic ban-candidate page
// (Phase 1 of the AI-advisor design).  The engine (internal/advisor) proposes;
// this page shows the evidence and hands each row to a human, who either
// applies a ban through the ordinary /admin/bans/save path or dismisses the
// suggestion.  Nothing is ever applied automatically.
package handlers

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"gorm.io/gorm/clause"

	"github.com/unmask-sh/unmask/admin/internal/advisor"
	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/i18n"
	"github.com/unmask-sh/unmask/admin/internal/safe"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// AdminAdvisorIndex: GET {base}/admin/advisor/
func (h *Handler) AdminAdvisorIndex(w http.ResponseWriter, r *http.Request) {
	tmpl, err := loadDashboardTemplate()
	if err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}

	windowH := advisorWindow(r.URL.Query().Get("window"))
	showAll := r.URL.Query().Get("min") == "all"
	// "Show dismissed": the operator's earlier no-thank-yous come back into
	// the list, marked, with the decision reversible from the row.
	showDismissed := r.URL.Query().Get("show_dismissed") == "1"

	excl, err := h.advisorExclusions(r.Context())
	if err != nil {
		log.Printf("advisor exclusions: %v", err)
	}
	dismissedIP, dismissedJA4 := excl.DismissedIP, excl.DismissedJA4
	if showDismissed {
		excl.DismissedIP, excl.DismissedJA4 = map[string]bool{}, map[string]bool{}
	}
	cands, candAt, err := advisor.CachedCandidates(r.Context(), h.DB, h.IPGeo, excl,
		advisor.Options{WindowMinutes: windowH * 60})
	engineErr := ""
	if err != nil {
		// Render the page with the error rather than a bare 500: the operator
		// still gets the frame, the window picker and the explanation.
		engineErr = err.Error()
	}

	// The model layer (settings > AI advisor) runs on the operator's click,
	// never on a page load -- see AdminAdvisorAIRun.  Here the page only
	// shows what the last click produced for this window: reviews for the
	// rows still present, the rows it nominated unless they have since been
	// banned or dismissed, the reverse DNS it resolved -- and how old that
	// is, so the operator can decide whether to ask again.
	var reviews map[string]advisor.Review
	aiCfg := h.cfg().AIAdvisor
	aiHave, aiFailed, aiAt, aiAge, aiModel, aiErr, aiErrAt := false, false, "", "", "", "", ""
	var aiErrAtTs int64
	aiReviewed, aiKept := 0, 0
	aiIn, aiOut := 0, 0
	var aiAtTs int64
	lang := string(i18n.Resolve(r))
	aiRunning, aiSince := false, 0
	aiSentRows, aiKeptRows := map[string]bool{}, map[string]bool{}
	if aiCfg.Active() {
		if info, ok := advisor.Running(advisor.ResultKey(aiCfg, windowH*60, lang)); ok {
			aiRunning, aiSince = true, int(time.Since(info.Since).Seconds())
			aiSentRows, aiKeptRows = info.Sent, info.Kept
		}
		if st, ok := advisor.LastResult(h.DB, advisor.ResultKey(aiCfg, windowH*60, lang)); ok {
			aiModel = st.Model
			if st.HasResult() {
				// The last answer.  Shown even when a later attempt failed:
				// a failure never erases it (advisor.StoreLast).
				aiHave = true
				// The page formats aiAtTs in the operator's timezone (compact);
				// aiAt is the no-JS fallback.
				aiAt = st.At.UTC().Format("2006-01-02 15:04 UTC")
				aiAtTs = st.At.Unix()
				aiAge = humanAge(time.Since(st.At))
				aiReviewed, aiKept = st.Reviewed, st.Kept
				aiIn, aiOut = st.InTokens, st.OutTokens
				reviews = st.Reviews
				present := map[string]bool{}
				for i := range cands {
					present[cands[i].Target] = true
					if v := st.RDNS[cands[i].Target]; v != "" && cands[i].Type == "ip" {
						cands[i].RDNS = v
					}
				}
				for _, n := range st.Nominated {
					if present[n.Target] {
						continue
					}
					if n.Type == "ip" && (excl.BannedIPs[n.Target] || excl.DismissedIP[n.Target]) {
						continue
					}
					if n.Type == "ja4" && (excl.BannedJA4s[n.Target] || excl.DismissedJA4[n.Target]) {
						continue
					}
					cands = append(cands, n)
				}
			}
			if st.Err != "" {
				// The latest attempt failed: the bar says so once, with its
				// time and the reason, under the answer that still stands.
				aiFailed, aiErr = true, st.Err
				aiErrAt = st.ErrAt.UTC().Format("2006-01-02 15:04 UTC")
				aiErrAtTs = st.ErrAt.Unix()
			}
		}
	}

	// Default view: the rows that deserve attention (score >= AttentionScore)
	// and whatever the model nominated.  A three-hit scanner probe or a
	// thirty-serve hammerer is real but rarely worth a ban; it stays behind
	// the "show all" filter until its volume (high_volume) or a second signal
	// lifts it.
	for i := range cands {
		switch cands[i].Type {
		case "ip":
			cands[i].Dismissed = dismissedIP[cands[i].Target]
		case "ja4":
			cands[i].Dismissed = dismissedJA4[cands[i].Target]
		}
	}
	hidden := 0
	if !showAll {
		kept := cands[:0]
		for _, c := range cands {
			if c.Attention() || c.Dismissed {
				kept = append(kept, c)
			} else {
				hidden++
			}
		}
		cands = kept
	}

	banAct, banEffect := h.banDialogEffect()
	data := map[string]any{
		"Lang":           i18n.Resolve(r),
		"TZ":             resolveTZ(r),
		"BasePath":       h.cfg().Server.BasePath,
		"Version":        h.Version,
		"BanTab":         "advisor",
		"Candidates":     cands,
		"ShowAll":        showAll,
		"Hidden":         hidden,
		"AttentionScore": advisor.AttentionScore,
		"Reviews":        reviews,
		"AIActive":       aiCfg.Active(),
		"AIHave":         aiHave,
		"AIFailed":       aiFailed,
		"AIAt":           aiAt,
		"AIAtTs":         aiAtTs,
		"AIReviewed":     aiReviewed,
		"AIKept":         aiKept,
		"AIInTokens":     aiIn,
		"AIOutTokens":    aiOut,
		"AIAge":          aiAge,
		"AIModel":        aiModel,
		"AIErrAt":        aiErrAt,
		"AIErrAtTs":      aiErrAtTs,
		// A run in flight: the bar says so, the rows show they are being
		// analysed, and the page's script polls until the answer lands.
		"AIRunning":      aiRunning,
		"AIRunningSince": aiSince,
		"AISent":         aiSentRows,
		"AIKeptRows":     aiKeptRows,
		"WindowH":        windowH,
		"EngineErr":      engineErr,
		"CandAge":        humanAge(time.Since(candAt)),
		"CandStale":      time.Since(candAt) >= 60*time.Second, // served from memory, refresh running behind
		"LLMErr":         aiErr,
		"Saved":          r.URL.Query().Get("saved") != "",
		"Dismissed":      r.URL.Query().Get("done") == "dismissed",
		"Undismissed":    r.URL.Query().Get("done") == "undismissed",
		"ShowDismissed":  showDismissed,
		// The BAN dialog is the bot-hunt one (partial_ban_dialog.html): same
		// sharing gate, and here the reason row is always editable.
		"CommunityBansActive":   h.snapshotSettings().CommunityBans.SubmitActive(),
		"BanDialogReasonAlways": true,
		"BanDialogAction":       banAct,
		"BanDialogEffectKey":    banEffect,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	h.addMeToData(r, data)
	if err := tmpl.ExecuteTemplate(w, "advisor.html", data); err != nil {
		log.Printf("advisor render: %v", err)
	}
}

// AdminAdvisorDismiss: POST {base}/admin/advisor/dismiss — remember that the
// operator rejected one candidate so it stops being proposed.
func (h *Handler) AdminAdvisorDismiss(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	base := h.cfg().Server.BasePath
	targetType := strings.TrimSpace(r.FormValue("target_type"))
	target := strings.TrimSpace(r.FormValue("target"))
	if (targetType != "ip" && targetType != "ja4") || target == "" || len(target) > 64 {
		http.Error(w, "bad target", http.StatusBadRequest)
		return
	}
	me := ""
	if pay := SessionFromContext(r); pay != nil {
		if u, err := h.UserRepo.GetByID(r.Context(), pay.UserID); err == nil {
			me = u.Username
		}
	}
	row := db.AdvisorDismiss{
		TargetType:  targetType,
		Target:      target,
		DismissedBy: me,
		DismissedAt: time.Now().UTC().Unix(),
	}
	if err := h.DB.Gorm.WithContext(r.Context()).
		Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "target_type"}, {Name: "target"}},
			DoUpdates: clause.AssignmentColumns([]string{"dismissed_by", "dismissed_at"}),
		}).Create(&row).Error; err != nil {
		log.Printf("advisor dismiss: %v", err)
		http.Error(w, "store error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, base+"/admin/advisor/?done=dismissed", http.StatusFound)
}

// AdminAdvisorUndismiss: POST {base}/admin/advisor/undismiss — take a
// dismissal back; the target is proposed again from the next render.
func (h *Handler) AdminAdvisorUndismiss(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	base := h.cfg().Server.BasePath
	targetType := strings.TrimSpace(r.FormValue("target_type"))
	target := strings.TrimSpace(r.FormValue("target"))
	if (targetType != "ip" && targetType != "ja4") || target == "" || len(target) > 64 {
		http.Error(w, "bad target", http.StatusBadRequest)
		return
	}
	if err := h.DB.Gorm.WithContext(r.Context()).
		Where("target_type = ? AND target = ?", targetType, target).
		Delete(&db.AdvisorDismiss{}).Error; err != nil {
		log.Printf("advisor undismiss: %v", err)
		http.Error(w, "store error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("%s/admin/advisor/?window=%d&show_dismissed=1&done=undismissed", base, advisorWindow(r.FormValue("window"))), http.StatusFound)
}

// advisorExclusions assembles everything the engine must never propose:
// existing bans, dismissed candidates, and the install's own monitoring
// addresses (stats_exclude_ips).
func (h *Handler) advisorExclusions(ctx context.Context) (advisor.Exclusions, error) {
	excl := advisor.Exclusions{
		BannedIPs:    map[string]bool{},
		BannedJA4s:   map[string]bool{},
		DismissedIP:  map[string]bool{},
		DismissedJA4: map[string]bool{},
		ExcludeIPs:   map[string]bool{},
	}
	for _, ip := range h.cfg().Nginx.StatsExcludeIPs {
		excl.ExcludeIPs[strings.TrimSpace(ip)] = true
	}
	// The lists are read independently: a failure on one is reported, but
	// the others still apply (a bans read that fails must not bring the
	// operator's dismissals back into the list).
	var firstErr error
	var bans []db.Ban
	if err := h.DB.Gorm.WithContext(ctx).Find(&bans).Error; err != nil {
		firstErr = err
	}
	for _, b := range bans {
		if b.IP != "" {
			excl.BannedIPs[b.IP] = true
		}
		if b.JA4 != "" {
			excl.BannedJA4s[b.JA4] = true
		}
	}
	var dis []db.AdvisorDismiss
	if err := h.DB.Gorm.WithContext(ctx).Find(&dis).Error; err != nil && firstErr == nil {
		firstErr = err
	}
	for _, d := range dis {
		if d.TargetType == "ja4" {
			excl.DismissedJA4[d.Target] = true
		} else {
			excl.DismissedIP[d.Target] = true
		}
	}
	return excl, firstErr
}

// RunAdvisorSchedule starts the scheduled digest pass.  Started unconditionally
// at boot like the other monitors: the schedule itself is read live inside the
// loop, so switching it on in the web UI takes effect without a restart, and
// with it off the loop just sleeps.
func (h *Handler) RunAdvisorSchedule(ctx context.Context) {
	if h.DB == nil {
		return
	}
	advisor.RunSchedule(ctx, advisor.Deps{
		DB:  h.DB,
		Geo: h.IPGeo,
		Cfg: func() settings.AIAdvisorConfig { return h.cfg().AIAdvisor },
		Excl: func(c context.Context) (advisor.Exclusions, error) {
			return h.advisorExclusions(c)
		},
		Notify: func(d advisor.Digest) {
			defer safe.Recover("advisor-digest-notify")
			if h.Notifier == nil {
				return
			}
			h.Notifier.AdvisorDigest(len(d.New), d.Total,
				advisor.FormatDigest(d, h.advisorPageURL()))
		},
	})
}

// advisorPageURL builds the link carried in the digest.  The daemon does not
// know the name visitors reach it by, so it uses the first configured admin
// hostname when there is one and leaves the link out otherwise -- a wrong URL
// in an alert is worse than none.
func (h *Handler) advisorPageURL() string {
	hosts := settings.EnabledValues(h.cfg().Nginx.AdminAllowedHosts, h.cfg().Nginx.AdminAllowedHostsDisabled)
	if len(hosts) == 0 {
		return ""
	}
	return "https://" + hosts[0] + h.cfg().Server.BasePath + "/admin/advisor/"
}

// AdminAdvisorAIRun: POST {base}/admin/advisor/ai-run — the click that asks
// the model.  The plan is made here, synchronously and cheaply (the engine
// query plus a fingerprint comparison with the last result): which
// candidates go to the model and which keep their review.  The answer comes
// straight back with that plan -- JSON for the page's script, which then
// shows a spinner on the sent rows and "kept" on the others and polls
// AdminAdvisorAIStatus; a redirect for a plain form post -- and the pool,
// the model and the merge run in the background (advisor.StartRun).  When
// nothing is to be sent the result is stored at once and no run starts.  A
// click while a run for the same window is out attaches to that run.
func (h *Handler) AdminAdvisorAIRun(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	windowH := advisorWindow(r.FormValue("window"))
	back := fmt.Sprintf("%s/admin/advisor/?window=%d", h.cfg().Server.BasePath, windowH)
	if r.FormValue("min") == "all" {
		back += "&min=all"
	}
	if r.FormValue("show_dismissed") == "1" {
		back += "&show_dismissed=1"
	}
	aiCfg := h.cfg().AIAdvisor
	if !aiCfg.Active() {
		if wantsJSON(r) {
			writeJSON(w, http.StatusConflict, map[string]any{"running": false, "error": "ai advisor is not enabled"})
			return
		}
		http.Redirect(w, r, back, http.StatusFound)
		return
	}
	lang := string(i18n.Resolve(r))
	key := advisor.ResultKey(aiCfg, windowH*60, lang)
	respond := func(code int, body map[string]any) {
		if wantsJSON(r) {
			writeJSON(w, code, body)
			return
		}
		http.Redirect(w, r, back, http.StatusFound)
	}
	if info, ok := advisor.Running(key); ok {
		respond(http.StatusAccepted, map[string]any{"running": true, "since": int(time.Since(info.Since).Seconds()), "sent": keys(info.Sent), "kept": keys(info.Kept)})
		return
	}
	prep, err := h.planAdvisorAI(r.Context(), aiCfg, windowH, lang)
	if err != nil {
		advisor.StoreLast(h.DB, key, advisor.Stored{ErrAt: time.Now(), Model: aiCfg.ResolvedModel(), Err: err.Error()})
		respond(http.StatusOK, map[string]any{"running": false, "error": err.Error()})
		return
	}
	if len(prep.send) == 0 && prep.prev.HasResult() {
		// Nothing changed since the last answer: keep it, say so, call no one
		// (and a failed attempt in between is moot -- cleared).
		st := prep.prev
		st.At, st.Model, st.Reviewed, st.Kept = time.Now(), aiCfg.ResolvedModel(), 0, len(prep.kept)
		st.Err, st.ErrAt = "", time.Time{}
		advisor.StoreLast(h.DB, key, st)
		respond(http.StatusOK, map[string]any{"running": false, "nochange": true, "kept": len(prep.kept)})
		return
	}
	info := advisor.RunInfo{Sent: map[string]bool{}, Kept: map[string]bool{}}
	for _, c := range prep.send {
		info.Sent[c.Target] = true
	}
	for t := range prep.kept {
		info.Kept[t] = true
	}
	advisor.StartRun(h.DB, key, info, func(ctx context.Context) advisor.Stored {
		return h.finishAdvisorAI(ctx, aiCfg, lang, prep)
	})
	respond(http.StatusAccepted, map[string]any{"running": true, "since": 0, "sent": keys(info.Sent), "kept": keys(info.Kept)})
}

// AdminAdvisorAIStatus: GET {base}/admin/advisor/ai-status?window=N — is a run
// for this window still out (and what it is doing), and is there a result.
func (h *Handler) AdminAdvisorAIStatus(w http.ResponseWriter, r *http.Request) {
	windowH := advisorWindow(r.URL.Query().Get("window"))
	aiCfg := h.cfg().AIAdvisor
	if !aiCfg.Active() {
		writeJSON(w, http.StatusOK, map[string]any{"active": false, "running": false})
		return
	}
	key := advisor.ResultKey(aiCfg, windowH*60, string(i18n.Resolve(r)))
	out := map[string]any{"active": true, "running": false, "have": false}
	if info, ok := advisor.Running(key); ok {
		out["running"] = true
		out["since"] = int(time.Since(info.Since).Seconds())
		out["sent"] = keys(info.Sent)
		out["kept"] = keys(info.Kept)
	}
	if st, ok := advisor.LastResult(h.DB, key); ok {
		out["have"] = st.HasResult() // the answer stands even when the latest attempt failed
		if st.Err != "" {
			out["error"] = st.Err
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// AdminJA4Collateral: GET {base}/admin/api/ja4-collateral?ja4=... — what a
// ban of this fingerprint would hit: the BAN dialog asks before it lets the
// operator confirm.
func (h *Handler) AdminJA4Collateral(w http.ResponseWriter, r *http.Request) {
	ja4 := strings.TrimSpace(r.URL.Query().Get("ja4"))
	if ja4 == "" || len(ja4) > 64 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "bad ja4"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	col, err := advisor.JA4Collateral(ctx, h.DB, ja4)
	if err != nil {
		log.Printf("ja4 collateral: %v", err)
		writeJSON(w, http.StatusOK, map[string]any{"ja4": ja4, "error": "could not measure the collateral"})
		return
	}
	writeJSON(w, http.StatusOK, col)
}

// advisorPrep is what the synchronous half of a run hands to the background
// half: the candidates, the plan, and what the pool query needs.
type advisorPrep struct {
	excl    advisor.Exclusions
	opt     advisor.Options
	current map[string]bool
	prev    advisor.Stored
	send    []advisor.Candidate
	kept    map[string]advisor.Review
}

// planAdvisorAI runs the engine and the fingerprint comparison: cheap, so it
// happens on the click itself and the page can show the plan at once.
func (h *Handler) planAdvisorAI(ctx context.Context, aiCfg settings.AIAdvisorConfig, windowH int, lang string) (*advisorPrep, error) {
	key := advisor.ResultKey(aiCfg, windowH*60, lang)
	excl, err := h.advisorExclusions(ctx)
	if err != nil {
		log.Printf("advisor exclusions: %v", err)
	}
	opt := advisor.Options{WindowMinutes: windowH * 60}
	cands, _, err := advisor.CachedCandidates(ctx, h.DB, h.IPGeo, excl, opt)
	if err != nil {
		return nil, err
	}
	// Only the rows worth attention go to the model: the low scores are
	// hidden by default anyway, and every candidate costs tokens.
	worth := make([]advisor.Candidate, 0, len(cands))
	current := map[string]bool{}
	for _, c := range cands {
		current[c.Target] = true
		if c.Attention() {
			worth = append(worth, c)
		}
	}
	// Incremental: what the last run already reviewed and whose evidence has
	// not changed is carried over; only the rest is sent.
	prev, _ := advisor.LastResult(h.DB, key)
	send, kept := advisor.Plan(prev, worth)
	return &advisorPrep{excl: excl, opt: opt, current: current, prev: prev, send: send, kept: kept}, nil
}

// finishAdvisorAI is the background half: the wider pool with its reverse
// DNS, the model, the merge.  ctx is the run's own (advisor.runTimeout), not
// the click's -- see StartRun.
func (h *Handler) finishAdvisorAI(ctx context.Context, aiCfg settings.AIAdvisorConfig, lang string, prep *advisorPrep) advisor.Stored {
	st := advisor.Stored{At: time.Now(), Model: aiCfg.ResolvedModel()}
	pool, err := advisor.BuildPool(ctx, h.DB, h.IPGeo, prep.excl, prep.opt)
	if err != nil {
		log.Printf("advisor pool: %v", err)
		pool = advisor.Pool{}
	}
	// The model must know what a fingerprint ban would hit.
	for i := range prep.send {
		if prep.send[i].Type != "ja4" {
			continue
		}
		if col, err := advisor.JA4Collateral(ctx, h.DB, prep.send[i].Target); err == nil {
			prep.send[i].PassIPs7d, prep.send[i].Verdict = col.PassIPs, col.Verdict
		} else {
			log.Printf("advisor collateral: %v", err)
		}
	}
	res, err := advisor.ReviewWithPool(ctx, aiCfg, prep.send, pool, lang)
	if err != nil {
		// StoreLast keeps the last answer and notes this failure beside it.
		return advisor.Stored{Model: aiCfg.ResolvedModel(), Err: err.Error(), ErrAt: time.Now()}
	}
	merged := advisor.Merge(prep.prev, prep.send, res, pool, prep.kept, prep.current)
	st.Reviews, st.Nominated, st.Reviewed, st.Kept = merged.Reviews, merged.Nominated, merged.Reviewed, merged.Kept
	st.InTokens, st.OutTokens = merged.InTokens, merged.OutTokens
	st.RDNS = map[string]string{}
	for _, row := range pool.IPs {
		if row.RDNS != "" {
			st.RDNS[row.IP] = row.RDNS
		}
	}
	return st
}

// keys lists a set, sorted, for JSON.
func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// advisorWindow parses the window (hours) the page and its endpoints share.
func advisorWindow(v string) int {
	if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n >= 1 && n <= 24*14 {
		return n
	}
	return 24
}

func wantsJSON(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept"), "application/json")
}

// banDialogEffect: what a ban added from bot hunt / the advisor does on this
// install (source=manual, no per-row action) -- the dialog says so, because
// by default it is a challenge, not a refusal, and a human still gets
// through.  Returns the action code and the i18n key of its explanation
// ("" for a value the dictionary does not know).
func (h *Handler) banDialogEffect() (string, string) {
	act := h.cfg().Nginx.Bans.ResolveAction("manual", "")
	switch act {
	case settings.RateChallengeDeny, settings.RateChallengeCaptchaOnly, settings.RateChallengePoWOnly, settings.RateChallengePoWThenCaptcha:
		return act, "hunt.ban.effect." + act
	}
	return act, ""
}

// humanAge: "3m" / "2h" / "1d" -- language-neutral, read next to the model
// name in the AI bar.
func humanAge(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "<1m"
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	}
	return fmt.Sprintf("%dd", int(d.Hours()/24))
}
