package handlers

import (
	"io"
	"testing"

	"gorm.io/gorm/clause"

	"context"
	"encoding/json"
	"github.com/unmask-sh/unmask/admin/internal/advisor"
	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/events"
	"github.com/unmask-sh/unmask/admin/internal/i18n"
	"github.com/unmask-sh/unmask/admin/internal/settings"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// The advisor page must render with the shared template set — a field typo or
// a broken pipeline in advisor.html would otherwise only surface on the first
// live click.
func TestAdvisorTemplateRenders(t *testing.T) {
	tmpl, err := loadDashboardTemplate()
	if err != nil {
		t.Fatal(err)
	}
	data := map[string]any{
		"Lang":     i18n.Lang("en"),
		"TZ":       "UTC",
		"BasePath": "/unmask",
		"Version":  "test",
		"WindowH":  24,
		"Candidates": []advisor.Candidate{
			{
				Type: "ip", Target: "203.0.113.9", Scope: "ip_only", JA4: "t13d_x",
				UA:      "curl/8",
				Signals: []advisor.Signal{{ID: "challenge_hammering", Detail: "42 serves", Weight: 3}},
				Score:   3, Serves: 42, Passes: 0,
				FirstSeen: "2026-09-03 00:00:00", LastSeen: "2026-09-03 01:00:00",
				ASNOrg: "ExampleHost", Country: "US",
				SamplePaths: []string{"/.env"},
			},
			{
				Type: "ja4", Target: "q13d_herd", Scope: "ja4_only",
				Signals: []advisor.Signal{{ID: "ja4_herd", Detail: "12 addresses", Weight: 3}},
				Score:   3, Serves: 60, Passes: 0, DistinctIPs: 12,
				FirstSeen: "2026-09-03 00:00:00", LastSeen: "2026-09-03 01:00:00",
			},
		},
		"EngineErr":             "",
		"Saved":                 false,
		"Dismissed":             false,
		"CommunityBansActive":   false,
		"BanDialogReasonAlways": true,
		"CSRFToken":             "tok",
		"NavCommunityBadge":     0,
		"Me":                    nil,
		"MeName":                "",
		"Hosts":                 nil,
		"HostSelected":          "",
		"SelfHostID":            "",
		"Sites":                 nil,
		"SiteSelected":          "",
	}
	if err := tmpl.ExecuteTemplate(io.Discard, "advisor.html", data); err != nil {
		t.Fatalf("advisor.html render: %v", err)
	}
}

// The dismiss store must upsert on (target_type, target): a second dismissal
// updates the row instead of erroring on the unique key.
func TestAdvisorDismissUpsert(t *testing.T) {
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: t.TempDir() + "/a.sqlite"})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := db.Migrate(d); err != nil {
		t.Fatal(err)
	}
	save := func(by string, at int64) {
		row := db.AdvisorDismiss{TargetType: "ip", Target: "203.0.113.9", DismissedBy: by, DismissedAt: at}
		if err := d.Gorm.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "target_type"}, {Name: "target"}},
			DoUpdates: clause.AssignmentColumns([]string{"dismissed_by", "dismissed_at"}),
		}).Create(&row).Error; err != nil {
			t.Fatal(err)
		}
	}
	save("alice", 100)
	save("bob", 200)

	var rows []db.AdvisorDismiss
	if err := d.Gorm.Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 row after upsert, got %d", len(rows))
	}
	if rows[0].DismissedBy != "bob" || rows[0].DismissedAt != 200 {
		t.Errorf("upsert did not update: %+v", rows[0])
	}
}

// The click starts a background run and the page stays put: ai-run answers
// 202 at once, the page rendered meanwhile shows every eligible row as
// "analysing" with the button disabled, ai-status says running, a second
// click attaches to the run rather than paying twice, and when the provider
// answers the page shows the reviews and the nominated row -- without calling
// the provider again.  Low-score candidates are hidden by default, shown
// under min=all, and never sent to the model.  A plain (non-fetch) post
// redirects back to the window.
func TestAdvisorAIRunStoresAndShows(t *testing.T) {
	advisor.ResetCandidateCache()
	var calls int32
	var mu sync.Mutex
	var bundles []string
	release := make(chan struct{})
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		raw, _ := io.ReadAll(r.Body)
		mu.Lock()
		bundles = append(bundles, string(raw))
		mu.Unlock()
		select {
		case <-release:
		case <-time.After(10 * time.Second):
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"stop_reason":"end_turn","content":[{"type":"text","text":"{\"reviews\":[{\"target\":\"203.0.113.10\",\"priority\":\"low\",\"reasoning\":\"contained scanner, cost only\"},{\"target\":\"203.0.113.11\",\"priority\":\"low\",\"reasoning\":\"second scanner\"}],\"nominations\":[{\"target\":\"198.51.100.7\",\"type\":\"ip\",\"priority\":\"high\",\"reasoning\":\"passes at scale from a farm\"}]}"}],"usage":{"input_tokens":4321,"output_tokens":210}}`))
	}))
	defer stub.Close()
	orig := advisor.LookupPTR
	advisor.LookupPTR = func(ctx context.Context, ip string) []string { return nil }
	t.Cleanup(func() { advisor.LookupPTR = orig })

	h := newTestHandler(t)
	cur := h.snapshotSettings()
	cur.AIAdvisor = settings.AIAdvisorConfig{Enabled: true, Provider: "anthropic", APIKey: "k", Endpoint: stub.URL}
	h.settingsPtr.Store(&cur)
	seed := func(ip, phase, payload string, n int) {
		for i := 0; i < n; i++ {
			if _, err := h.DB.Exec(`INSERT INTO unmask_event
				(site,host,scheme,port,ip_address,user_agent,ja4,ja4_verdict,ja4_verdict_id,phase,flags,reload_count,cookie_bv,cookie_br,payload_json,date_created)
				VALUES ('','','',0,?,'Mozilla/5.0','t13d_x','',0,?,0,0,'','',?,datetime('now'))`,
				events.PackIP(ip), phase, payload); err != nil {
				t.Fatal(err)
			}
		}
	}
	seed("203.0.113.10", "serve", `{"path":"/.env"}`, 35) // engine candidate: hammering + scanner = 6
	seed("203.0.113.11", "serve", `{"path":"/.env"}`, 35) // a second one; the stub reviews it too
	seed("203.0.113.77", "serve", `{"path":"/.env"}`, 3)  // a lone three-hit probe: score 3, below the floor
	seed("198.51.100.7", "serve", "{}", 8)                // pool only: passes, no rule flags it
	seed("198.51.100.7", "bv_pow_only", "{}", 6)

	get := func(q string) string {
		req := httptest.NewRequest(http.MethodGet, "/unmask/admin/advisor/?window=24"+q, nil)
		rr := httptest.NewRecorder()
		h.AdminAdvisorIndex(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("advisor page: %d", rr.Code)
		}
		return rr.Body.String()
	}
	status := func() string {
		req := httptest.NewRequest(http.MethodGet, "/unmask/admin/advisor/ai-status?window=24", nil)
		rr := httptest.NewRecorder()
		h.AdminAdvisorAIStatus(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("ai-status: %d", rr.Code)
		}
		return rr.Body.String()
	}
	post := func(json bool) *httptest.ResponseRecorder {
		form := url.Values{"window": {"24"}}
		req := httptest.NewRequest(http.MethodPost, "/unmask/admin/advisor/ai-run", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if json {
			req.Header.Set("Accept", "application/json")
		}
		rr := httptest.NewRecorder()
		h.AdminAdvisorAIRun(rr, req)
		return rr
	}
	key := advisor.ResultKey(cur.AIAdvisor, 24*60, string(i18n.Resolve(httptest.NewRequest(http.MethodGet, "/", nil))))
	waitDone := func() {
		deadline := time.Now().Add(8 * time.Second)
		for {
			if _, running := advisor.Running(key); !running {
				return
			}
			if time.Now().After(deadline) {
				t.Fatal("the run did not finish")
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	waitCalls := func(n int32) {
		deadline := time.Now().Add(8 * time.Second)
		for atomic.LoadInt32(&calls) < n {
			if time.Now().After(deadline) {
				t.Fatalf("provider calls = %d, want %d", atomic.LoadInt32(&calls), n)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}

	body := get("")
	if atomic.LoadInt32(&calls) != 0 {
		t.Fatalf("the page load called the provider %d time(s)", calls)
	}
	// The note mentions ai_pick by name, so look for the rendered badge class.
	// (the <template> for the spinner is always in the page; a spinner IN a
	// row is the slot marker followed by the wait span)
	const rowSpinner = `data-target="203.0.113.10"><span class="ai-wait"`
	if !strings.Contains(body, `/admin/advisor/ai-run`) || strings.Contains(body, `class="sig ai"`) || strings.Contains(body, rowSpinner) {
		t.Fatalf("before the click: expected the button, no nomination and no spinner")
	}
	if !strings.Contains(body, `class="score">`) {
		t.Fatal("the rows must show the engine's score")
	}
	// The dialog says what a ban does on this install: the manual default,
	// a challenge chain unless the operator configured deny.
	if !strings.Contains(body, `class="ban-dialog-effect"`) || !strings.Contains(body, `<code>pow_then_captcha</code>`) {
		t.Error("the BAN dialog must state the ban's effect (manual default: pow_then_captcha)")
	}
	if strings.Contains(body, "203.0.113.77") || !strings.Contains(body, `class="hidden-note"`) {
		t.Fatal("the lone probe must be hidden by default, with the note saying so")
	}
	if all := get("&min=all"); !strings.Contains(all, "203.0.113.77") || strings.Contains(all, `class="hidden-note"`) {
		t.Fatal("min=all must show the lone probe and drop the note")
	}
	if !strings.Contains(status(), `"running":false`) {
		t.Fatalf("idle status: %s", status())
	}

	// The click: 202 at once with the plan (everything is new), the run is out.
	rr := post(true)
	if rr.Code != http.StatusAccepted || !strings.Contains(rr.Body.String(), `"running":true`) || !strings.Contains(rr.Body.String(), `"sent":["203.0.113.10","203.0.113.11"]`) {
		t.Fatalf("ai-run (fetch): want 202 running with the plan, got %d %s", rr.Code, rr.Body.String())
	}
	waitCalls(1)
	if !strings.Contains(status(), `"running":true`) {
		t.Fatalf("status during the run: %s", status())
	}
	body = get("")
	if !strings.Contains(body, rowSpinner) || !strings.Contains(body, `data-running="1"`) || !strings.Contains(body, `class="btn ai" disabled`) {
		t.Fatal("the page rendered mid-run must show the rows as analysing and the button disabled")
	}
	// A second click while the run is out attaches to it.
	if rr := post(true); rr.Code != http.StatusAccepted {
		t.Fatalf("second click: %d", rr.Code)
	}
	close(release)
	waitDone()
	if n := atomic.LoadInt32(&calls); n != 1 {
		t.Fatalf("two clicks during one run must call the provider once, got %d", n)
	}
	if st := status(); !strings.Contains(st, `"running":false`) || !strings.Contains(st, `"have":true`) {
		t.Fatalf("status after the run: %s", st)
	}
	// The bundle carried the candidate worth attention and not the lone probe
	// (the probe may still sit in the pool, which is the wider ranking).
	mu.Lock()
	sent := bundles[0]
	mu.Unlock()
	var req struct {
		Messages []struct {
			Content string `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal([]byte(sent), &req); err != nil || len(req.Messages) == 0 {
		t.Fatalf("cannot read the provider request: %v", err)
	}
	parts := strings.SplitN(req.Messages[0].Content, "\n\n", 2)
	var bundle struct {
		Candidates []struct {
			Target string `json:"target"`
		} `json:"candidates"`
	}
	// The bundle is the first JSON value after the intro line; a language
	// instruction may follow it, so decode rather than unmarshal.
	if len(parts) != 2 || json.NewDecoder(strings.NewReader(parts[1])).Decode(&bundle) != nil {
		t.Fatalf("cannot read the bundle: %.300q", req.Messages[0].Content)
	}
	sentTargets := map[string]bool{}
	for _, c := range bundle.Candidates {
		sentTargets[c.Target] = true
	}
	if !sentTargets["203.0.113.10"] || !sentTargets["203.0.113.11"] || sentTargets["203.0.113.77"] || len(sentTargets) != 2 {
		t.Errorf("the model must get the attention-worthy candidates only, got %v", sentTargets)
	}

	body = get("")
	if atomic.LoadInt32(&calls) != 1 {
		t.Fatalf("showing the stored result must not call the provider again (%d)", calls)
	}
	for _, want := range []string{"contained scanner, cost only", `class="sig ai"`, "198.51.100.7", "passes at scale from a farm", "claude-opus-5", `class="ai-box"><span class="ai-tag">`} {
		if !strings.Contains(body, want) {
			t.Errorf("after the run the page is missing %q", want)
		}
	}
	if strings.Contains(body, rowSpinner) {
		t.Error("no spinner once the run is done")
	}
	// No empty card anywhere (index on a missing map key yields a zero
	// struct, which templates treat as true).
	if strings.Contains(body, `<span class="prio "></span>`) {
		t.Error("never an empty card")
	}
	if !strings.Contains(body, `data-reviewed="2" data-kept="0"`) {
		t.Error("the first run must report two reviewed, none kept")
	}
	if !strings.Contains(body, `class="ai-when">`) {
		t.Error("each card says when its review was fetched")
	}
	if !strings.Contains(body, "4,321") || !strings.Contains(body, "210") {
		t.Error("the last-run line must show the tokens the provider reported")
	}
	if !strings.Contains(body, `data-state="have"`) {
		t.Error("the bar must say it has an answer")
	}
	if !strings.Contains(body, `class="js-datetime js-datetime-short ai-at" data-ts="`) {
		t.Error("the bar's timestamp must be the compact tz-aware one")
	}
	// A restart forgets the in-memory copy; the page must still show the
	// answer (unmask_advisor_result), without asking the provider again.
	advisor.ForgetInMemory()
	body = get("")
	if atomic.LoadInt32(&calls) != 1 || !strings.Contains(body, "contained scanner, cost only") || !strings.Contains(body, `data-state="have"`) {
		t.Fatal("after a restart the stored answer must come back from the database")
	}

	// A plain form post (no fetch) redirects back to the window -- and, the
	// evidence being unchanged, nothing is sent: no run starts, no provider
	// call, the answer is "no change" at once.
	rr = post(false)
	if rr.Code != http.StatusFound || rr.Header().Get("Location") != h.cfg().Server.BasePath+"/admin/advisor/?window=24" {
		t.Fatalf("ai-run (form): want 302 back to the window, got %d %s", rr.Code, rr.Header().Get("Location"))
	}
	if _, running := advisor.Running(key); running {
		t.Fatal("an unchanged rerun must not start a run")
	}
	if n := atomic.LoadInt32(&calls); n != 1 {
		t.Fatalf("an unchanged rerun must not call the provider, calls = %d", n)
	}
	if rr := post(true); rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"nochange":true`) {
		t.Fatalf("an unchanged fetch click answers nochange at once, got %d %s", rr.Code, rr.Body.String())
	}
	body = get("")
	if !strings.Contains(body, `data-reviewed="0" data-kept="2"`) || !strings.Contains(body, "contained scanner, cost only") || !strings.Contains(body, "second scanner") {
		t.Fatal("an unchanged rerun keeps both reviews and says nothing was sent")
	}
	// One candidate's evidence moves on: only that one is sent, the other
	// review is carried over.
	seed("203.0.113.11", "serve", `{"path":"/.env"}`, 1)
	advisor.ResetCandidateCache() // the list is cached for a minute; the seed must be seen
	rr = post(true)
	if rr.Code != http.StatusAccepted || !strings.Contains(rr.Body.String(), `"sent":["203.0.113.11"]`) || !strings.Contains(rr.Body.String(), `"kept":["203.0.113.10"]`) {
		t.Fatalf("third run: want the plan (send .11, keep .10), got %d %s", rr.Code, rr.Body.String())
	}
	waitDone()
	if n := atomic.LoadInt32(&calls); n != 2 {
		t.Fatalf("the changed candidate must be sent, calls = %d", n)
	}
	mu.Lock()
	sent = bundles[1]
	mu.Unlock()
	if err := json.Unmarshal([]byte(sent), &req); err != nil || len(req.Messages) == 0 {
		t.Fatalf("cannot read the second provider request: %v", err)
	}
	parts = strings.SplitN(req.Messages[0].Content, "\n\n", 2)
	bundle.Candidates = nil
	if len(parts) != 2 || json.NewDecoder(strings.NewReader(parts[1])).Decode(&bundle) != nil {
		t.Fatalf("cannot read the second bundle")
	}
	if len(bundle.Candidates) != 1 || bundle.Candidates[0].Target != "203.0.113.11" {
		t.Errorf("only the changed candidate goes to the model, got %+v", bundle.Candidates)
	}
	body = get("")
	if !strings.Contains(body, `data-reviewed="1" data-kept="1"`) || !strings.Contains(body, "contained scanner, cost only") {
		t.Fatal("after the partial rerun: one reviewed, one kept, the kept review still shown")
	}
	if strings.Contains(body, `class="badge-new"`) {
		t.Error("every row reviewed: no new badge")
	}
	// A candidate that appears after the last answer is marked new (and
	// shows the not-reviewed note) until the next click covers it.
	seed("203.0.113.12", "serve", `{"path":"/.env"}`, 35)
	advisor.ResetCandidateCache()
	body = get("")
	i := strings.Index(body, `data-ip="203.0.113.12"`)
	if i < 0 || !strings.Contains(body[i:i+3000], `class="badge-new"`) || !strings.Contains(body[i:i+3000], `class="ai-missing"`) {
		t.Error("a row that appeared after the last answer must carry the new badge and the not-reviewed note")
	}
	if j := strings.Index(body, `data-ip="203.0.113.10"`); j < 0 || strings.Contains(body[j:j+1500], `class="badge-new"`) {
		t.Error("a reviewed row is not new")
	}
}

// A failed run is reported as a failure, not as "the model has not been
// asked yet": the bar names it once, with the reason, ai-status reports it,
// and the button offers a retry.  No banner -- one place, not two.
func TestAdvisorAIRunFailureIsShown(t *testing.T) {
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":{"type":"overloaded_error","message":"Overloaded"}}`, http.StatusServiceUnavailable)
	}))
	defer stub.Close()
	orig := advisor.LookupPTR
	advisor.LookupPTR = func(ctx context.Context, ip string) []string { return nil }
	t.Cleanup(func() { advisor.LookupPTR = orig })

	h := newTestHandler(t)
	cur := h.snapshotSettings()
	cur.AIAdvisor = settings.AIAdvisorConfig{Enabled: true, Provider: "anthropic", APIKey: "k", Endpoint: stub.URL}
	h.settingsPtr.Store(&cur)
	for i := 0; i < 35; i++ {
		if _, err := h.DB.Exec(`INSERT INTO unmask_event
			(site,host,scheme,port,ip_address,user_agent,ja4,ja4_verdict,ja4_verdict_id,phase,flags,reload_count,cookie_bv,cookie_br,payload_json,date_created)
			VALUES ('','','',0,?,'curl/8','t13d_x','',0,'serve',0,0,'','','{"path":"/.env"}',datetime('now'))`, events.PackIP("203.0.113.10")); err != nil {
			t.Fatal(err)
		}
	}
	form := url.Values{"window": {"24"}}
	req := httptest.NewRequest(http.MethodPost, "/unmask/admin/advisor/ai-run", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	rr := httptest.NewRecorder()
	h.AdminAdvisorAIRun(rr, req)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("ai-run: %d", rr.Code)
	}
	key := advisor.ResultKey(cur.AIAdvisor, 24*60, string(i18n.Resolve(httptest.NewRequest(http.MethodGet, "/", nil))))
	deadline := time.Now().Add(8 * time.Second)
	for {
		if _, running := advisor.Running(key); !running {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the run did not finish")
		}
		time.Sleep(20 * time.Millisecond)
	}
	sreq := httptest.NewRequest(http.MethodGet, "/unmask/admin/advisor/ai-status?window=24", nil)
	srr := httptest.NewRecorder()
	h.AdminAdvisorAIStatus(srr, sreq)
	if st := srr.Body.String(); !strings.Contains(st, `"have":false`) || !strings.Contains(st, `"error":`) {
		t.Fatalf("status after a failed run: %s", st)
	}
	preq := httptest.NewRequest(http.MethodGet, "/unmask/admin/advisor/?window=24", nil)
	prr := httptest.NewRecorder()
	h.AdminAdvisorIndex(prr, preq)
	body := prr.Body.String()
	if !strings.Contains(body, `data-state="failed"`) || !strings.Contains(body, `data-failed="1"`) || strings.Count(body, `class="ai-failed"`) != 1 {
		t.Fatal("a failed run must show as failed in the bar, once")
	}
	if strings.Contains(body, `class="banner bad"`) {
		t.Fatal("the failure is said in the bar, not in a banner as well")
	}
}

// A failed attempt does not erase the last answer: the rows keep their
// reviews, the bar still dates the answer, and the failure is noted once
// beside it with its own time.  (Seen live: a 90-second provider timeout
// wiped the reviews and the error banner then greeted every reload.)
func TestAdvisorAIFailureKeepsLastAnswer(t *testing.T) {
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":{"type":"overloaded_error","message":"Overloaded"}}`, http.StatusServiceUnavailable)
	}))
	defer stub.Close()
	orig := advisor.LookupPTR
	advisor.LookupPTR = func(ctx context.Context, ip string) []string { return nil }
	t.Cleanup(func() { advisor.LookupPTR = orig })

	h := newTestHandler(t)
	cur := h.snapshotSettings()
	cur.AIAdvisor = settings.AIAdvisorConfig{Enabled: true, Provider: "anthropic", APIKey: "k", Endpoint: stub.URL}
	h.settingsPtr.Store(&cur)
	for i := 0; i < 35; i++ {
		if _, err := h.DB.Exec(`INSERT INTO unmask_event
			(site,host,scheme,port,ip_address,user_agent,ja4,ja4_verdict,ja4_verdict_id,phase,flags,reload_count,cookie_bv,cookie_br,payload_json,date_created)
			VALUES ('','','',0,?,'curl/8','t13d_x','',0,'serve',0,0,'','','{"path":"/.env"}',datetime('now'))`, events.PackIP("203.0.113.10")); err != nil {
			t.Fatal(err)
		}
	}
	lang := string(i18n.Resolve(httptest.NewRequest(http.MethodGet, "/", nil)))
	key := advisor.ResultKey(cur.AIAdvisor, 24*60, lang)
	answered := time.Now().Add(-2 * time.Hour).Truncate(time.Second)
	advisor.StoreLast(h.DB, key, advisor.Stored{At: answered, Model: cur.AIAdvisor.ResolvedModel(), Reviewed: 1,
		Reviews: map[string]advisor.Review{"203.0.113.10": {Target: "203.0.113.10", Priority: "high", Reasoning: "kept-after-failure"}}})

	form := url.Values{"window": {"24"}}
	req := httptest.NewRequest(http.MethodPost, "/unmask/admin/advisor/ai-run", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	rr := httptest.NewRecorder()
	h.AdminAdvisorAIRun(rr, req)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("ai-run: %d %s", rr.Code, rr.Body.String())
	}
	deadline := time.Now().Add(8 * time.Second)
	for {
		if _, running := advisor.Running(key); !running {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the run did not finish")
		}
		time.Sleep(20 * time.Millisecond)
	}
	st, ok := advisor.LastResult(h.DB, key)
	if !ok || st.Err == "" || !st.At.Equal(answered) || st.Reviews["203.0.113.10"].Reasoning != "kept-after-failure" || !st.ErrAt.After(answered) {
		t.Fatalf("the failure must sit beside the kept answer: ok=%v %+v", ok, st)
	}
	sreq := httptest.NewRequest(http.MethodGet, "/unmask/admin/advisor/ai-status?window=24", nil)
	srr := httptest.NewRecorder()
	h.AdminAdvisorAIStatus(srr, sreq)
	if s := srr.Body.String(); !strings.Contains(s, `"have":true`) || !strings.Contains(s, `"error":`) {
		t.Fatalf("status after a failed attempt over an answer: %s", s)
	}
	preq := httptest.NewRequest(http.MethodGet, "/unmask/admin/advisor/?window=24", nil)
	prr := httptest.NewRecorder()
	h.AdminAdvisorIndex(prr, preq)
	body := prr.Body.String()
	if !strings.Contains(body, "kept-after-failure") || !strings.Contains(body, `data-state="have"`) || !strings.Contains(body, `data-failed="1"`) {
		t.Fatal("the page must keep showing the last answer and mark the failed attempt")
	}
	if strings.Count(body, `class="ai-failed"`) != 1 || strings.Contains(body, `class="banner bad"`) {
		t.Fatal("the failure is said once, in the bar")
	}
}

// A dismissed candidate leaves the list, comes back marked under the "show
// dismissed" filter with an un-dismiss button, and is a plain candidate again
// once un-dismissed.
func TestAdvisorDismissedFilterAndUndismiss(t *testing.T) {
	h := newTestHandler(t)
	for i := 0; i < 35; i++ {
		if _, err := h.DB.Exec(`INSERT INTO unmask_event
			(site,host,scheme,port,ip_address,user_agent,ja4,ja4_verdict,ja4_verdict_id,phase,flags,reload_count,cookie_bv,cookie_br,payload_json,date_created)
			VALUES ('','','',0,?,'curl/8','t13d_x','',0,'serve',0,0,'','','{"orig_path":"/.env"}',datetime('now'))`, events.PackIP("203.0.113.10")); err != nil {
			t.Fatal(err)
		}
	}
	get := func(q string) string {
		req := httptest.NewRequest(http.MethodGet, "/unmask/admin/advisor/?window=24"+q, nil)
		rr := httptest.NewRecorder()
		h.AdminAdvisorIndex(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("advisor page: %d", rr.Code)
		}
		return rr.Body.String()
	}
	post := func(path string, form url.Values, fn func(http.ResponseWriter, *http.Request)) string {
		req := httptest.NewRequest(http.MethodPost, "/unmask/admin/advisor/"+path, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		fn(rr, req)
		if rr.Code != http.StatusFound {
			t.Fatalf("%s: want 302, got %d %s", path, rr.Code, rr.Body.String())
		}
		return rr.Header().Get("Location")
	}
	if body := get(""); !strings.Contains(body, "203.0.113.10") || !strings.Contains(body, `name="show_dismissed"`) {
		t.Fatal("the candidate and the show-dismissed filter must be on the page")
	}
	post("dismiss", url.Values{"target_type": {"ip"}, "target": {"203.0.113.10"}}, h.AdminAdvisorDismiss)
	if body := get(""); strings.Contains(body, "203.0.113.10") {
		t.Fatal("a dismissed candidate must leave the default list")
	}
	body := get("&show_dismissed=1")
	if !strings.Contains(body, "203.0.113.10") || !strings.Contains(body, `class="state dismissed"`) || !strings.Contains(body, `/admin/advisor/undismiss`) {
		t.Fatal("under show_dismissed the row must be back, marked, with an un-dismiss form")
	}
	loc := post("undismiss", url.Values{"target_type": {"ip"}, "target": {"203.0.113.10"}, "window": {"24"}}, h.AdminAdvisorUndismiss)
	if !strings.Contains(loc, "show_dismissed=1") || !strings.Contains(loc, "done=undismissed") {
		t.Errorf("undismiss must return to the dismissed view with its notice: %s", loc)
	}
	if body := get(""); !strings.Contains(body, "203.0.113.10") || strings.Contains(body, `class="state dismissed"`) {
		t.Fatal("after un-dismissing the candidate is plain again")
	}
}

// A page rendered while a run is out shows the plan: rows the run sent spin,
// rows it kept say so and still show their review.
func TestAdvisorMidRunShowsPlan(t *testing.T) {
	h := newTestHandler(t)
	cur := h.snapshotSettings()
	cur.AIAdvisor = settings.AIAdvisorConfig{Enabled: true, Provider: "anthropic", APIKey: "k", Endpoint: "http://127.0.0.1:9"}
	h.settingsPtr.Store(&cur)
	for _, ip := range []string{"203.0.113.10", "203.0.113.11"} {
		for i := 0; i < 35; i++ {
			if _, err := h.DB.Exec(`INSERT INTO unmask_event
				(site,host,scheme,port,ip_address,user_agent,ja4,ja4_verdict,ja4_verdict_id,phase,flags,reload_count,cookie_bv,cookie_br,payload_json,date_created)
				VALUES ('','','',0,?,'curl/8','t13d_x','',0,'serve',0,0,'','','{"orig_path":"/.env"}',datetime('now'))`, events.PackIP(ip)); err != nil {
				t.Fatal(err)
			}
		}
	}
	key := advisor.ResultKey(cur.AIAdvisor, 24*60, string(i18n.Resolve(httptest.NewRequest(http.MethodGet, "/", nil))))
	advisor.StoreLast(h.DB, key, advisor.Stored{At: time.Now(), Model: "m", Reviews: map[string]advisor.Review{
		"203.0.113.10": {Target: "203.0.113.10", Priority: "low", Reasoning: "kept review"},
	}})
	release := make(chan struct{})
	defer close(release)
	advisor.StartRun(h.DB, key, advisor.RunInfo{Sent: map[string]bool{"203.0.113.11": true}, Kept: map[string]bool{"203.0.113.10": true}}, func(ctx context.Context) advisor.Stored {
		<-release
		return advisor.Stored{At: time.Now(), Model: "m"}
	})
	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/advisor/?window=24", nil)
	rr := httptest.NewRecorder()
	h.AdminAdvisorIndex(rr, req)
	body := rr.Body.String()
	i := strings.Index(body, `data-ip="203.0.113.10"`)
	j := strings.Index(body, `data-ip="203.0.113.11"`)
	if i < 0 || j < 0 {
		t.Fatal("both rows must render")
	}
	segA, segB := body[i:], body[j:]
	if k := strings.Index(segA, "</tr>"); k > 0 {
		segA = segA[:k]
	}
	if k := strings.Index(segB, "</tr>"); k > 0 {
		segB = segB[:k]
	}
	if !strings.Contains(segA, `class="ai-box"`) || !strings.Contains(segA, `class="ai-kept"`) || !strings.Contains(segA, "kept review") || strings.Contains(segA, `class="ai-wait"`) {
		t.Error("the kept row must say kept and still show its review, not spin")
	}
	if !strings.Contains(segB, `class="ai-wait"`) || strings.Contains(segB, `class="ai-kept"`) {
		t.Error("the sent row must spin")
	}
	sreq := httptest.NewRequest(http.MethodGet, "/unmask/admin/advisor/ai-status?window=24", nil)
	srr := httptest.NewRecorder()
	h.AdminAdvisorAIStatus(srr, sreq)
	if st := srr.Body.String(); !strings.Contains(st, `"sent":["203.0.113.11"]`) || !strings.Contains(st, `"kept":["203.0.113.10"]`) {
		t.Errorf("status must carry the plan: %s", st)
	}
}

// The BAN dialog asks this before letting a fingerprint ban through.
func TestAdminJA4Collateral(t *testing.T) {
	h := newTestHandler(t)
	for _, ip := range []string{"203.0.113.1", "203.0.113.2"} {
		if _, err := h.DB.Exec(`INSERT INTO unmask_event
			(site,host,scheme,port,ip_address,user_agent,ja4,ja4_verdict,ja4_verdict_id,phase,flags,reload_count,cookie_bv,cookie_br,payload_json,date_created)
			VALUES ('','','',0,?,'Mozilla/5.0 (iPhone)','t13d_shared','',0,'bv_pow_only',0,0,'','','{}',datetime('now'))`, events.PackIP(ip)); err != nil {
			t.Fatal(err)
		}
	}
	get := func(q string) (int, string) {
		req := httptest.NewRequest(http.MethodGet, "/unmask/admin/api/ja4-collateral"+q, nil)
		rr := httptest.NewRecorder()
		h.AdminJA4Collateral(rr, req)
		return rr.Code, rr.Body.String()
	}
	if code, body := get("?ja4=t13d_shared"); code != http.StatusOK || !strings.Contains(body, `"pass_ips":2`) || !strings.Contains(body, `"level":"some"`) || !strings.Contains(body, "iPhone") {
		t.Fatalf("shared fingerprint: %d %s", code, body)
	}
	if code, body := get("?ja4=t13d_nobody"); code != http.StatusOK || !strings.Contains(body, `"level":"none"`) {
		t.Fatalf("unknown fingerprint: %d %s", code, body)
	}
	if code, _ := get(""); code != http.StatusBadRequest {
		t.Fatalf("missing ja4: %d", code)
	}
}

// The bar shows what the last 30 days cost -- requests and tokens across
// every window -- once there is something to add up.
func TestAdvisorMonthTotalsShown(t *testing.T) {
	h := newTestHandler(t)
	cur := h.snapshotSettings()
	cur.AIAdvisor = settings.AIAdvisorConfig{Enabled: true, Provider: "anthropic", APIKey: "k"}
	h.settingsPtr.Store(&cur)
	preq := httptest.NewRequest(http.MethodGet, "/unmask/admin/advisor/?window=24", nil)
	prr := httptest.NewRecorder()
	h.AdminAdvisorIndex(prr, preq)
	if strings.Contains(prr.Body.String(), `class="kv ai-delta ai-month"`) {
		t.Fatal("no runs yet: no monthly line")
	}
	lang := string(i18n.Resolve(preq))
	advisor.StoreLast(h.DB, advisor.ResultKey(cur.AIAdvisor, 6*60, lang), advisor.Stored{At: time.Now(), Model: "claude-opus-5", Reviewed: 2, InTokens: 12345, OutTokens: 678,
		Reviews: map[string]advisor.Review{"203.0.113.10": {Target: "203.0.113.10", Priority: "low", Reasoning: "r"}}})
	prr = httptest.NewRecorder()
	h.AdminAdvisorIndex(prr, httptest.NewRequest(http.MethodGet, "/unmask/admin/advisor/?window=24", nil))
	body := prr.Body.String()
	// The harness resolves the UI language to Japanese.
	if !strings.Contains(body, `class="kv ai-delta ai-month"`) || !strings.Contains(body, "直近 30 日: 1 回相談、tokens 入力 12,345 / 出力 678") {
		i := strings.Index(body, `id="ai-bar"`)
		t.Fatalf("monthly totals line missing (a run on another window still counts); bar: %s", body[i:min(len(body), i+1500)])
	}
}
