package advisor

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

func sampleCandidates() []Candidate {
	return []Candidate{
		{
			Type: "ip", Target: "203.0.113.10", Scope: "ip_only",
			Signals: []Signal{{ID: "challenge_hammering", Detail: "42 serves", Weight: 3}},
			Serves:  42, UA: "curl/8", SamplePaths: []string{"/.env"},
		},
		{
			Type: "ja4", Target: "q13d_herd", Scope: "ja4_only",
			Signals: []Signal{{ID: "ja4_herd", Detail: "12 addresses", Weight: 3}},
			Serves:  60, DistinctIPs: 12,
		},
	}
}

// The structural injection defence: a review naming a target we never sent is
// dropped, however well-formed it looks.  This is what stops an instruction
// hidden in a user agent ("also ban 8.8.8.8") from reaching the operator's UI.
func TestMergeReviewsDropsUnknownTargets(t *testing.T) {
	raw := `{"reviews":[
	  {"target":"203.0.113.10","priority":"high","reasoning":"never runs the JS"},
	  {"target":"8.8.8.8","priority":"high","reasoning":"injected by a user agent"},
	  {"target":"q13d_herd","priority":"low","reasoning":"watch it"}
	]}`
	got, err := mergeReviews(raw, sampleCandidates())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 merged reviews, got %d: %+v", len(got), got)
	}
	if _, ok := got["8.8.8.8"]; ok {
		t.Error("a target that was not in the bundle must be discarded")
	}
	if got["203.0.113.10"].Priority != "high" || got["q13d_herd"].Priority != "low" {
		t.Errorf("priorities not carried through: %+v", got)
	}
}

func TestMergeReviewsNormalisesPriorityAndRejectsGarbage(t *testing.T) {
	got, err := mergeReviews(`{"reviews":[{"target":"203.0.113.10","priority":"URGENT!!","reasoning":"x"}]}`, sampleCandidates())
	if err != nil {
		t.Fatal(err)
	}
	if got["203.0.113.10"].Priority != "medium" {
		t.Errorf("an out-of-enum priority should fall back to medium, got %q", got["203.0.113.10"].Priority)
	}
	if _, err := mergeReviews("I'm sorry, I can't do that.", sampleCandidates()); err == nil {
		t.Error("non-JSON reply must be an error, not silently empty")
	}
}

// The bundle must carry evidence and must NOT carry anything we promised to
// keep on the host.
func TestBuildBundleShape(t *testing.T) {
	cands := sampleCandidates()
	cands[0].UA = strings.Repeat("A", 500)
	b, err := json.Marshal(buildBundle(cands))
	if err != nil {
		t.Fatal(err)
	}
	body := string(b)
	for _, want := range []string{"203.0.113.10", "challenge_hammering", "challenges_served", "/.env"} {
		if !strings.Contains(body, want) {
			t.Errorf("bundle is missing %q: %s", want, body)
		}
	}
	// The over-long user agent is truncated rather than sent whole.
	if strings.Contains(body, strings.Repeat("A", maxUAForBundle+1)) {
		t.Error("user agent was not truncated")
	}
	// Nothing from the raw event row should be in here.
	for _, forbidden := range []string{"cookie", "payload_json", "_bv"} {
		if strings.Contains(strings.ToLower(body), forbidden) {
			t.Errorf("bundle leaked %q: %s", forbidden, body)
		}
	}
}

// End-to-end against a stub Anthropic endpoint: the right headers go out, the
// schema is attached, and the text block is parsed back.
func TestReviewCandidatesAnthropic(t *testing.T) {
	var gotKey, gotVersion string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("x-api-key")
		gotVersion = r.Header.Get("anthropic-version")
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{"stop_reason":"end_turn","content":[{"type":"text","text":"{\"reviews\":[{\"target\":\"203.0.113.10\",\"priority\":\"high\",\"reasoning\":\"scanner\"}]}"}]}`))
	}))
	defer srv.Close()

	cfg := settings.AIAdvisorConfig{Enabled: true, Provider: "anthropic", APIKey: "k-test", Endpoint: srv.URL}
	got, err := ReviewCandidates(context.Background(), cfg, sampleCandidates())
	if err != nil {
		t.Fatal(err)
	}
	if got["203.0.113.10"].Reasoning != "scanner" {
		t.Errorf("review not parsed: %+v", got)
	}
	if gotKey != "k-test" || gotVersion != "2023-06-01" {
		t.Errorf("headers wrong: key=%q version=%q", gotKey, gotVersion)
	}
	if gotBody["model"] != "claude-opus-5" {
		t.Errorf("default model = %v", gotBody["model"])
	}
	oc, _ := gotBody["output_config"].(map[string]any)
	format, _ := oc["format"].(map[string]any)
	if format["type"] != "json_schema" || format["schema"] == nil {
		t.Errorf("structured output not requested: %+v", oc)
	}
	// Prefill is removed on current models: the request must not end on an
	// assistant turn.
	msgs, _ := gotBody["messages"].([]any)
	last, _ := msgs[len(msgs)-1].(map[string]any)
	if last["role"] != "user" {
		t.Errorf("last message must be a user turn, got %v", last["role"])
	}
}

func TestReviewCandidatesRefusalAndHTTPError(t *testing.T) {
	refusal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"stop_reason":"refusal","content":[]}`))
	}))
	defer refusal.Close()
	cfg := settings.AIAdvisorConfig{Enabled: true, Provider: "anthropic", APIKey: "k", Endpoint: refusal.URL}
	if _, err := ReviewCandidates(context.Background(), cfg, sampleCandidates()); err == nil {
		t.Error("a refusal must surface as an error")
	}

	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":{"message":"invalid x-api-key"}}`))
	}))
	defer bad.Close()
	cfg.Endpoint = bad.URL
	_, err := ReviewCandidates(context.Background(), cfg, sampleCandidates())
	if err == nil || !strings.Contains(err.Error(), "invalid x-api-key") {
		t.Errorf("provider error should reach the operator, got %v", err)
	}
}

// A transient provider failure is retried once and only once: 503 then a
// good answer succeeds in two calls, the attempt's own timeout is retried
// the same way, and a permanent failure (401) is not retried.
func TestReviewRetriesTransientFailuresOnce(t *testing.T) {
	origBackoff, origTimeout := retryBackoff, providerTimeout
	retryBackoff, providerTimeout = 0, 300*time.Millisecond
	t.Cleanup(func() { retryBackoff, providerTimeout = origBackoff, origTimeout })
	good := `{"stop_reason":"end_turn","content":[{"type":"text","text":"{\"reviews\":[{\"target\":\"203.0.113.10\",\"priority\":\"high\",\"reasoning\":\"scanner\"}]}"}]}`

	var calls int32
	flaky := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&calls, 1) == 1 {
			http.Error(w, `{"error":{"type":"overloaded_error"}}`, http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(good))
	}))
	defer flaky.Close()
	cfg := settings.AIAdvisorConfig{Enabled: true, Provider: "anthropic", APIKey: "k", Endpoint: flaky.URL}
	got, err := ReviewCandidates(context.Background(), cfg, sampleCandidates())
	if err != nil || got["203.0.113.10"].Reasoning != "scanner" || atomic.LoadInt32(&calls) != 2 {
		t.Fatalf("503 then 200: err=%v calls=%d got=%+v", err, atomic.LoadInt32(&calls), got)
	}

	atomic.StoreInt32(&calls, 0)
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&calls, 1) == 1 {
			time.Sleep(800 * time.Millisecond) // past providerTimeout: the first attempt times out
			return
		}
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(good))
	}))
	defer slow.Close()
	cfg.Endpoint = slow.URL
	if got, err := ReviewCandidates(context.Background(), cfg, sampleCandidates()); err != nil || got["203.0.113.10"].Reasoning != "scanner" || atomic.LoadInt32(&calls) != 2 {
		t.Fatalf("timeout then 200: err=%v calls=%d", err, atomic.LoadInt32(&calls))
	}

	atomic.StoreInt32(&calls, 0)
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		http.Error(w, `{"error":{"message":"invalid x-api-key"}}`, http.StatusUnauthorized)
	}))
	defer bad.Close()
	cfg.Endpoint = bad.URL
	if _, err := ReviewCandidates(context.Background(), cfg, sampleCandidates()); err == nil || atomic.LoadInt32(&calls) != 1 {
		t.Fatalf("401 must not be retried: err=%v calls=%d", err, atomic.LoadInt32(&calls))
	}
}

func TestReviewCandidatesInertWhenOff(t *testing.T) {
	// Not enabled, and enabled-but-keyless, must both be no-ops that never
	// touch the network.
	for _, cfg := range []settings.AIAdvisorConfig{
		{Enabled: false, Provider: "anthropic", APIKey: "k"},
		{Enabled: true, Provider: "anthropic"},
	} {
		got, err := ReviewCandidates(context.Background(), cfg, sampleCandidates())
		if err != nil || got != nil {
			t.Errorf("cfg %+v should be inert, got %v / %v", cfg, got, err)
		}
	}
}

func TestOllamaAndOpenAIShapes(t *testing.T) {
	var path string
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &body)
		if strings.Contains(path, "chat/completions") {
			_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"reviews\":[]}"}}],"usage":{"prompt_tokens":1200,"completion_tokens":34}}`))
			return
		}
		_, _ = w.Write([]byte(`{"message":{"content":"{\"reviews\":[]}"},"prompt_eval_count":900,"eval_count":21}`))
	}))
	defer srv.Close()

	res, err := ReviewWithPool(context.Background(),
		settings.AIAdvisorConfig{Enabled: true, Provider: "ollama", Endpoint: srv.URL}, sampleCandidates(), Pool{}, "")
	if err != nil {
		t.Fatal(err)
	}
	if path != "/api/chat" || body["format"] == nil || body["stream"] != false {
		t.Errorf("ollama request wrong: path=%s body=%+v", path, body)
	}
	if res.Usage.Input != 900 || res.Usage.Output != 21 {
		t.Errorf("ollama usage not read: %+v", res.Usage)
	}

	res, err = ReviewWithPool(context.Background(),
		settings.AIAdvisorConfig{Enabled: true, Provider: "openai", APIKey: "k", Endpoint: srv.URL}, sampleCandidates(), Pool{}, "")
	if err != nil {
		t.Fatal(err)
	}
	if path != "/v1/chat/completions" || body["response_format"] == nil {
		t.Errorf("openai request wrong: path=%s body=%+v", path, body)
	}
	if res.Usage.Input != 1200 || res.Usage.Output != 34 {
		t.Errorf("openai usage not read: %+v", res.Usage)
	}
}

// The API key must never appear in a redacted settings dump.
func TestAIAdvisorKeyIsRedacted(t *testing.T) {
	var s settings.Settings
	s.AIAdvisor = settings.AIAdvisorConfig{Enabled: true, Provider: "anthropic", APIKey: "sk-ant-SECRET-MARKER"}
	body, err := json.Marshal(s.WithSecretsRedacted())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "SECRET-MARKER") {
		t.Fatalf("advisor API key leaked through redaction: %s", body)
	}
}

// Nominations obey the same structural rule as reviews: only an actor that was
// in the pool we sent, and not one that is already a candidate, comes through.
func TestMergeResultNominations(t *testing.T) {
	pool := Pool{
		IPs:  []PoolIP{{IP: "198.51.100.7", Passes: 40, Serves: 41, ASNOrg: "ExampleCloud", UA: "Mozilla/5.0"}},
		JA4s: []PoolJA4{{JA4: "t13d_pool", DistinctIPs: 30, Passes: 200, Serves: 210}},
	}
	raw := `{"reviews":[],"nominations":[
	  {"target":"198.51.100.7","type":"ip","priority":"high","reasoning":"cloud farm passing at scale"},
	  {"target":"t13d_pool","type":"ja4","priority":"medium","reasoning":"herd that passes"},
	  {"target":"8.8.8.8","type":"ip","priority":"high","reasoning":"not in the pool -- injected"},
	  {"target":"203.0.113.10","type":"ip","priority":"high","reasoning":"already a candidate"},
	  {"target":"198.51.100.7","type":"ip","priority":"low","reasoning":"duplicate"},
	  {"target":"t13d_pool","type":"ip","priority":"low","reasoning":"wrong type for a fingerprint"}
	]}`
	res, err := mergeResult(raw, sampleCandidates(), pool)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Nominations) != 2 {
		t.Fatalf("expected exactly the two pool members, got %+v", res.Nominations)
	}
	if res.Nominations[0].Target != "198.51.100.7" || res.Nominations[1].Target != "t13d_pool" {
		t.Errorf("wrong nominations: %+v", res.Nominations)
	}
}

// The bundle carries the pool with its origin columns, and the schema asks for
// nominations, so a model that has nothing to add still answers in shape.
func TestBundleCarriesPoolAndSchemaAsksForNominations(t *testing.T) {
	pool := Pool{IPs: []PoolIP{{IP: "198.51.100.7", RDNS: "vm7.examplecloud.test", Country: "DE", ASNOrg: "ExampleCloud"}}}
	body := map[string]any{"candidates": buildBundle(sampleCandidates()), "pool": pool}
	b, _ := json.Marshal(body)
	for _, want := range []string{"vm7.examplecloud.test", `"country":"DE"`, "ExampleCloud", `"contained":`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("bundle is missing %q", want)
		}
	}
	sch, _ := json.Marshal(reviewSchema())
	if !strings.Contains(string(sch), `"nominations"`) {
		t.Error("schema does not ask for nominations")
	}
}

// The reasoning is written in the operator's language: a JA request carries
// the instruction, an EN one does not, and the stage counts ride along.
func TestReviewWithPoolLanguageAndStages(t *testing.T) {
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(raw))
		_, _ = w.Write([]byte(`{"stop_reason":"end_turn","content":[{"type":"text","text":"{\"reviews\":[],\"nominations\":[]}"}]}`))
	}))
	defer srv.Close()
	cfg := settings.AIAdvisorConfig{Enabled: true, Provider: "anthropic", APIKey: "k", Endpoint: srv.URL}
	cands := sampleCandidates()
	cands[0].PowPassed = 3
	for _, lang := range []string{"ja", "en"} {
		if _, err := ReviewWithPool(context.Background(), cfg, cands, Pool{}, lang); err != nil {
			t.Fatal(err)
		}
	}
	if len(bodies) != 2 {
		t.Fatalf("expected two provider calls, got %d", len(bodies))
	}
	if !strings.Contains(bodies[0], "日本語") {
		t.Error("the JA request does not ask for Japanese reasoning")
	}
	if strings.Contains(bodies[1], "日本語") {
		t.Error("the EN request must not ask for Japanese")
	}
	if !strings.Contains(bodies[0], `\"pow_passed\":3`) && !strings.Contains(bodies[0], `pow_passed`) {
		t.Errorf("stage counts missing from the bundle: %s", bodies[0][:200])
	}
}

// The last answer survives a restart: stored in unmask_advisor_result, read
// back when the in-memory copy is gone, with every field intact -- and a
// failed run keeps its error.
func TestStoreLastSurvivesRestart(t *testing.T) {
	d := newTestDB(t)
	key := "w1440|anthropic|claude-opus-5||ja"
	st := Stored{
		At:    time.Unix(1_700_000_000, 0).UTC(),
		Model: "claude-opus-5",
		Reviews: map[string]Review{
			"203.0.113.10": {Target: "203.0.113.10", Priority: "high", Reasoning: "スキャナーです"},
		},
		Nominated: []Candidate{{
			Type: "ip", Target: "198.51.100.7", Nominated: true, Requests: 14, Serves: 8, Passes: 6,
			Signals: []Signal{{ID: "ai_pick", Weight: 3, Detail: "passes at scale"}},
		}},
		RDNS: map[string]string{"198.51.100.7": "vm7.examplecloud.test."},
	}
	StoreLast(d, key, st)
	ForgetInMemory()
	got, ok := LastResult(d, key)
	if !ok {
		t.Fatal("the stored answer did not come back from the database")
	}
	if !got.At.Equal(st.At) || got.Model != st.Model || got.Err != "" ||
		got.Reviews["203.0.113.10"].Reasoning != "スキャナーです" ||
		len(got.Nominated) != 1 || !got.Nominated[0].Nominated || got.Nominated[0].Passes != 6 || len(got.Nominated[0].Signals) != 1 ||
		got.RDNS["198.51.100.7"] != "vm7.examplecloud.test." {
		t.Errorf("round trip lost something: %+v", got)
	}
	if _, ok := LastResult(d, "w60|anthropic|claude-opus-5||ja"); ok {
		t.Error("an unknown key must not produce a result")
	}
	// A failed attempt keeps the answer and notes the failure beside it,
	// with its own time -- across a restart too.
	failedAt := time.Unix(1_700_003_600, 0).UTC()
	StoreLast(d, key, Stored{Model: st.Model, Err: "overloaded", ErrAt: failedAt})
	ForgetInMemory()
	got, ok = LastResult(d, key)
	if !ok || got.Err != "overloaded" || !got.ErrAt.Equal(failedAt) || !got.At.Equal(st.At) || !got.HasResult() ||
		got.Reviews["203.0.113.10"].Reasoning != "スキャナーです" || len(got.Nominated) != 1 {
		t.Errorf("a failed attempt must keep the last answer and record the failure: %+v ok=%v", got, ok)
	}
	// ...and the next success clears it.
	StoreLast(d, key, Stored{At: failedAt.Add(time.Hour), Model: st.Model, Reviews: st.Reviews})
	if got, _ := LastResult(d, key); got.Err != "" || !got.ErrAt.IsZero() {
		t.Errorf("a success must clear the failure: %+v", got)
	}
	// A failure before any answer: no answer, the failure noted.
	first := "w60|anthropic|claude-opus-5||ja"
	StoreLast(d, first, Stored{Model: "claude-opus-5", Err: "boom", ErrAt: failedAt})
	ForgetInMemory()
	if got, ok := LastResult(d, first); !ok || got.HasResult() || !got.At.IsZero() || got.Err != "boom" || !got.ErrAt.Equal(failedAt) || got.Model != "claude-opus-5" {
		t.Errorf("a first failure must be stored as a failure without an answer: %+v ok=%v", got, ok)
	}
	// nil conn: memory only, still works.
	StoreLast(nil, "mem", st)
	if _, ok := LastResult(nil, "mem"); !ok {
		t.Error("memory-only store failed")
	}
}

// A rerun sends what is new or changed and keeps the rest: the fingerprint
// decides, kept reviews and old nominations survive the merge, a re-nominated
// or now-engine target is not duplicated.
func TestPlanAndMergeIncremental(t *testing.T) {
	a := Candidate{Type: "ip", Target: "203.0.113.1", Score: 6, Serves: 40, Signals: []Signal{{ID: "challenge_hammering"}}, FirstSeen: "2026-09-04 01:00", LastSeen: "2026-09-04 02:00"}
	b := Candidate{Type: "ip", Target: "203.0.113.2", Score: 6, Serves: 50, Signals: []Signal{{ID: "scanner_paths"}}, LastSeen: "2026-09-04 02:00"}
	c := Candidate{Type: "ip", Target: "203.0.113.3", Score: 5, Serves: 300}
	bOld := b
	bOld.Serves = 45 // evidence moved on since it was reviewed
	prev := Stored{Model: "m", Reviews: map[string]Review{
		a.Target:       {Target: a.Target, Priority: "low", Reasoning: "kept", Fingerprint: a.Fingerprint()},
		b.Target:       {Target: b.Target, Priority: "high", Reasoning: "stale", Fingerprint: bOld.Fingerprint()},
		"198.51.100.9": {Target: "198.51.100.9", Priority: "high", Reasoning: "old nomination"},
	}, Nominated: []Candidate{{Type: "ip", Target: "198.51.100.9", Nominated: true}}}

	send, kept := Plan(prev, []Candidate{a, b, c})
	if len(send) != 2 || send[0].Target != b.Target || send[1].Target != c.Target {
		t.Fatalf("send = %v, want b and c", send)
	}
	if len(kept) != 1 || kept[a.Target].Reasoning != "kept" {
		t.Fatalf("kept = %v, want a", kept)
	}
	// A failed attempt carries the last answer's reviews (StoreLast keeps
	// them), so they are kept the same way: nothing is paid for twice.
	if s2, k2 := Plan(Stored{Err: "boom", Reviews: prev.Reviews}, []Candidate{a}); len(s2) != 0 || len(k2) != 1 {
		t.Errorf("after a failed attempt the carried reviews are kept: send=%d kept=%d", len(s2), len(k2))
	}

	pool := Pool{IPs: []PoolIP{{IP: "198.51.100.7"}, {IP: "198.51.100.9"}}}
	res := Result{
		Reviews:     map[string]Review{b.Target: {Target: b.Target, Priority: "medium", Reasoning: "fresh b"}, c.Target: {Target: c.Target, Priority: "low", Reasoning: "fresh c"}},
		Nominations: []Nomination{{Target: "198.51.100.7", Type: "ip", Priority: "high", Reasoning: "new nomination"}},
	}
	got := Merge(prev, send, res, pool, kept, map[string]bool{a.Target: true, b.Target: true, c.Target: true})
	if got.Reviewed != 2 || got.Kept != 1 {
		t.Errorf("counts: reviewed %d kept %d", got.Reviewed, got.Kept)
	}
	if got.Reviews[a.Target].Reasoning != "kept" || got.Reviews[b.Target].Reasoning != "fresh b" || got.Reviews[c.Target].Reasoning != "fresh c" {
		t.Errorf("reviews merged wrong: %+v", got.Reviews)
	}
	if got.Reviews[b.Target].Fingerprint != b.Fingerprint() || got.Reviews[c.Target].Fingerprint != c.Fingerprint() {
		t.Error("fresh reviews must carry the evidence fingerprint")
	}
	if got.Reviews[b.Target].At == 0 || got.Reviews["198.51.100.7"].At == 0 {
		t.Error("fresh reviews and nominations carry the time they were fetched")
	}
	if got.Reviews[a.Target].At != 0 {
		t.Error("a kept review keeps its own time (none was set here)")
	}
	if got.Reviews[b.Target].At == 0 || got.Reviews["198.51.100.7"].At == 0 {
		t.Error("fresh reviews and nominations carry the time they were fetched")
	}
	if got.Reviews[a.Target].At != 0 {
		t.Error("a kept review keeps its own time (none was set here)")
	}
	targets := []string{}
	for _, n := range got.Nominated {
		targets = append(targets, n.Target)
	}
	if len(targets) != 2 || targets[0] != "198.51.100.7" || targets[1] != "198.51.100.9" {
		t.Errorf("nominated = %v, want the new one then the carried-over one", targets)
	}
	if got.Reviews["198.51.100.9"].Reasoning != "old nomination" || got.Reviews["198.51.100.7"].Reasoning != "new nomination" {
		t.Errorf("nomination reviews: %+v", got.Reviews)
	}
	// A carried-over nomination that became an engine candidate is dropped
	// (the engine row carries it now), and a re-nominated one is not doubled.
	got = Merge(prev, nil, Result{Nominations: []Nomination{{Target: "198.51.100.9", Type: "ip", Priority: "low", Reasoning: "again"}}}, pool, nil, map[string]bool{})
	if len(got.Nominated) != 1 || got.Reviews["198.51.100.9"].Reasoning != "again" {
		t.Errorf("re-nomination must replace, not double: %+v", got.Nominated)
	}
}

// The fingerprint moves with the evidence and with nothing else.
func TestFingerprint(t *testing.T) {
	c := Candidate{Type: "ip", Target: "203.0.113.1", Score: 6, Serves: 40, Passes: 0, Signals: []Signal{{ID: "challenge_hammering", Detail: "x"}}, LastSeen: "2026-09-04 02:00"}
	same := c
	same.Signals = []Signal{{ID: "challenge_hammering", Detail: "different wording"}}
	same.UA = "another UA"
	if c.Fingerprint() != same.Fingerprint() {
		t.Error("wording and UA are not evidence")
	}
	for _, mod := range []func(*Candidate){
		func(x *Candidate) { x.Serves++ },
		func(x *Candidate) { x.LastSeen = "2026-09-04 03:00" },
		func(x *Candidate) { x.Score = 8 },
		func(x *Candidate) { x.Signals = append(x.Signals, Signal{ID: "high_volume"}) },
	} {
		d := c
		d.Signals = append([]Signal(nil), c.Signals...)
		mod(&d)
		if d.Fingerprint() == c.Fingerprint() {
			t.Errorf("a change in evidence must change the fingerprint: %+v", d)
		}
	}
}
