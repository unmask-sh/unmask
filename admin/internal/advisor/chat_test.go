package advisor

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/aitools"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// stubTools records what the model asked for and answers with a fixed row.
type stubTools struct {
	mu    sync.Mutex
	calls []string
}

func (s *stubTools) List() []aitools.Tool {
	return []aitools.Tool{{Name: "bans", Description: "the ban list", Schema: map[string]any{"type": "object", "properties": map[string]any{"limit": map[string]any{"type": "integer"}}}}}
}

func (s *stubTools) Run(ctx context.Context, name string, args map[string]any) (any, error) {
	s.mu.Lock()
	s.calls = append(s.calls, name)
	s.mu.Unlock()
	if name != "bans" {
		return nil, errors.New("unknown tool " + name)
	}
	return map[string]any{"count": 1, "bans": []map[string]any{{"ip": "203.0.113.9", "reason": "WordPress: https://shop.example/wp-login.php"}}}, nil
}

func readBody(t *testing.T, r *http.Request) map[string]any {
	t.Helper()
	b, _ := io.ReadAll(r.Body)
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("request body: %v\n%s", err, b)
	}
	return m
}

// Each provider: the first request asks for the bans tool, the second gets
// its result back in the provider's own shape and answers.
func TestChatToolLoopAnthropic(t *testing.T) {
	var reqs []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/messages" || r.Header.Get("x-api-key") != "k" {
			http.Error(w, "wrong path or key", 400)
			return
		}
		m := readBody(t, r)
		reqs = append(reqs, m)
		if len(reqs) == 1 {
			io.WriteString(w, `{"stop_reason":"tool_use","usage":{"input_tokens":10,"output_tokens":5,"cache_creation_input_tokens":100},"content":[{"type":"text","text":"Let me look."},{"type":"tool_use","id":"tu_1","name":"bans","input":{"limit":3}}]}`)
			return
		}
		io.WriteString(w, `{"stop_reason":"end_turn","usage":{"input_tokens":20,"output_tokens":7,"cache_read_input_tokens":100},"content":[{"type":"text","text":"One ban: 203.0.113.9."}]}`)
	}))
	defer srv.Close()
	cfg := settings.AIAdvisorConfig{Enabled: true, Provider: "anthropic", Endpoint: srv.URL, APIKey: "k", Model: "m"}
	st := &stubTools{}
	res, err := Chat(context.Background(), cfg, st, []ChatTurn{{Question: "hi", Answer: "hello"}}, "who is banned?", "ja")
	if err != nil {
		t.Fatal(err)
	}
	// The input is the whole prompt: the cache's part counted in, and told
	// apart (100 written by the first round, read back by the second).
	if res.Answer != "One ban: 203.0.113.9." || res.Rounds != 2 || res.Usage.Input != 230 || res.Usage.Output != 12 || res.Usage.CacheWrite != 100 || res.Usage.CacheRead != 100 {
		t.Errorf("result %+v", res)
	}
	if len(res.Tools) != 1 || res.Tools[0].Name != "bans" || res.Tools[0].Args["limit"] != float64(3) || res.Tools[0].Err != "" {
		t.Errorf("tools %+v", res.Tools)
	}
	if st.calls[0] != "bans" {
		t.Errorf("calls %v", st.calls)
	}
	// The first request: system prompt, tools, the history and the question
	// with the language asked for.  The prompt cache's marks sit on the
	// system prompt, the last tool and the last message, and nowhere else.
	first := reqs[0]
	marked := func(v any) bool {
		m, _ := v.(map[string]any)
		return m != nil && m["cache_control"] != nil
	}
	sys, _ := first["system"].([]any)
	tools, _ := first["tools"].([]any)
	if len(sys) != 1 || sys[0].(map[string]any)["text"] != chatSystemPrompt || !marked(sys[0]) || len(tools) != 1 || !marked(tools[0]) {
		t.Errorf("first request's system prompt or tools, or their cache marks: %v %v", first["system"], first["tools"])
	}
	msgs := first["messages"].([]any)
	if len(msgs) != 3 {
		t.Fatalf("messages %v", msgs)
	}
	q := msgs[2].(map[string]any)["content"].([]any)
	if _, plain := msgs[0].(map[string]any)["content"].(string); !plain || len(q) != 1 || !strings.Contains(q[0].(map[string]any)["text"].(string), "日本語") || !marked(q[0]) {
		t.Errorf("the question is not the one marked message: %v", msgs)
	}
	// The second: the assistant's blocks echoed, then the tool result by id,
	// which carries the mark now; the question no longer does.
	msgs = reqs[1]["messages"].([]any)
	if len(msgs) != 5 {
		t.Fatalf("second request has %d messages, want 5", len(msgs))
	}
	last := msgs[4].(map[string]any)
	content := last["content"].([]any)[0].(map[string]any)
	if last["role"] != "user" || content["type"] != "tool_result" || content["tool_use_id"] != "tu_1" || !strings.Contains(content["content"].(string), "203.0.113.9") || !marked(content) {
		t.Errorf("tool result message %v", last)
	}
	if _, plain := msgs[2].(map[string]any)["content"].(string); !plain {
		t.Errorf("the question kept its cache mark in the second request: %v", msgs[2])
	}
}

func TestChatToolLoopOpenAI(t *testing.T) {
	var reqs []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" || r.Header.Get("authorization") != "Bearer k" {
			http.Error(w, "wrong path or key", 400)
			return
		}
		m := readBody(t, r)
		reqs = append(reqs, m)
		if len(reqs) == 1 {
			io.WriteString(w, `{"choices":[{"finish_reason":"tool_calls","message":{"role":"assistant","content":null,"tool_calls":[{"id":"c1","type":"function","function":{"name":"bans","arguments":"{\"limit\":2}"}}]}}],"usage":{"prompt_tokens":3,"completion_tokens":4}}`)
			return
		}
		io.WriteString(w, `{"choices":[{"finish_reason":"stop","message":{"role":"assistant","content":"Done."}}],"usage":{"prompt_tokens":5,"completion_tokens":6}}`)
	}))
	defer srv.Close()
	cfg := settings.AIAdvisorConfig{Enabled: true, Provider: "openai", Endpoint: srv.URL, APIKey: "k", Model: "m"}
	res, err := Chat(context.Background(), cfg, &stubTools{}, nil, "q", "en")
	if err != nil || res.Answer != "Done." || res.Usage.Input != 8 || len(res.Tools) != 1 || res.Tools[0].Args["limit"] != float64(2) {
		t.Fatalf("err=%v res=%+v", err, res)
	}
	msgs := reqs[1]["messages"].([]any)
	// system, question, the assistant's message with its tool_calls, the tool message
	if len(msgs) != 4 {
		t.Fatalf("%d messages", len(msgs))
	}
	tool := msgs[3].(map[string]any)
	if tool["role"] != "tool" || tool["tool_call_id"] != "c1" || !strings.Contains(tool["content"].(string), "203.0.113.9") {
		t.Errorf("tool message %v", tool)
	}
	if _, ok := msgs[2].(map[string]any)["tool_calls"]; !ok {
		t.Error("the assistant message was not echoed with its tool_calls")
	}
	if tools, ok := reqs[0]["tools"].([]any); !ok || len(tools) != 1 || tools[0].(map[string]any)["type"] != "function" {
		t.Error("tools not in the function shape")
	}
}

// OpenAI's own endpoint is spoken to on the Responses API: the system prompt
// as instructions, flat function tools, nothing stored, the effort under
// reasoning; the second request replays every output item of the first --
// the encrypted reasoning and the function_call -- and then the tool's
// result under its call_id.
func TestChatToolLoopOpenAIResponses(t *testing.T) {
	old := openaiUsesResponses
	openaiUsesResponses = func(string) bool { return true }
	t.Cleanup(func() { openaiUsesResponses = old })
	var reqs []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/responses" || r.Header.Get("authorization") != "Bearer k" {
			http.Error(w, "wrong path or key", 400)
			return
		}
		m := readBody(t, r)
		reqs = append(reqs, m)
		if len(reqs) == 1 {
			io.WriteString(w, `{"status":"completed","output":[
			  {"type":"reasoning","id":"rs_1","summary":[],"encrypted_content":"gAAAA"},
			  {"type":"function_call","id":"fc_1","call_id":"call_1","name":"bans","arguments":"{\"limit\":2}","status":"completed"}],
			  "usage":{"input_tokens":3,"output_tokens":4}}`)
			return
		}
		io.WriteString(w, `{"status":"completed","output":[
		  {"type":"message","id":"msg_1","role":"assistant","status":"completed","content":[{"type":"output_text","text":"Done.","annotations":[]}]}],
		  "usage":{"input_tokens":5,"output_tokens":6}}`)
	}))
	defer srv.Close()
	cfg := settings.AIAdvisorConfig{Enabled: true, Provider: "openai", Endpoint: srv.URL, APIKey: "k", Model: "gpt-6.1-sol", Effort: "low"}
	res, err := Chat(context.Background(), cfg, &stubTools{}, []ChatTurn{{Question: "earlier?", Answer: "Earlier."}}, "q", "en")
	if err != nil || res.Answer != "Done." || res.Usage.Input != 8 || res.Usage.Output != 10 || len(res.Tools) != 1 || res.Tools[0].Args["limit"] != float64(2) {
		t.Fatalf("err=%v res=%+v", err, res)
	}
	first := reqs[0]
	if first["instructions"] != chatSystemPrompt || first["store"] != false {
		t.Errorf("instructions/store: %v / %v", first["instructions"] != nil, first["store"])
	}
	if r, ok := first["reasoning"].(map[string]any); !ok || r["effort"] != "low" {
		t.Errorf("reasoning = %v, want effort low", first["reasoning"])
	}
	if _, has := first["reasoning_effort"]; has {
		t.Error("reasoning_effort is chat/completions' field")
	}
	if tools, ok := first["tools"].([]any); !ok || len(tools) != 1 || tools[0].(map[string]any)["name"] != "bans" || tools[0].(map[string]any)["function"] != nil {
		t.Errorf("tools not in the Responses (flat) shape: %v", first["tools"])
	}
	// the earlier turn (two messages) and the question
	if in := first["input"].([]any); len(in) != 3 || in[2].(map[string]any)["role"] != "user" {
		t.Errorf("first input %v", first["input"])
	}
	in := reqs[1]["input"].([]any)
	// earlier turn ×2, question, reasoning, function_call, function_call_output
	if len(in) != 6 {
		t.Fatalf("%d input items on the second request", len(in))
	}
	if r := in[3].(map[string]any); r["type"] != "reasoning" || r["encrypted_content"] != "gAAAA" {
		t.Errorf("the reasoning item was not replayed as it came: %v", r)
	}
	if c := in[4].(map[string]any); c["type"] != "function_call" || c["call_id"] != "call_1" {
		t.Errorf("the function_call item was not replayed: %v", c)
	}
	if o := in[5].(map[string]any); o["type"] != "function_call_output" || o["call_id"] != "call_1" || !strings.Contains(o["output"].(string), "203.0.113.9") {
		t.Errorf("tool result %v", o)
	}
}

// Which API an OpenAI-provider endpoint is spoken to on: OpenAI's own host
// the Responses API, any other server chat/completions.
func TestOpenAIEndpointPicksTheAPI(t *testing.T) {
	for ep, want := range map[string]bool{
		"https://api.openai.com":          true,
		"https://API.OpenAI.com/":         true,
		"http://127.0.0.1:11434/v1":       false,
		"https://llm.example/openai":      false,
		"https://api.openai.com.example":  false,
		"https://openai.azure.example/v1": false,
	} {
		if got := openaiUsesResponses(ep); got != want {
			t.Errorf("%s: responses=%v, want %v", ep, got, want)
		}
	}
}

// A Responses answer that stopped short, or a refusal, is an error the page
// can show, with the tokens it cost counted.
func TestChatOpenAIResponsesIncompleteAndRefusal(t *testing.T) {
	old := openaiUsesResponses
	openaiUsesResponses = func(string) bool { return true }
	t.Cleanup(func() { openaiUsesResponses = old })
	for _, tc := range []struct{ body, wantErr string }{
		{`{"status":"incomplete","incomplete_details":{"reason":"max_output_tokens"},"output":[],"usage":{"input_tokens":7,"output_tokens":9}}`, "max_output_tokens"},
		{`{"status":"completed","output":[{"type":"message","role":"assistant","content":[{"type":"refusal","refusal":"No."}]}],"usage":{"input_tokens":7,"output_tokens":9}}`, "declined"},
	} {
		body := tc.body
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, body) }))
		cfg := settings.AIAdvisorConfig{Enabled: true, Provider: "openai", Endpoint: srv.URL, APIKey: "k", Model: "m"}
		res, err := Chat(context.Background(), cfg, &stubTools{}, nil, "q", "en")
		srv.Close()
		if err == nil || !strings.Contains(err.Error(), tc.wantErr) || res.Usage.Input != 7 || res.Usage.Output != 9 {
			t.Errorf("%s: err=%v usage=%+v", tc.wantErr, err, res.Usage)
		}
	}
}

func TestChatToolLoopOllama(t *testing.T) {
	var reqs []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m := readBody(t, r)
		reqs = append(reqs, m)
		if r.URL.Path != "/api/chat" || m["stream"] != false {
			http.Error(w, "wrong path or stream", 400)
			return
		}
		if len(reqs) == 1 {
			io.WriteString(w, `{"message":{"role":"assistant","content":"","tool_calls":[{"function":{"name":"bans","arguments":{"limit":1}}}]},"prompt_eval_count":2,"eval_count":1}`)
			return
		}
		io.WriteString(w, `{"message":{"role":"assistant","content":"Local answer."},"prompt_eval_count":4,"eval_count":3}`)
	}))
	defer srv.Close()
	cfg := settings.AIAdvisorConfig{Enabled: true, Provider: "ollama", Endpoint: srv.URL, Model: "llama"}
	res, err := Chat(context.Background(), cfg, &stubTools{}, nil, "q", "en")
	if err != nil || res.Answer != "Local answer." || res.Usage.Input != 6 || res.Usage.Output != 4 {
		t.Fatalf("err=%v res=%+v", err, res)
	}
	msgs := reqs[1]["messages"].([]any)
	tool := msgs[len(msgs)-1].(map[string]any)
	if tool["role"] != "tool" || tool["tool_name"] != "bans" {
		t.Errorf("tool message %v", tool)
	}
}

// An unknown tool, or a tool that fails, goes back to the model as the
// result rather than ending the turn; the trace keeps the error.
func TestChatToolErrorGoesBackToTheModel(t *testing.T) {
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n++
		m := readBody(t, r)
		if n == 1 {
			io.WriteString(w, `{"choices":[{"message":{"role":"assistant","content":"","tool_calls":[{"id":"c1","type":"function","function":{"name":"nope","arguments":"{}"}}]}}]}`)
			return
		}
		msgs := m["messages"].([]any)
		tool := msgs[len(msgs)-1].(map[string]any)
		if !strings.Contains(tool["content"].(string), "unknown tool") {
			t.Errorf("the model did not get the error: %v", tool)
		}
		io.WriteString(w, `{"choices":[{"message":{"role":"assistant","content":"No such tool, sorry."}}]}`)
	}))
	defer srv.Close()
	cfg := settings.AIAdvisorConfig{Enabled: true, Provider: "openai", Endpoint: srv.URL, Model: "m"}
	res, err := Chat(context.Background(), cfg, &stubTools{}, nil, "q", "en")
	if err != nil || res.Answer != "No such tool, sorry." || len(res.Tools) != 1 || res.Tools[0].Err == "" {
		t.Fatalf("err=%v res=%+v", err, res)
	}
}

// A model that never stops asking for data ends with ErrChatRounds.
func TestChatRoundCap(t *testing.T) {
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n++
		io.WriteString(w, `{"choices":[{"message":{"role":"assistant","content":"","tool_calls":[{"id":"c","type":"function","function":{"name":"bans","arguments":"{}"}}]}}]}`)
	}))
	defer srv.Close()
	cfg := settings.AIAdvisorConfig{Enabled: true, Provider: "openai", Endpoint: srv.URL, Model: "m"}
	res, err := Chat(context.Background(), cfg, &stubTools{}, nil, "q", "en")
	if !errors.Is(err, ErrChatRounds) || n != chatMaxRounds || res.Rounds != chatMaxRounds {
		t.Fatalf("err=%v n=%d rounds=%d", err, n, res.Rounds)
	}
}

// Only the last chatHistoryMax turns ride along.
func TestChatHistoryCap(t *testing.T) {
	var got int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = len(readBody(t, r)["messages"].([]any))
		io.WriteString(w, `{"choices":[{"message":{"role":"assistant","content":"ok"}}]}`)
	}))
	defer srv.Close()
	cfg := settings.AIAdvisorConfig{Enabled: true, Provider: "openai", Endpoint: srv.URL, Model: "m"}
	hist := make([]ChatTurn, 30)
	if _, err := Chat(context.Background(), cfg, &stubTools{}, hist, "q", "en"); err != nil {
		t.Fatal(err)
	}
	// system + 2 per kept turn + the question
	if got != 1+2*chatHistoryMax+1 {
		t.Errorf("%d messages sent, want %d", got, 1+2*chatHistoryMax+1)
	}
}
