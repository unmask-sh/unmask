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
			io.WriteString(w, `{"stop_reason":"tool_use","usage":{"input_tokens":10,"output_tokens":5},"content":[{"type":"text","text":"Let me look."},{"type":"tool_use","id":"tu_1","name":"bans","input":{"limit":3}}]}`)
			return
		}
		io.WriteString(w, `{"stop_reason":"end_turn","usage":{"input_tokens":20,"output_tokens":7},"content":[{"type":"text","text":"One ban: 203.0.113.9."}]}`)
	}))
	defer srv.Close()
	cfg := settings.AIAdvisorConfig{Enabled: true, Provider: "anthropic", Endpoint: srv.URL, APIKey: "k", Model: "m"}
	st := &stubTools{}
	res, err := Chat(context.Background(), cfg, st, []ChatTurn{{Question: "hi", Answer: "hello"}}, "who is banned?", "ja")
	if err != nil {
		t.Fatal(err)
	}
	if res.Answer != "One ban: 203.0.113.9." || res.Rounds != 2 || res.Usage.Input != 30 || res.Usage.Output != 12 {
		t.Errorf("result %+v", res)
	}
	if len(res.Tools) != 1 || res.Tools[0].Name != "bans" || res.Tools[0].Args["limit"] != float64(3) || res.Tools[0].Err != "" {
		t.Errorf("tools %+v", res.Tools)
	}
	if st.calls[0] != "bans" {
		t.Errorf("calls %v", st.calls)
	}
	// The first request: system prompt, tools, the history and the question
	// with the language asked for.
	first := reqs[0]
	if first["system"] != chatSystemPrompt || len(first["tools"].([]any)) != 1 {
		t.Error("first request lacks the system prompt or the tools")
	}
	msgs := first["messages"].([]any)
	if len(msgs) != 3 || !strings.Contains(msgs[2].(map[string]any)["content"].(string), "日本語") {
		t.Errorf("messages %v", msgs)
	}
	// The second: the assistant's blocks echoed, then the tool result by id.
	msgs = reqs[1]["messages"].([]any)
	if len(msgs) != 5 {
		t.Fatalf("second request has %d messages, want 5", len(msgs))
	}
	last := msgs[4].(map[string]any)
	content := last["content"].([]any)[0].(map[string]any)
	if last["role"] != "user" || content["type"] != "tool_result" || content["tool_use_id"] != "tu_1" || !strings.Contains(content["content"].(string), "203.0.113.9") {
		t.Errorf("tool result message %v", last)
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
