package advisor

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// sse answers with the events as the Messages API streams them: each one an
// "event:" line, a "data:" line and a blank line.
func sse(w http.ResponseWriter, events ...string) {
	w.Header().Set("content-type", "text/event-stream")
	for _, ev := range events {
		var head struct {
			Type string `json:"type"`
		}
		_ = json.Unmarshal([]byte(ev), &head)
		fmt.Fprintf(w, "event: %s\ndata: %s\n\n", head.Type, ev)
	}
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
}

// The events build the message a non-streaming request returns: blocks in
// order (a thinking block with its signature, the text in one piece, a tool
// call's input parsed from its pieces), the stop reason and the counts.
// Pings and event names are skipped.
func TestAnthropicPostBuildsTheMessage(t *testing.T) {
	var sent map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sent = readBody(t, r)
		sse(w,
			`{"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","content":[],"usage":{"input_tokens":100,"output_tokens":1}}}`,
			`{"type":"ping"}`,
			`{"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":"","signature":""}}`,
			`{"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"a"}}`,
			`{"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"b"}}`,
			`{"type":"content_block_delta","index":0,"delta":{"type":"signature_delta","signature":"sig"}}`,
			`{"type":"content_block_stop","index":0}`,
			`{"type":"content_block_start","index":1,"content_block":{"type":"text","text":""}}`,
			`{"type":"content_block_delta","index":1,"delta":{"type":"text_delta","text":"Hel"}}`,
			`{"type":"content_block_delta","index":1,"delta":{"type":"text_delta","text":"lo"}}`,
			`{"type":"content_block_stop","index":1}`,
			`{"type":"content_block_start","index":2,"content_block":{"type":"tool_use","id":"tu_1","name":"bans","input":{}}}`,
			`{"type":"content_block_delta","index":2,"delta":{"type":"input_json_delta","partial_json":"{\"lim"}}`,
			`{"type":"content_block_delta","index":2,"delta":{"type":"input_json_delta","partial_json":"it\":3}"}}`,
			`{"type":"content_block_stop","index":2}`,
			`{"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":42}}`,
			`{"type":"message_stop"}`,
		)
	}))
	defer srv.Close()
	out, err := anthropicPost(context.Background(), srv.URL, map[string]string{"x-api-key": "k"}, map[string]any{"model": "m", "max_tokens": 10})
	if err != nil {
		t.Fatal(err)
	}
	if sent["stream"] != true || sent["model"] != "m" {
		t.Errorf("request %v", sent)
	}
	var msg struct {
		StopReason string           `json:"stop_reason"`
		Content    []map[string]any `json:"content"`
		Usage      struct {
			Input  int `json:"input_tokens"`
			Output int `json:"output_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(out, &msg); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if msg.StopReason != "tool_use" || msg.Usage.Input != 100 || msg.Usage.Output != 42 || len(msg.Content) != 3 {
		t.Fatalf("message %s", out)
	}
	if b := msg.Content[0]; b["type"] != "thinking" || b["thinking"] != "ab" || b["signature"] != "sig" {
		t.Errorf("thinking block %v", b)
	}
	if b := msg.Content[1]; b["type"] != "text" || b["text"] != "Hello" {
		t.Errorf("text block %v", b)
	}
	if b := msg.Content[2]; b["type"] != "tool_use" || b["id"] != "tu_1" || b["input"].(map[string]any)["limit"] != float64(3) {
		t.Errorf("tool block %v", b)
	}
}

// What can go wrong on a stream, and whether the attempt is retried: an
// error event (overloaded: yes), a stream that stops before its message
// does (yes), a provider that goes quiet (yes, as a timeout, after
// streamIdle), a refused request (no).  An answer that is plain JSON is
// read as it is.
func TestAnthropicPostFailures(t *testing.T) {
	orig := streamIdle
	streamIdle = 150 * time.Millisecond
	t.Cleanup(func() { streamIdle = orig })
	start := `{"type":"message_start","message":{"usage":{"input_tokens":5}}}`
	for _, tc := range []struct {
		name  string
		serve func(w http.ResponseWriter, r *http.Request)
		want  string // in the error; "" = no error
		retry bool
	}{
		{"error event", func(w http.ResponseWriter, r *http.Request) {
			sse(w, start, `{"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}}`)
		}, "Overloaded", true},
		{"cut", func(w http.ResponseWriter, r *http.Request) {
			sse(w, start, `{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`)
		}, "ended before", true},
		{"stall", func(w http.ResponseWriter, r *http.Request) {
			sse(w, start)
			select {
			case <-r.Context().Done():
			case <-time.After(3 * time.Second):
			}
		}, "sent nothing for", true},
		{"refused", func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, `{"error":{"type":"invalid_request_error","message":"max_tokens: too large"}}`, http.StatusBadRequest)
		}, "max_tokens: too large", false},
		{"plain json", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("content-type", "application/json")
			fmt.Fprint(w, `{"stop_reason":"end_turn","content":[]}`)
		}, "", false},
	} {
		srv := httptest.NewServer(http.HandlerFunc(tc.serve))
		out, err := anthropicPost(context.Background(), srv.URL, nil, map[string]any{"model": "m"})
		srv.Close()
		if tc.want == "" {
			if err != nil || !strings.Contains(string(out), "end_turn") {
				t.Errorf("%s: %v %s", tc.name, err, out)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), tc.want) || retryable(err) != tc.retry {
			t.Errorf("%s: err=%v retryable=%v", tc.name, err, err != nil && retryable(err))
		}
	}
}

// At effort max the review leaves 64K for the thinking and the JSON.  If
// the thinking takes all of it anyway, the run fails saying so -- not "no
// text block" -- and what it cost comes back with the failure.
func TestReviewOutOfRoom(t *testing.T) {
	var maxTokens any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		maxTokens = readBody(t, r)["max_tokens"]
		sse(w,
			`{"type":"message_start","message":{"usage":{"input_tokens":4000}}}`,
			`{"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":"","signature":""}}`,
			`{"type":"content_block_delta","index":0,"delta":{"type":"signature_delta","signature":"s"}}`,
			`{"type":"content_block_stop","index":0}`,
			`{"type":"message_delta","delta":{"stop_reason":"max_tokens"},"usage":{"output_tokens":64000}}`,
			`{"type":"message_stop"}`,
		)
	}))
	defer srv.Close()
	cfg := settings.AIAdvisorConfig{Enabled: true, Provider: "anthropic", APIKey: "k", Endpoint: srv.URL, Model: "claude-opus-5-5", Effort: "max"}
	res, err := ReviewWithPool(context.Background(), cfg, sampleCandidates(), Pool{}, "")
	if maxTokens != float64(64000) {
		t.Errorf("max_tokens at effort max: %v", maxTokens)
	}
	if err == nil || !strings.Contains(err.Error(), "max_tokens 64000") || !strings.Contains(err.Error(), "lower effort") {
		t.Errorf("err %v", err)
	}
	if res.Usage.Input != 4000 || res.Usage.Output != 64000 {
		t.Errorf("usage of the failed run %+v", res.Usage)
	}
}

// The chat reads Anthropic's stream the same way, and the assistant turn
// it echoes into the next round is the one the stream built: the thinking
// block with its signature, the tool call with its input.  A round cut off
// at max_tokens fails the question with its tokens counted.
func TestChatAnthropicStreamed(t *testing.T) {
	var reqs []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqs = append(reqs, readBody(t, r))
		switch len(reqs) {
		case 1:
			sse(w,
				`{"type":"message_start","message":{"usage":{"input_tokens":10}}}`,
				`{"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":"","signature":""}}`,
				`{"type":"content_block_delta","index":0,"delta":{"type":"signature_delta","signature":"sig1"}}`,
				`{"type":"content_block_stop","index":0}`,
				`{"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"tu_1","name":"bans","input":{}}}`,
				`{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"limit\":3}"}}`,
				`{"type":"content_block_stop","index":1}`,
				`{"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":5}}`,
				`{"type":"message_stop"}`)
		case 2:
			sse(w,
				`{"type":"message_start","message":{"usage":{"input_tokens":20}}}`,
				`{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`,
				`{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"One ban."}}`,
				`{"type":"content_block_stop","index":0}`,
				`{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":7}}`,
				`{"type":"message_stop"}`)
		default:
			sse(w,
				`{"type":"message_start","message":{"usage":{"input_tokens":30}}}`,
				`{"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":"","signature":""}}`,
				`{"type":"content_block_stop","index":0}`,
				`{"type":"message_delta","delta":{"stop_reason":"max_tokens"},"usage":{"output_tokens":16000}}`,
				`{"type":"message_stop"}`)
		}
	}))
	defer srv.Close()
	cfg := settings.AIAdvisorConfig{Enabled: true, Provider: "anthropic", Endpoint: srv.URL, APIKey: "k", Model: "claude-opus-5-5"}
	res, err := Chat(context.Background(), cfg, &stubTools{}, nil, "who is banned?", "en")
	if err != nil || res.Answer != "One ban." || res.Usage.Input != 30 || res.Usage.Output != 12 {
		t.Fatalf("res %+v err %v", res, err)
	}
	if reqs[0]["stream"] != true || reqs[0]["max_tokens"] != float64(16000) {
		t.Errorf("first request: stream %v max_tokens %v (Opus 5.5 runs at medium: 16000)", reqs[0]["stream"], reqs[0]["max_tokens"])
	}
	msgs := reqs[1]["messages"].([]any)
	echoed := msgs[1].(map[string]any)["content"].([]any)
	th, tu := echoed[0].(map[string]any), echoed[1].(map[string]any)
	if th["type"] != "thinking" || th["signature"] != "sig1" || tu["type"] != "tool_use" || tu["input"].(map[string]any)["limit"] != float64(3) {
		t.Errorf("echoed turn %v", echoed)
	}

	res, err = Chat(context.Background(), cfg, &stubTools{}, nil, "again", "en")
	if err == nil || !strings.Contains(err.Error(), "max_tokens 16000") || res.Usage.Output != 16000 || res.Usage.Input != 30 {
		t.Errorf("cut-off round: res %+v err %v", res, err)
	}
}
